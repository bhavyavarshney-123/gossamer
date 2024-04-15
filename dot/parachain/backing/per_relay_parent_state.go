// Copyright 2024 ChainSafe Systems (ON)
// SPDX-License-Identifier: LGPL-3.0-only

package backing

import (
	"errors"
	"fmt"

	availabilitystore "github.com/ChainSafe/gossamer/dot/parachain/availability-store"
	collatorprotocolmessages "github.com/ChainSafe/gossamer/dot/parachain/collator-protocol/messages"
	parachaintypes "github.com/ChainSafe/gossamer/dot/parachain/types"

	"github.com/ChainSafe/gossamer/lib/common"
	"github.com/ChainSafe/gossamer/pkg/scale"
)

// PerRelayParentState represents the state information for a relay-parent in the subsystem.
type perRelayParentState struct {
	prospectiveParachainsMode parachaintypes.ProspectiveParachainsMode
	// The hash of the relay parent on top of which this job is doing it's work.
	relayParent common.Hash
	// The `ParaId` assigned to the local validator at this relay parent.
	assignment parachaintypes.ParaID
	// The table of candidates and statements under this relay-parent.
	table Table
	// The table context, including groups.
	tableContext TableContext
	// Data needed for retrying in case of `ValidatedCandidateCommand::AttestNoPoV`.
	fallbacks map[parachaintypes.CandidateHash]attestingData
	// These candidates are undergoing validation in the background.
	awaitingValidation map[parachaintypes.CandidateHash]bool
	// We issued `Seconded` or `Valid` statements on about these candidates.
	issuedStatements map[parachaintypes.CandidateHash]bool
	// The candidates that are backed by enough validators in their group, by hash.
	backed map[parachaintypes.CandidateHash]bool
}

// importStatement imports a statement into the statement table and returns the summary of the import.
func (rpState *perRelayParentState) importStatement(
	subSystemToOverseer chan<- any,
	signedStatementWithPVD SignedFullStatementWithPVD,
	perCandidate map[parachaintypes.CandidateHash]*perCandidateState,
) (*Summary, error) {
	statementVDT, err := signedStatementWithPVD.SignedFullStatement.Payload.Value()
	if err != nil {
		return nil, fmt.Errorf("getting value from statementVDT: %w", err)
	}

	if statementVDT.Index() == 2 { // Valid
		return rpState.table.importStatement(&rpState.tableContext, signedStatementWithPVD)
	}

	// PersistedValidationData should not be nil if the statementVDT is Seconded.
	if signedStatementWithPVD.PersistedValidationData == nil {
		return nil, fmt.Errorf("persisted validation data is nil")
	}

	statementVDTSeconded := statementVDT.(parachaintypes.Seconded)
	hash, err := parachaintypes.CommittedCandidateReceipt(statementVDTSeconded).Hash()
	if err != nil {
		return nil, fmt.Errorf("getting candidate hash: %w", err)
	}

	candidateHash := parachaintypes.CandidateHash{Value: hash}

	if _, ok := perCandidate[candidateHash]; ok {
		return rpState.table.importStatement(&rpState.tableContext, signedStatementWithPVD)
	}

	if rpState.prospectiveParachainsMode.IsEnabled {
		chIntroduceCandidate := make(chan error)
		subSystemToOverseer <- parachaintypes.ProspectiveParachainsMessageIntroduceCandidate{
			IntroduceCandidateRequest: parachaintypes.IntroduceCandidateRequest{
				CandidateParaID:           parachaintypes.ParaID(statementVDTSeconded.Descriptor.ParaID),
				CommittedCandidateReceipt: parachaintypes.CommittedCandidateReceipt(statementVDTSeconded),
				PersistedValidationData:   *signedStatementWithPVD.PersistedValidationData,
			},
			Ch: chIntroduceCandidate,
		}

		introduceCandidateErr, ok := <-chIntroduceCandidate
		if !ok {
			return nil, fmt.Errorf("%w: %s",
				errRejectedByProspectiveParachains,
				"Could not reach the Prospective Parachains subsystem.",
			)
		}
		if introduceCandidateErr != nil {
			return nil, fmt.Errorf("%w: %w", errRejectedByProspectiveParachains, introduceCandidateErr)
		}

		subSystemToOverseer <- parachaintypes.ProspectiveParachainsMessageCandidateSeconded{
			ParaID:        parachaintypes.ParaID(statementVDTSeconded.Descriptor.ParaID),
			CandidateHash: candidateHash,
		}
	}

	// Only save the candidate if it was approved by prospective parachains.
	perCandidate[candidateHash] = &perCandidateState{
		persistedValidationData: *signedStatementWithPVD.PersistedValidationData,
		secondedLocally:         false, // This is set after importing when seconding locally.
		paraID:                  parachaintypes.ParaID(statementVDTSeconded.Descriptor.ParaID),
		relayParent:             statementVDTSeconded.Descriptor.RelayParent,
	}

	return rpState.table.importStatement(&rpState.tableContext, signedStatementWithPVD)
}

// postImportStatement handles a summary received from importStatement func and dispatches `Backed` notifications and
// misbehaviors as a result of importing a statement.
func (rpState *perRelayParentState) postImportStatement(subSystemToOverseer chan<- any, summary *Summary) {
	// If the summary is nil, issue new misbehaviors and return.
	if summary == nil {
		issueNewMisbehaviors(subSystemToOverseer, rpState.relayParent, rpState.table)
		return
	}

	attested, err := rpState.table.attestedCandidate(summary.Candidate, &rpState.tableContext)
	if err != nil {
		logger.Error(err.Error())
	}

	// If the candidate is not attested, issue new misbehaviors and return.
	if attested == nil {
		issueNewMisbehaviors(subSystemToOverseer, rpState.relayParent, rpState.table)
		return
	}

	hash, err := attested.Candidate.Hash()
	if err != nil {
		logger.Error(err.Error())
		return
	}

	candidateHash := parachaintypes.CandidateHash{Value: hash}

	// If the candidate is already backed, issue new misbehaviors and return.
	if rpState.backed[candidateHash] {
		issueNewMisbehaviors(subSystemToOverseer, rpState.relayParent, rpState.table)
		return
	}

	// Mark the candidate as backed.
	rpState.backed[candidateHash] = true

	// Convert the attested candidate to a backed candidate.
	backedCandidate := attestedToBackedCandidate(*attested, &rpState.tableContext)
	if backedCandidate == nil {
		issueNewMisbehaviors(subSystemToOverseer, rpState.relayParent, rpState.table)
		return
	}

	paraID := backedCandidate.Candidate.Descriptor.ParaID

	if rpState.prospectiveParachainsMode.IsEnabled {

		// Inform the prospective parachains subsystem that the candidate is now backed.
		subSystemToOverseer <- parachaintypes.ProspectiveParachainsMessageCandidateBacked{
			ParaID:        parachaintypes.ParaID(paraID),
			CandidateHash: candidateHash,
		}

		// Backed candidate potentially unblocks new advertisements, notify collator protocol.
		subSystemToOverseer <- collatorprotocolmessages.Backed{
			ParaID:   parachaintypes.ParaID(paraID),
			ParaHead: backedCandidate.Candidate.Descriptor.ParaHead,
		}

		// Notify statement distribution of backed candidate.
		subSystemToOverseer <- parachaintypes.StatementDistributionMessageBacked(candidateHash)

	} else {
		// TODO: figure out what this comment means by 'avoid cycles'.
		//
		// The provisioner waits on candidate-backing, which means
		// that we need to send unbounded messages to avoid cycles.
		//
		// Backed candidates are bounded by the number of validators,
		// parachains, and the block production rate of the relay chain.
		subSystemToOverseer <- parachaintypes.ProvisionerMessageProvisionableData{
			RelayParent:       rpState.relayParent,
			ProvisionableData: parachaintypes.ProvisionableDataBackedCandidate(backedCandidate.Candidate.ToPlain()),
		}
	}

	issueNewMisbehaviors(subSystemToOverseer, rpState.relayParent, rpState.table)
}

// issueNewMisbehaviors checks for new misbehaviors and sends necessary messages to the Overseer subsystem.
func issueNewMisbehaviors(subSystemToOverseer chan<- any, relayParent common.Hash, table Table) {
	// collect the misbehaviors to avoid double mutable self borrow issues
	misbehaviors := table.drainMisbehaviors()

	for _, m := range misbehaviors {
		// TODO: figure out what this comment means by 'avoid cycles'.
		//
		// The provisioner waits on candidate-backing, which means
		// that we need to send unbounded messages to avoid cycles.
		//
		// Misbehaviors are bounded by the number of validators and
		// the block production protocol.
		subSystemToOverseer <- parachaintypes.ProvisionerMessageProvisionableData{
			RelayParent: relayParent,
			ProvisionableData: parachaintypes.ProvisionableDataMisbehaviorReport{
				ValidatorIndex: m.ValidatorIndex,
				Misbehaviour:   m.Misbehaviour,
			},
		}
	}
}

func attestedToBackedCandidate(
	attested AttestedCandidate,
	tableContext *TableContext,
) *parachaintypes.BackedCandidate {
	group := tableContext.groups[attested.GroupID]
	validatorIndices := make([]bool, len(group))
	var validityAttestations []parachaintypes.ValidityAttestation

	// The order of the validity votes in the backed candidate must match
	// the order of bits set in the bitfield, which is not necessarily
	// the order of the `validity_votes` we got from the table.
	for positionInGroup, validatorIndex := range group {
		for _, validityVote := range attested.ValidityVotes {
			if validityVote.ValidatorIndex == validatorIndex {
				validatorIndices[positionInGroup] = true
				validityAttestations = append(validityAttestations, validityVote.ValidityAttestation)
			}
		}

		if !validatorIndices[positionInGroup] {
			logger.Error("validity vote from unknown validator")
			return nil
		}
	}

	return &parachaintypes.BackedCandidate{
		Candidate:        attested.Candidate,
		ValidityVotes:    validityAttestations,
		ValidatorIndices: scale.NewBitVec(validatorIndices),
	}
}

// Kick off validation work and distribute the result as a signed statement.
func (rpState *perRelayParentState) kickOffValidationWork(
	subSystemToOverseer chan<- any,
	chRelayParentAndCommand chan relayParentAndCommand,
	pvd parachaintypes.PersistedValidationData,
	attesting attestingData,
) error {
	hash, err := attesting.candidate.Hash()
	if err != nil {
		return fmt.Errorf("getting candidate hash: %w", err)
	}

	candidateHash := parachaintypes.CandidateHash{Value: hash}

	if rpState.issuedStatements[candidateHash] {
		return nil
	}

	pov := getPovFromValidator()

	return rpState.validateAndMakeAvailable(
		executorParamsAtRelayParent,
		subSystemToOverseer,
		chRelayParentAndCommand,
		attesting.candidate,
		rpState.relayParent,
		pvd,
		pov,
		uint32(len(rpState.tableContext.validators)),
		attest,
		candidateHash,
	)
}

// this is temporary until we implement executorParamsAtRelayParent #3544
type executorParamsGetter func(common.Hash, chan<- any) (parachaintypes.ExecutorParams, error)

func (rpState *perRelayParentState) validateAndMakeAvailable(
	executorParamsAtRelayParentFunc executorParamsGetter, // remove after executorParamsAtRelayParent is implemented #3544
	subSystemToOverseer chan<- any,
	chRelayParentAndCommand chan relayParentAndCommand,
	candidateReceipt parachaintypes.CandidateReceipt,
	relayParent common.Hash,
	pvd parachaintypes.PersistedValidationData,
	pov parachaintypes.PoV,
	numValidator uint32,
	makeCommand validatedCandidateCommand,
	candidateHash parachaintypes.CandidateHash,
) error {
	if rpState.awaitingValidation[candidateHash] {
		return nil
	}

	rpState.awaitingValidation[candidateHash] = true
	validationCodeHash := candidateReceipt.Descriptor.ValidationCodeHash

	chValidationCodeByHashRes := make(chan parachaintypes.OverseerFuncRes[parachaintypes.ValidationCode])
	subSystemToOverseer <- parachaintypes.RuntimeApiMessageRequest{
		RelayParent: relayParent,
		RuntimeApiRequest: parachaintypes.RuntimeApiRequestValidationCodeByHash{
			ValidationCodeHash: validationCodeHash,
			Ch:                 chValidationCodeByHashRes,
		},
	}

	validationCodeByHashRes := <-chValidationCodeByHashRes
	if validationCodeByHashRes.Err != nil {
		return fmt.Errorf("getting validation code by hash: %w", validationCodeByHashRes.Err)
	}

	// executorParamsAtRelayParent() should be called after it is implemented #3544
	executorParams, err := executorParamsAtRelayParentFunc(relayParent, subSystemToOverseer)
	if err != nil {
		return fmt.Errorf("getting executor params at relay parent: %w", err)
	}

	pvfExecTimeoutKind := parachaintypes.NewPvfExecTimeoutKind()
	err = pvfExecTimeoutKind.Set(parachaintypes.Backing{})
	if err != nil {
		return fmt.Errorf("setting pvfExecTimeoutKind: %w", err)
	}

	chValidationResultRes := make(chan parachaintypes.OverseerFuncRes[parachaintypes.ValidationResult])
	subSystemToOverseer <- parachaintypes.CandidateValidationMessageValidateFromExhaustive{
		PersistedValidationData: pvd,
		ValidationCode:          validationCodeByHashRes.Data,
		CandidateReceipt:        candidateReceipt,
		PoV:                     pov,
		ExecutorParams:          executorParams,
		PvfExecTimeoutKind:      pvfExecTimeoutKind,
		Ch:                      chValidationResultRes,
	}

	validationResultRes := <-chValidationResultRes
	if validationResultRes.Err != nil {
		return fmt.Errorf("getting validation result: %w", validationResultRes.Err)
	}

	var bgValidationResult backgroundValidationResult

	if validationResultRes.Data.IsValid { // Valid
		// Important: the `av-store` subsystem will check if the erasure root of the `available_data`
		// matches `expected_erasure_root` which was provided by the collator in the `CandidateReceipt`.
		// This check is consensus critical and the `backing` subsystem relies on it for ensuring
		// candidate validity.

		logger.Debugf("validation successful! candidateHash=%s", candidateHash)

		chStoreAvailableDataError := make(chan error)
		subSystemToOverseer <- availabilitystore.StoreAvailableData{
			CandidateHash: candidateHash,
			NumValidators: numValidator,
			AvailableData: availabilitystore.AvailableData{
				PoV:            pov,
				ValidationData: pvd,
			},
			ExpectedErasureRoot: candidateReceipt.Descriptor.ErasureRoot,
			Sender:              chStoreAvailableDataError,
		}

		storeAvailableDataError := <-chStoreAvailableDataError
		switch {
		case storeAvailableDataError == nil:
			bgValidationResult = backgroundValidationResult{
				candidateReceipt:        &candidateReceipt,
				candidateCommitments:    &validationResultRes.Data.CandidateCommitments,
				persistedValidationData: &validationResultRes.Data.PersistedValidationData,
				err:                     nil,
			}
		case errors.Is(storeAvailableDataError, errInvalidErasureRoot):
			logger.Debug(errInvalidErasureRoot.Error())

			bgValidationResult = backgroundValidationResult{
				candidateReceipt: &candidateReceipt,
				err:              errInvalidErasureRoot,
			}
		default:
			return fmt.Errorf("storing available data: %w", storeAvailableDataError)
		}

	} else { // Invalid
		logger.Error(validationResultRes.Data.Err.Error())
		bgValidationResult = backgroundValidationResult{
			candidateReceipt: &candidateReceipt,
			err:              validationResultRes.Data.Err,
		}
	}

	chRelayParentAndCommand <- relayParentAndCommand{
		relayParent:   relayParent,
		command:       makeCommand,
		validationRes: bgValidationResult,
		candidateHash: candidateHash,
	}
	return nil
}

func executorParamsAtRelayParent(
	relayParent common.Hash, subSystemToOverseer chan<- any,
) (parachaintypes.ExecutorParams, error) {
	// TODO: Implement this #3544
	// https://github.com/paritytech/polkadot-sdk/blob/7ca0d65f19497ac1c3c7ad6315f1a0acb2ca32f8/polkadot/node/subsystem-util/src/lib.rs#L241-L242
	return parachaintypes.ExecutorParams{}, nil
}