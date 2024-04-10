// Copyright 2024 ChainSafe Systems (ON)
// SPDX-License-Identifier: LGPL-3.0-only

package backing

import (
	"errors"
	"testing"

	availabilitystore "github.com/ChainSafe/gossamer/dot/parachain/availability-store"
	collatorprotocolmessages "github.com/ChainSafe/gossamer/dot/parachain/collator-protocol/messages"
	parachaintypes "github.com/ChainSafe/gossamer/dot/parachain/types"
	"github.com/ChainSafe/gossamer/lib/common"
	"github.com/ChainSafe/gossamer/lib/crypto/sr25519"
	"github.com/stretchr/testify/require"
	gomock "go.uber.org/mock/gomock"
)

var tempSignature = common.MustHexToBytes("0xc67cb93bf0a36fcee3d29de8a6a69a759659680acf486475e0a2552a5fbed87e45adce5f290698d8596095722b33599227f7461f51af8617c8be74b894cf1b86") //nolint:lll

func getDummyHash(t *testing.T, num byte) common.Hash {
	t.Helper()
	hash := common.Hash{}
	for i := 0; i < 32; i++ {
		hash[i] = num
	}
	return hash
}

func getDummyCommittedCandidateReceipt(t *testing.T) parachaintypes.CommittedCandidateReceipt {
	t.Helper()
	hash5 := getDummyHash(t, 6)

	var collatorID parachaintypes.CollatorID
	tempCollatID := common.MustHexToBytes("0x48215b9d322601e5b1a95164cea0dc4626f545f98343d07f1551eb9543c4b147")
	copy(collatorID[:], tempCollatID)

	var collatorSignature parachaintypes.CollatorSignature
	copy(collatorSignature[:], tempSignature)

	ccr := parachaintypes.CommittedCandidateReceipt{
		Descriptor: parachaintypes.CandidateDescriptor{
			ParaID:                      uint32(1),
			RelayParent:                 hash5,
			Collator:                    collatorID,
			PersistedValidationDataHash: hash5,
			PovHash:                     hash5,
			ErasureRoot:                 hash5,
			Signature:                   collatorSignature,
			ParaHead:                    hash5,
			ValidationCodeHash:          parachaintypes.ValidationCodeHash(hash5),
		},
		Commitments: parachaintypes.CandidateCommitments{
			UpwardMessages:    []parachaintypes.UpwardMessage{{1, 2, 3}},
			NewValidationCode: &parachaintypes.ValidationCode{1, 2, 3},
			HeadData: parachaintypes.HeadData{
				Data: []byte{1, 2, 3},
			},
			ProcessedDownwardMessages: uint32(5),
			HrmpWatermark:             uint32(0),
		},
	}

	return ccr
}

func mockOverseer(t *testing.T, subsystemToOverseer chan any) {
	t.Helper()
	for data := range subsystemToOverseer {
		switch data := data.(type) {
		case parachaintypes.ProspectiveParachainsMessageIntroduceCandidate:
			data.Ch <- nil
		case parachaintypes.ProspectiveParachainsMessageCandidateSeconded,
			parachaintypes.ProvisionerMessageProvisionableData,
			parachaintypes.ProspectiveParachainsMessageCandidateBacked,
			collatorprotocolmessages.Backed,
			parachaintypes.StatementDistributionMessageBacked:
			continue
		default:
			t.Errorf("unknown type: %T\n", data)
		}
	}
}

func secondedSignedFullStatementWithPVD(
	t *testing.T,
	statementVDTSeconded parachaintypes.StatementVDT,
) parachaintypes.SignedFullStatementWithPVD {
	t.Helper()
	return parachaintypes.SignedFullStatementWithPVD{
		SignedFullStatement: parachaintypes.SignedFullStatement{
			Payload: statementVDTSeconded,
		},
		PersistedValidationData: &parachaintypes.PersistedValidationData{
			ParentHead: parachaintypes.HeadData{
				Data: []byte{1, 2, 3},
			},
			RelayParentNumber:      5,
			RelayParentStorageRoot: getDummyHash(t, 5),
			MaxPovSize:             3,
		},
	}
}

func TestImportStatement(t *testing.T) {
	t.Parallel()

	dummyCCR := getDummyCommittedCandidateReceipt(t)
	seconded := parachaintypes.Seconded(dummyCCR)

	statementVDTSeconded := parachaintypes.NewStatementVDT()
	err := statementVDTSeconded.SetValue(seconded)
	require.NoError(t, err)

	hash, err := dummyCCR.Hash()
	require.NoError(t, err)

	candidateHash := parachaintypes.CandidateHash{Value: hash}

	statementVDTValid := parachaintypes.NewStatementVDT()
	err = statementVDTValid.SetValue(parachaintypes.Valid{})
	require.NoError(t, err)

	testCases := []struct {
		description            string
		rpState                func() perRelayParentState
		perCandidate           map[parachaintypes.CandidateHash]*perCandidateState
		signedStatementWithPVD parachaintypes.SignedFullStatementWithPVD
		summary                *Summary
		err                    string
	}{
		{
			description: "statementVDT_not_set",
			rpState: func() perRelayParentState {
				return perRelayParentState{}
			},
			signedStatementWithPVD: parachaintypes.SignedFullStatementWithPVD{},
			summary:                nil,
			err:                    "getting value from statementVDT:",
		},
		{
			description: "statementVDT_in_not_seconded",
			rpState: func() perRelayParentState {
				ctrl := gomock.NewController(t)
				mockTable := NewMockTable(ctrl)

				mockTable.EXPECT().importStatement(
					gomock.AssignableToTypeOf(new(TableContext)),
					gomock.AssignableToTypeOf(parachaintypes.SignedFullStatementWithPVD{}),
				).Return(new(Summary), nil)

				return perRelayParentState{
					table: mockTable,
				}
			},
			signedStatementWithPVD: parachaintypes.SignedFullStatementWithPVD{
				SignedFullStatement: parachaintypes.SignedFullStatement{
					Payload: statementVDTValid,
				},
			},
			summary: new(Summary),
			err:     "",
		},
		{
			description: "invalid_persisted_validation_data",
			rpState: func() perRelayParentState {
				return perRelayParentState{}
			},
			signedStatementWithPVD: parachaintypes.SignedFullStatementWithPVD{
				SignedFullStatement: parachaintypes.SignedFullStatement{
					Payload: statementVDTSeconded,
				},
			},
			summary: nil,
			err:     "persisted validation data is nil",
		},
		{
			description: "statement_is_seconded_and_candidate_is_known",
			rpState: func() perRelayParentState {
				ctrl := gomock.NewController(t)
				mockTable := NewMockTable(ctrl)

				mockTable.EXPECT().importStatement(
					gomock.AssignableToTypeOf(new(TableContext)),
					gomock.AssignableToTypeOf(parachaintypes.SignedFullStatementWithPVD{}),
				).Return(new(Summary), nil)

				return perRelayParentState{
					table: mockTable,
				}
			},
			perCandidate: map[parachaintypes.CandidateHash]*perCandidateState{
				candidateHash: {
					persistedValidationData: parachaintypes.PersistedValidationData{
						ParentHead: parachaintypes.HeadData{
							Data: []byte{1, 2, 3},
						},
					},
					secondedLocally: false,
					paraID:          1,
					relayParent:     getDummyHash(t, 5),
				},
			},
			signedStatementWithPVD: secondedSignedFullStatementWithPVD(t, statementVDTSeconded),
			summary:                new(Summary),
			err:                    "",
		},
		{
			description: "statement_is_seconded_and_candidate_is_unknown",
			rpState: func() perRelayParentState {
				ctrl := gomock.NewController(t)
				mockTable := NewMockTable(ctrl)

				mockTable.EXPECT().importStatement(
					gomock.AssignableToTypeOf(new(TableContext)),
					gomock.AssignableToTypeOf(parachaintypes.SignedFullStatementWithPVD{}),
				).Return(new(Summary), nil)

				return perRelayParentState{
					table: mockTable,
				}
			},
			perCandidate:           map[parachaintypes.CandidateHash]*perCandidateState{},
			signedStatementWithPVD: secondedSignedFullStatementWithPVD(t, statementVDTSeconded),
			summary:                new(Summary),
			err:                    "",
		},
		{
			description: "statement_is_seconded_and_candidate_is_unknown_with_prospective_parachain_mode_enabled",
			rpState: func() perRelayParentState {
				ctrl := gomock.NewController(t)
				mockTable := NewMockTable(ctrl)

				mockTable.EXPECT().importStatement(
					gomock.AssignableToTypeOf(new(TableContext)),
					gomock.AssignableToTypeOf(parachaintypes.SignedFullStatementWithPVD{}),
				).Return(new(Summary), nil)

				return perRelayParentState{
					table: mockTable,
					prospectiveParachainsMode: parachaintypes.ProspectiveParachainsMode{
						IsEnabled:          true,
						MaxCandidateDepth:  4,
						AllowedAncestryLen: 2,
					},
				}
			},
			perCandidate:           map[parachaintypes.CandidateHash]*perCandidateState{},
			signedStatementWithPVD: secondedSignedFullStatementWithPVD(t, statementVDTSeconded),
			summary:                new(Summary),
			err:                    "",
		},
	}

	for _, c := range testCases {
		c := c
		t.Run(c.description, func(t *testing.T) {
			t.Parallel()

			subSystemToOverseer := make(chan any)
			defer close(subSystemToOverseer)

			rpState := c.rpState()
			if rpState.prospectiveParachainsMode.IsEnabled {
				go mockOverseer(t, subSystemToOverseer)
			}

			summary, err := rpState.importStatement(subSystemToOverseer, c.signedStatementWithPVD, c.perCandidate)
			if c.summary == nil {
				require.Nil(t, summary)
			} else {
				require.Equal(t, c.summary, summary)
			}

			if c.err == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, c.err)
			}
		})
	}
}

func mustHexTo32BArray(t *testing.T, inputHex string) (outputArray [sr25519.PublicKeyLength]byte) {
	t.Helper()
	copy(outputArray[:], common.MustHexToBytes(inputHex))
	return outputArray
}

func dummySummary(t *testing.T) *Summary {
	t.Helper()

	return &Summary{
		Candidate: parachaintypes.CandidateHash{
			Value: getDummyHash(t, 5),
		},
		GroupID:       3,
		ValidityVotes: 5,
	}
}

func dummyValidityAttestation(t *testing.T, value string) parachaintypes.ValidityAttestation {
	t.Helper()

	var validatorSignature parachaintypes.ValidatorSignature
	copy(validatorSignature[:], tempSignature)

	vdt := parachaintypes.NewValidityAttestation()
	switch value {
	case "implicit":
		err := vdt.SetValue(parachaintypes.Implicit(validatorSignature))
		require.NoError(t, err)
	case "explicit":
		err := vdt.SetValue(parachaintypes.Explicit(validatorSignature))
		require.NoError(t, err)
	default:
		require.Fail(t, "invalid value")
	}
	return vdt
}

func dummyTableContext(t *testing.T) TableContext {
	t.Helper()

	return TableContext{
		validator: &validator{
			index: 1,
		},
		groups: map[parachaintypes.ParaID][]parachaintypes.ValidatorIndex{
			1: {1, 2, 3},
			2: {4, 5, 6},
			3: {7, 8, 9},
		},
		validators: []parachaintypes.ValidatorID{
			mustHexTo32BArray(t, "0xa262f83b46310770ae8d092147176b8b25e8855bcfbbe701d346b10db0c5385d"),
			mustHexTo32BArray(t, "0x804b9df571e2b744d65eca2d4c59eb8e4345286c00389d97bfc1d8d13aa6e57e"),
			mustHexTo32BArray(t, "0x4eb63e4aad805c06dc924e2f19b1dde7faf507e5bb3c1838d6a3cfc10e84fe72"),
			mustHexTo32BArray(t, "0x74c337d57035cd6b7718e92a0d8ea6ef710da8ab1215a057c40c4ef792155a68"),
		},
	}
}

func rpStateWhenPpmDisabled(t *testing.T) perRelayParentState {
	t.Helper()

	attestedToReturn := AttestedCandidate{
		GroupID:   3,
		Candidate: getDummyCommittedCandidateReceipt(t),
		ValidityVotes: []validityVote{
			{
				ValidatorIndex:      7,
				ValidityAttestation: dummyValidityAttestation(t, "implicit"),
			},
			{
				ValidatorIndex:      8,
				ValidityAttestation: dummyValidityAttestation(t, "explicit"),
			},
			{
				ValidatorIndex:      9,
				ValidityAttestation: dummyValidityAttestation(t, "implicit"),
			},
		},
	}

	ctrl := gomock.NewController(t)
	mockTable := NewMockTable(ctrl)

	mockTable.EXPECT().drainMisbehaviors().
		Return([]parachaintypes.ProvisionableDataMisbehaviorReport{})
	mockTable.EXPECT().attestedCandidate(
		gomock.AssignableToTypeOf(parachaintypes.CandidateHash{}),
		gomock.AssignableToTypeOf(new(TableContext)),
	).Return(&attestedToReturn, nil)

	return perRelayParentState{
		prospectiveParachainsMode: parachaintypes.ProspectiveParachainsMode{
			IsEnabled: false,
		},
		table:        mockTable,
		tableContext: dummyTableContext(t),
		backed:       map[parachaintypes.CandidateHash]bool{},
	}
}

func TestPostImportStatement(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		description string
		rpState     func() perRelayParentState
		summary     *Summary
	}{
		{
			description: "summary_is_nil",
			rpState: func() perRelayParentState {
				ctrl := gomock.NewController(t)
				mockTable := NewMockTable(ctrl)

				mockTable.EXPECT().drainMisbehaviors().Return([]parachaintypes.ProvisionableDataMisbehaviorReport{
					{
						ValidatorIndex: 1,
						Misbehaviour:   parachaintypes.MultipleCandidates{},
					},
				})

				return perRelayParentState{
					table: mockTable,
				}
			},
			summary: nil,
		},
		{
			description: "failed_to_get_attested_candidate_from_table",
			rpState: func() perRelayParentState {
				ctrl := gomock.NewController(t)
				mockTable := NewMockTable(ctrl)

				mockTable.EXPECT().drainMisbehaviors().
					Return([]parachaintypes.ProvisionableDataMisbehaviorReport{})
				mockTable.EXPECT().attestedCandidate(
					gomock.AssignableToTypeOf(parachaintypes.CandidateHash{}),
					gomock.AssignableToTypeOf(new(TableContext)),
				).Return(nil, errors.New("could not get attested candidate from table"))

				return perRelayParentState{
					table: mockTable,
				}
			},
			summary: dummySummary(t),
		},
		{
			description: "candidate_is_already_backed",
			rpState: func() perRelayParentState {
				ctrl := gomock.NewController(t)
				mockTable := NewMockTable(ctrl)

				candidate := getDummyCommittedCandidateReceipt(t)
				hash, err := candidate.Hash()
				require.NoError(t, err)

				candidateHash := parachaintypes.CandidateHash{Value: hash}

				mockTable.EXPECT().drainMisbehaviors().
					Return([]parachaintypes.ProvisionableDataMisbehaviorReport{})
				mockTable.EXPECT().attestedCandidate(
					gomock.AssignableToTypeOf(parachaintypes.CandidateHash{}),
					gomock.AssignableToTypeOf(new(TableContext)),
				).Return(&AttestedCandidate{
					GroupID:   4,
					Candidate: candidate,
				}, nil)

				return perRelayParentState{
					table: mockTable,
					backed: map[parachaintypes.CandidateHash]bool{
						candidateHash: true,
					},
				}
			},
			summary: dummySummary(t),
		},
		{
			description: "Validity_vote_from_unknown_validator",
			rpState: func() perRelayParentState {
				ctrl := gomock.NewController(t)
				mockTable := NewMockTable(ctrl)

				mockTable.EXPECT().drainMisbehaviors().
					Return([]parachaintypes.ProvisionableDataMisbehaviorReport{})
				mockTable.EXPECT().attestedCandidate(
					gomock.AssignableToTypeOf(parachaintypes.CandidateHash{}),
					gomock.AssignableToTypeOf(new(TableContext)),
				).Return(&AttestedCandidate{
					GroupID:   3,
					Candidate: getDummyCommittedCandidateReceipt(t),
				}, nil)

				return perRelayParentState{
					table:        mockTable,
					backed:       map[parachaintypes.CandidateHash]bool{},
					tableContext: dummyTableContext(t),
				}
			},
			summary: dummySummary(t),
		},
		{
			description: "prospective_parachain_mode_is_disabled",
			rpState: func() perRelayParentState {
				return rpStateWhenPpmDisabled(t)
			},
			summary: dummySummary(t),
		},
		{
			description: "prospective_parachain_mode_is_enabled",
			rpState: func() perRelayParentState {
				state := rpStateWhenPpmDisabled(t)
				state.prospectiveParachainsMode = parachaintypes.ProspectiveParachainsMode{
					IsEnabled:          true,
					MaxCandidateDepth:  4,
					AllowedAncestryLen: 2,
				}
				return state
			},
			summary: dummySummary(t),
		},
	}

	for _, c := range testCases {
		c := c
		t.Run(c.description, func(t *testing.T) {
			t.Parallel()

			subSystemToOverseer := make(chan any)
			defer close(subSystemToOverseer)

			go mockOverseer(t, subSystemToOverseer)

			rpState := c.rpState()
			rpState.postImportStatement(subSystemToOverseer, c.summary)
		})
	}
}

func TestKickOffValidationWork(t *testing.T) {
	t.Parallel()

	attesting := attestingData{
		candidate: getDummyCommittedCandidateReceipt(t).ToPlain(),
	}

	hash, err := attesting.candidate.Hash()
	require.NoError(t, err)

	candidateHash := parachaintypes.CandidateHash{Value: hash}

	testCases := []struct {
		description string
		rpState     perRelayParentState
	}{
		{
			description: "already_issued_statement_for_candidate",
			rpState: perRelayParentState{
				issuedStatements: map[parachaintypes.CandidateHash]bool{
					candidateHash: true,
				},
			},
		},
		{
			description: "not_issued_statement_but_waiting_for_validation",
			rpState: perRelayParentState{
				issuedStatements: map[parachaintypes.CandidateHash]bool{},
				awaitingValidation: map[parachaintypes.CandidateHash]bool{
					candidateHash: true,
				},
			},
		},
	}

	for _, c := range testCases {
		c := c
		t.Run(c.description, func(t *testing.T) {
			t.Parallel()

			subSystemToOverseer := make(chan any)
			chRelayParentAndCommand := make(chan relayParentAndCommand)
			pvd := parachaintypes.PersistedValidationData{}

			err := c.rpState.kickOffValidationWork(subSystemToOverseer, chRelayParentAndCommand, pvd, attesting)
			require.NoError(t, err)
		})
	}
}

func TestBackgroundValidateAndMakeAvailable(t *testing.T) {
	t.Parallel()

	var pvd parachaintypes.PersistedValidationData
	candidateReceipt := getDummyCommittedCandidateReceipt(t).ToPlain()

	hash, err := candidateReceipt.Hash()
	require.NoError(t, err)

	candidateHash := parachaintypes.CandidateHash{Value: hash}
	relayParent := getDummyHash(t, 5)

	testCases := []struct {
		description              string
		rpState                  perRelayParentState
		expectedErr              string
		mockOverseer             func(ch chan any)
		mockExecutorParamsGetter executorParamsGetter
	}{
		{
			description: "validation_process_already_started_for_candidate",
			rpState: perRelayParentState{
				issuedStatements: map[parachaintypes.CandidateHash]bool{},
				awaitingValidation: map[parachaintypes.CandidateHash]bool{
					candidateHash: true,
				},
			},
			expectedErr:              "",
			mockOverseer:             func(ch chan any) {},
			mockExecutorParamsGetter: executorParamsAtRelayParent,
		},
		{
			description: "unable_to_get_validation_code",
			rpState: perRelayParentState{
				issuedStatements:   map[parachaintypes.CandidateHash]bool{},
				awaitingValidation: map[parachaintypes.CandidateHash]bool{},
			},
			expectedErr: "getting validation code by hash: ",
			mockOverseer: func(ch chan any) {
				data := <-ch
				req, ok := data.(parachaintypes.RuntimeApiMessageRequest)
				if !ok {
					t.Errorf("invalid overseer message type: %T\n", data)
				}

				req.RuntimeApiRequest.(parachaintypes.RuntimeApiRequestValidationCodeByHash).
					Ch <- parachaintypes.OverseerFuncRes[parachaintypes.ValidationCode]{
					Err: errors.New("mock error getting validation code"),
				}
			},
			mockExecutorParamsGetter: executorParamsAtRelayParent,
		},
		{
			description: "unable_to_get_executor_params",
			rpState: perRelayParentState{
				issuedStatements:   map[parachaintypes.CandidateHash]bool{},
				awaitingValidation: map[parachaintypes.CandidateHash]bool{},
			},
			expectedErr: "getting executor params at relay parent: ",
			mockOverseer: func(ch chan any) {
				data := <-ch
				req, ok := data.(parachaintypes.RuntimeApiMessageRequest)
				if !ok {
					t.Errorf("invalid overseer message type: %T\n", data)
				}

				req.RuntimeApiRequest.(parachaintypes.RuntimeApiRequestValidationCodeByHash).
					Ch <- parachaintypes.OverseerFuncRes[parachaintypes.ValidationCode]{
					Data: parachaintypes.ValidationCode{1, 2, 3},
				}
			},
			mockExecutorParamsGetter: func(h common.Hash, c chan<- any) (parachaintypes.ExecutorParams, error) {
				return parachaintypes.NewExecutorParams(), errors.New("mock error getting executor params")
			},
		},
		{
			description: "unable_to_get_validation_result",
			rpState: perRelayParentState{
				issuedStatements:   map[parachaintypes.CandidateHash]bool{},
				awaitingValidation: map[parachaintypes.CandidateHash]bool{},
			},
			expectedErr: "getting validation result: ",
			mockOverseer: func(ch chan any) {
				for data := range ch {
					switch data := data.(type) {
					case parachaintypes.RuntimeApiMessageRequest:
						data.RuntimeApiRequest.(parachaintypes.RuntimeApiRequestValidationCodeByHash).
							Ch <- parachaintypes.OverseerFuncRes[parachaintypes.ValidationCode]{
							Data: parachaintypes.ValidationCode{1, 2, 3},
						}
					case parachaintypes.CandidateValidationMessageValidateFromExhaustive:
						data.Ch <- parachaintypes.OverseerFuncRes[parachaintypes.ValidationResult]{
							Err: errors.New("mock error getting validation result"),
						}
					default:
						t.Errorf("invalid overseer message type: %T\n", data)
					}
				}
			},
			mockExecutorParamsGetter: executorParamsAtRelayParent,
		},
		{
			description: "validation_result_is_invalid",
			rpState: perRelayParentState{
				issuedStatements:   map[parachaintypes.CandidateHash]bool{},
				awaitingValidation: map[parachaintypes.CandidateHash]bool{},
			},
			expectedErr: "",
			mockOverseer: func(ch chan any) {
				for data := range ch {
					switch data := data.(type) {
					case parachaintypes.RuntimeApiMessageRequest:
						data.RuntimeApiRequest.(parachaintypes.RuntimeApiRequestValidationCodeByHash).
							Ch <- parachaintypes.OverseerFuncRes[parachaintypes.ValidationCode]{
							Data: parachaintypes.ValidationCode{1, 2, 3},
						}
					case parachaintypes.CandidateValidationMessageValidateFromExhaustive:
						data.Ch <- parachaintypes.OverseerFuncRes[parachaintypes.ValidationResult]{
							Data: parachaintypes.ValidationResult{
								IsValid: false,
								Err:     errors.New("mock error validating candidate"),
							},
						}
					default:
						t.Errorf("invalid overseer message type: %T\n", data)
					}
				}
			},
			mockExecutorParamsGetter: executorParamsAtRelayParent,
		},
		{
			description: "validation_result_is_valid",
			rpState: perRelayParentState{
				issuedStatements:   map[parachaintypes.CandidateHash]bool{},
				awaitingValidation: map[parachaintypes.CandidateHash]bool{},
			},
			expectedErr: "",
			mockOverseer: func(ch chan any) {
				for data := range ch {
					switch data := data.(type) {
					case parachaintypes.RuntimeApiMessageRequest:
						data.RuntimeApiRequest.(parachaintypes.RuntimeApiRequestValidationCodeByHash).
							Ch <- parachaintypes.OverseerFuncRes[parachaintypes.ValidationCode]{
							Data: parachaintypes.ValidationCode{1, 2, 3},
						}
					case parachaintypes.CandidateValidationMessageValidateFromExhaustive:
						data.Ch <- parachaintypes.OverseerFuncRes[parachaintypes.ValidationResult]{
							Data: parachaintypes.ValidationResult{
								IsValid: true,
							},
						}
					case availabilitystore.StoreAvailableData:
						data.Sender <- errInvalidErasureRoot
					default:
						t.Errorf("invalid overseer message type: %T\n", data)
					}
				}
			},
			mockExecutorParamsGetter: executorParamsAtRelayParent,
		},
	}

	for _, c := range testCases {
		c := c
		t.Run(c.description, func(t *testing.T) {
			t.Parallel()

			subSystemToOverseer := make(chan any)
			chRelayParentAndCommand := make(chan relayParentAndCommand)

			go c.mockOverseer(subSystemToOverseer)
			go func(chRelayParentAndCommand chan relayParentAndCommand) {
				<-chRelayParentAndCommand
			}(chRelayParentAndCommand)

			err := c.rpState.validateAndMakeAvailable(
				c.mockExecutorParamsGetter,
				subSystemToOverseer,
				chRelayParentAndCommand,
				candidateReceipt,
				relayParent,
				pvd,
				parachaintypes.PoV{},
				2,
				attest,
				candidateHash,
			)

			if c.expectedErr != "" {
				require.ErrorContains(t, err, c.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestHandleStatementMessage(t *testing.T) {
	t.Parallel()

	relayParent := getDummyHash(t, 5)
	chRelayParentAndCommand := make(chan relayParentAndCommand)

	dummyCCR := getDummyCommittedCandidateReceipt(t)
	seconded := parachaintypes.Seconded(dummyCCR)

	statementVDTSeconded := parachaintypes.NewStatementVDT()
	err := statementVDTSeconded.SetValue(seconded)
	require.NoError(t, err)

	hash, err := dummyCCR.Hash()
	require.NoError(t, err)

	candidateHash := parachaintypes.CandidateHash{Value: hash}

	statementVDTValid := parachaintypes.NewStatementVDT()
	err = statementVDTValid.SetValue(parachaintypes.Valid(candidateHash))
	require.NoError(t, err)

	testCases := []struct {
		description            string
		perRelayParent         func() map[common.Hash]*perRelayParentState
		perCandidate           map[parachaintypes.CandidateHash]*perCandidateState
		signedStatementWithPVD parachaintypes.SignedFullStatementWithPVD
		err                    string
	}{

		{
			description: "unknown_relay_parent",
			perRelayParent: func() map[common.Hash]*perRelayParentState {
				return map[common.Hash]*perRelayParentState{}
			},
			signedStatementWithPVD: parachaintypes.SignedFullStatementWithPVD{},
			err:                    errStatementForUnknownRelayParent.Error(),
		},
		{
			description: "nil_relay_parent",
			perRelayParent: func() map[common.Hash]*perRelayParentState {
				return map[common.Hash]*perRelayParentState{
					relayParent: nil,
				}
			},
			signedStatementWithPVD: parachaintypes.SignedFullStatementWithPVD{},
			err:                    errNilRelayParentState.Error(),
		},
		{
			description: "getting_error_importing_statement",
			perRelayParent: func() map[common.Hash]*perRelayParentState {
				return map[common.Hash]*perRelayParentState{
					relayParent: {},
				}
			},
			signedStatementWithPVD: parachaintypes.SignedFullStatementWithPVD{},
			err:                    "unsupported VaryingDataTypeValue",
		},
		{
			description: "getting_nil_summary_of_import_statement",
			perRelayParent: func() map[common.Hash]*perRelayParentState {
				ctrl := gomock.NewController(t)
				mockTable := NewMockTable(ctrl)

				mockTable.EXPECT().importStatement(
					gomock.AssignableToTypeOf(new(TableContext)),
					gomock.AssignableToTypeOf(parachaintypes.SignedFullStatementWithPVD{}),
				).Return(nil, nil)
				mockTable.EXPECT().drainMisbehaviors().
					Return([]parachaintypes.ProvisionableDataMisbehaviorReport{})

				return map[common.Hash]*perRelayParentState{
					relayParent: {
						table: mockTable,
					},
				}
			},
			signedStatementWithPVD: parachaintypes.SignedFullStatementWithPVD{
				SignedFullStatement: parachaintypes.SignedFullStatement{
					Payload: statementVDTValid,
				},
			},
			err: "",
		},

		{
			description: "paraId_is_not_assigned_to_the_local_validator",
			perRelayParent: func() map[common.Hash]*perRelayParentState {
				ctrl := gomock.NewController(t)
				mockTable := NewMockTable(ctrl)

				mockTable.EXPECT().importStatement(
					gomock.AssignableToTypeOf(new(TableContext)),
					gomock.AssignableToTypeOf(parachaintypes.SignedFullStatementWithPVD{}),
				).Return(&Summary{
					GroupID: 4,
				}, nil)
				mockTable.EXPECT().drainMisbehaviors().
					Return([]parachaintypes.ProvisionableDataMisbehaviorReport{})
				mockTable.EXPECT().attestedCandidate(
					gomock.AssignableToTypeOf(parachaintypes.CandidateHash{}),
					gomock.AssignableToTypeOf(new(TableContext)),
				).Return(nil, errors.New("could not get attested candidate from table"))

				return map[common.Hash]*perRelayParentState{
					relayParent: {
						table:      mockTable,
						assignment: 5,
					},
				}
			},
			signedStatementWithPVD: parachaintypes.SignedFullStatementWithPVD{
				SignedFullStatement: parachaintypes.SignedFullStatement{
					Payload: statementVDTValid,
				},
			},
			err: "",
		},

		{
			description: "statementVDT_set_to_valid_and_candidate_not_in_fallbacks",
			perRelayParent: func() map[common.Hash]*perRelayParentState {
				ctrl := gomock.NewController(t)
				mockTable := NewMockTable(ctrl)

				mockTable.EXPECT().importStatement(
					gomock.AssignableToTypeOf(new(TableContext)),
					gomock.AssignableToTypeOf(parachaintypes.SignedFullStatementWithPVD{}),
				).Return(&Summary{
					Candidate: candidateHash,
					GroupID:   4,
				}, nil)
				mockTable.EXPECT().drainMisbehaviors().
					Return([]parachaintypes.ProvisionableDataMisbehaviorReport{})
				mockTable.EXPECT().attestedCandidate(
					gomock.AssignableToTypeOf(parachaintypes.CandidateHash{}),
					gomock.AssignableToTypeOf(new(TableContext)),
				).Return(new(AttestedCandidate), nil)

				return map[common.Hash]*perRelayParentState{
					relayParent: {
						table:      mockTable,
						assignment: 4,
						backed:     map[parachaintypes.CandidateHash]bool{},
						fallbacks:  map[parachaintypes.CandidateHash]attestingData{},
					},
				}
			},
			signedStatementWithPVD: parachaintypes.SignedFullStatementWithPVD{
				SignedFullStatement: parachaintypes.SignedFullStatement{
					Payload: statementVDTValid,
				},
			},
			err: errFallbackNotAvailable.Error(),
		},

		{
			description: "statementVDT_set_to_valid_also_same_validatorIndex_in_tableContext_and_signedStatement",
			perRelayParent: func() map[common.Hash]*perRelayParentState {
				ctrl := gomock.NewController(t)
				mockTable := NewMockTable(ctrl)

				mockTable.EXPECT().importStatement(
					gomock.AssignableToTypeOf(new(TableContext)),
					gomock.AssignableToTypeOf(parachaintypes.SignedFullStatementWithPVD{}),
				).Return(&Summary{
					Candidate: candidateHash,
					GroupID:   4,
				}, nil)
				mockTable.EXPECT().drainMisbehaviors().
					Return([]parachaintypes.ProvisionableDataMisbehaviorReport{})
				mockTable.EXPECT().attestedCandidate(
					gomock.AssignableToTypeOf(parachaintypes.CandidateHash{}),
					gomock.AssignableToTypeOf(new(TableContext)),
				).Return(new(AttestedCandidate), nil)

				return map[common.Hash]*perRelayParentState{
					relayParent: {
						table:        mockTable,
						tableContext: dummyTableContext(t),
						assignment:   4,
						backed:       map[parachaintypes.CandidateHash]bool{},
						fallbacks: map[parachaintypes.CandidateHash]attestingData{
							candidateHash: {},
						},
					},
				}
			},
			signedStatementWithPVD: parachaintypes.SignedFullStatementWithPVD{
				SignedFullStatement: parachaintypes.SignedFullStatement{
					Payload:        statementVDTValid,
					ValidatorIndex: 1,
				},
			},
			err: "",
		},
		{
			description: "statementVDT_set_to_valid_and_validation_job_already_running_for_candidate",
			perRelayParent: func() map[common.Hash]*perRelayParentState {
				ctrl := gomock.NewController(t)
				mockTable := NewMockTable(ctrl)

				mockTable.EXPECT().importStatement(
					gomock.AssignableToTypeOf(new(TableContext)),
					gomock.AssignableToTypeOf(parachaintypes.SignedFullStatementWithPVD{}),
				).Return(&Summary{
					Candidate: candidateHash,
					GroupID:   4,
				}, nil)
				mockTable.EXPECT().drainMisbehaviors().
					Return([]parachaintypes.ProvisionableDataMisbehaviorReport{})
				mockTable.EXPECT().attestedCandidate(
					gomock.AssignableToTypeOf(parachaintypes.CandidateHash{}),
					gomock.AssignableToTypeOf(new(TableContext)),
				).Return(new(AttestedCandidate), nil)

				return map[common.Hash]*perRelayParentState{
					relayParent: {
						table:        mockTable,
						tableContext: dummyTableContext(t),
						assignment:   4,
						backed:       map[parachaintypes.CandidateHash]bool{},
						fallbacks: map[parachaintypes.CandidateHash]attestingData{
							candidateHash: {},
						},
						awaitingValidation: map[parachaintypes.CandidateHash]bool{
							candidateHash: true,
						},
					},
				}
			},
			signedStatementWithPVD: parachaintypes.SignedFullStatementWithPVD{
				SignedFullStatement: parachaintypes.SignedFullStatement{
					Payload:        statementVDTValid,
					ValidatorIndex: 2,
				},
			},
			err: "",
		},
		{
			description: "statementVDT_set_to_valid_and_start_validation_job_for_candidate",
			perRelayParent: func() map[common.Hash]*perRelayParentState {
				ctrl := gomock.NewController(t)
				mockTable := NewMockTable(ctrl)

				mockTable.EXPECT().importStatement(
					gomock.AssignableToTypeOf(new(TableContext)),
					gomock.AssignableToTypeOf(parachaintypes.SignedFullStatementWithPVD{}),
				).Return(&Summary{
					Candidate: candidateHash,
					GroupID:   4,
				}, nil)
				mockTable.EXPECT().drainMisbehaviors().
					Return([]parachaintypes.ProvisionableDataMisbehaviorReport{})
				mockTable.EXPECT().attestedCandidate(
					gomock.AssignableToTypeOf(parachaintypes.CandidateHash{}),
					gomock.AssignableToTypeOf(new(TableContext)),
				).Return(new(AttestedCandidate), nil)

				return map[common.Hash]*perRelayParentState{
					relayParent: {
						table:        mockTable,
						tableContext: dummyTableContext(t),
						assignment:   4,
						backed:       map[parachaintypes.CandidateHash]bool{},
						fallbacks: map[parachaintypes.CandidateHash]attestingData{
							candidateHash: {
								candidate: getDummyCommittedCandidateReceipt(t).ToPlain(),
							},
						},
						awaitingValidation: map[parachaintypes.CandidateHash]bool{},
						issuedStatements: map[parachaintypes.CandidateHash]bool{
							candidateHash: true,
						},
					},
				}
			},

			perCandidate: map[parachaintypes.CandidateHash]*perCandidateState{
				candidateHash: {},
			},
			signedStatementWithPVD: parachaintypes.SignedFullStatementWithPVD{
				SignedFullStatement: parachaintypes.SignedFullStatement{
					Payload:        statementVDTValid,
					ValidatorIndex: 2,
				},
			},
			err: "",
		},
		{
			description: "statementVDT_set_to_seconded_and_error_getting_candidate_from_table",
			perRelayParent: func() map[common.Hash]*perRelayParentState {
				ctrl := gomock.NewController(t)
				mockTable := NewMockTable(ctrl)

				mockTable.EXPECT().importStatement(
					gomock.AssignableToTypeOf(new(TableContext)),
					gomock.AssignableToTypeOf(parachaintypes.SignedFullStatementWithPVD{}),
				).Return(&Summary{
					Candidate: candidateHash,
					GroupID:   4,
				}, nil)
				mockTable.EXPECT().drainMisbehaviors().
					Return([]parachaintypes.ProvisionableDataMisbehaviorReport{})
				mockTable.EXPECT().attestedCandidate(
					gomock.AssignableToTypeOf(parachaintypes.CandidateHash{}),
					gomock.AssignableToTypeOf(new(TableContext)),
				).Return(new(AttestedCandidate), nil)
				mockTable.EXPECT().getCandidate(
					gomock.AssignableToTypeOf(parachaintypes.CandidateHash{}),
				).Return(
					new(parachaintypes.CommittedCandidateReceipt),
					errors.New("could not get candidate from table"),
				)

				return map[common.Hash]*perRelayParentState{
					relayParent: {
						table:      mockTable,
						assignment: 4,
						backed: map[parachaintypes.CandidateHash]bool{
							candidateHash: true,
						},
						fallbacks: map[parachaintypes.CandidateHash]attestingData{},
						issuedStatements: map[parachaintypes.CandidateHash]bool{
							candidateHash: true,
						},
					},
				}
			},
			signedStatementWithPVD: secondedSignedFullStatementWithPVD(t, statementVDTSeconded),
			err:                    "could not get candidate from table",
		},
		{
			description: "statementVDT_set_to_seconded_and_successfully_get_candidate_from_table",
			perRelayParent: func() map[common.Hash]*perRelayParentState {
				ctrl := gomock.NewController(t)
				mockTable := NewMockTable(ctrl)

				mockTable.EXPECT().importStatement(
					gomock.AssignableToTypeOf(new(TableContext)),
					gomock.AssignableToTypeOf(parachaintypes.SignedFullStatementWithPVD{}),
				).Return(&Summary{
					Candidate: candidateHash,
					GroupID:   4,
				}, nil)
				mockTable.EXPECT().drainMisbehaviors().
					Return([]parachaintypes.ProvisionableDataMisbehaviorReport{})
				mockTable.EXPECT().attestedCandidate(
					gomock.AssignableToTypeOf(parachaintypes.CandidateHash{}),
					gomock.AssignableToTypeOf(new(TableContext)),
				).Return(new(AttestedCandidate), nil)
				mockTable.EXPECT().getCandidate(
					gomock.AssignableToTypeOf(parachaintypes.CandidateHash{}),
				).Return(&dummyCCR, nil)

				return map[common.Hash]*perRelayParentState{
					relayParent: {
						table:      mockTable,
						assignment: 4,
						backed: map[parachaintypes.CandidateHash]bool{
							candidateHash: true,
						},
						fallbacks: map[parachaintypes.CandidateHash]attestingData{},
						issuedStatements: map[parachaintypes.CandidateHash]bool{
							candidateHash: true,
						},
					},
				}

			},
			signedStatementWithPVD: secondedSignedFullStatementWithPVD(t, statementVDTSeconded),
			err:                    "",
		},
	}

	for _, c := range testCases {
		c := c
		t.Run(c.description, func(t *testing.T) {
			t.Parallel()

			subSystemToOverseer := make(chan any)

			backing := CandidateBacking{
				SubSystemToOverseer: subSystemToOverseer,
				perRelayParent:      c.perRelayParent(),
				perCandidate: func() map[parachaintypes.CandidateHash]*perCandidateState {
					if c.perCandidate == nil {
						return map[parachaintypes.CandidateHash]*perCandidateState{}
					}
					return c.perCandidate
				}(),
			}

			defer close(subSystemToOverseer)
			go mockOverseer(t, subSystemToOverseer)

			err := backing.handleStatementMessage(relayParent, c.signedStatementWithPVD, chRelayParentAndCommand)
			if c.err == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, c.err)
			}
		})
	}
}
