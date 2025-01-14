// Copyright 2023 ChainSafe Systems (ON)
// SPDX-License-Identifier: LGPL-3.0-only

package grandpa

import (
	"time"

	"golang.org/x/exp/constraints"
)

type stateStart[T any] [2]T

type stateProposed[T any] [2]T

type statePrevoting[T, U any] struct {
	T T
	U U
}

type statePrevoted[T any] [1]T

type statePrecommitted struct{}

type states[T, W any] interface {
	stateStart[T] | stateProposed[T] | statePrevoting[T, W] | statePrevoted[T] | statePrecommitted
}

// The state of a voting round.
type state any

func setState[T, W any, V states[T, W]](s *state, val V) {
	*s = val
}

func newState[T, W any, V states[T, W]](val V) state {
	var s state
	setState[T, W](&s, val)
	return s
}

type hashBestChain[Hash comparable, Number constraints.Unsigned] struct {
	Hash      Hash
	BestChain BestChain[Hash, Number]
}

// Whether we should vote in the current round (i.e. push votes to the sink.)
type voting uint

const (
	// Voting is disabled for the current round.
	votingNo voting = iota
	// Voting is enabled for the current round (prevotes and precommits.)
	votingYes
	// Voting is enabled for the current round and we are the primary proposer
	// (we can also push primary propose messages).
	votingPrimary
)

// Whether the voter should cast round votes (prevotes and precommits.)
func (v voting) isActive() bool {
	return v == votingYes || v == votingPrimary
}

// Whether the voter is the primary proposer.
func (v voting) isPrimary() bool {
	return v == votingPrimary
}

// Logic for a voter on a specific round.
type votingRound[
	Hash constraints.Ordered,
	Number constraints.Unsigned,
	Signature comparable,
	ID constraints.Ordered,
	E Environment[Hash, Number, Signature, ID],
] struct {
	env               E
	voting            voting
	votes             *Round[ID, Hash, Number, Signature]
	incoming          *wakerChan[SignedMessageError[Hash, Number, Signature, ID]]
	outgoing          *buffered[Message[Hash, Number]]
	state             state
	bridgedRoundState priorView[Hash, Number]
	lastRoundState    latterView[Hash, Number]
	primaryBlock      *HashNumber[Hash, Number]
	finalizedSender   chan finalizedNotification[Hash, Number, Signature, ID]
	bestFinalized     *Commit[Hash, Number, Signature, ID]
}

// Create a new voting round.
func newVotingRound[
	Hash constraints.Ordered, Number constraints.Unsigned, Signature comparable, ID constraints.Ordered,
	E Environment[Hash, Number, Signature, ID],
](
	roundNumber uint64, voters VoterSet[ID], base HashNumber[Hash, Number],
	lastRoundState latterView[Hash, Number],
	finalizedSender chan finalizedNotification[Hash, Number, Signature, ID], env E,
) votingRound[Hash, Number, Signature, ID, E] {
	outgoing := make(chan Message[Hash, Number])
	roundData := env.RoundData(roundNumber, outgoing)
	roundParams := RoundParams[ID, Hash, Number]{
		RoundNumber: roundNumber,
		Voters:      voters,
		Base:        base,
	}

	votes := NewRound[ID, Hash, Number, Signature](roundParams)

	primaryVoterID, _ := votes.PrimaryVoter()
	var voting voting //nolint:govet
	if roundData.VoterID != nil && *roundData.VoterID == primaryVoterID {
		voting = votingPrimary
	} else if roundData.VoterID != nil && votes.Voters().Contains(*roundData.VoterID) {
		voting = votingYes
	} else {
		voting = votingNo
	}

	return votingRound[Hash, Number, Signature, ID, E]{
		votes:    votes,
		voting:   voting,
		incoming: newWakerChan(roundData.Incoming),
		outgoing: newBuffered(outgoing),
		state: newState[Timer, hashBestChain[Hash, Number]](
			stateStart[Timer]{roundData.PrevoteTimer, roundData.PrecommitTimer}),
		bridgedRoundState: nil,
		primaryBlock:      nil,
		bestFinalized:     nil,
		env:               env,
		lastRoundState:    lastRoundState,
		finalizedSender:   finalizedSender,
	}
}

// Create a voting round from a completed `Round`. We will not vote further
// in this round.
func newVotingRoundCompleted[
	Hash constraints.Ordered, Number constraints.Unsigned, Signature comparable, ID constraints.Ordered,
	E Environment[Hash, Number, Signature, ID],
](
	votes *Round[ID, Hash, Number, Signature],
	finalizedSender chan finalizedNotification[Hash, Number, Signature, ID],
	lastRoundState latterView[Hash, Number],
	env E,
) votingRound[Hash, Number, Signature, ID, E] {
	outgoing := make(chan Message[Hash, Number])
	roundData := env.RoundData(votes.Number(), outgoing)
	return votingRound[Hash, Number, Signature, ID, E]{
		votes:             votes,
		voting:            votingNo,
		incoming:          newWakerChan(roundData.Incoming),
		outgoing:          newBuffered(outgoing),
		state:             nil,
		bridgedRoundState: nil,
		primaryBlock:      nil,
		bestFinalized:     nil,
		env:               env,
		lastRoundState:    lastRoundState,
		finalizedSender:   finalizedSender,
	}
}

// Poll the round. When the round is completable and messages have been flushed, it will return `true` but
// can continue to be polled.
func (vr *votingRound[Hash, Number, Signature, ID, E]) poll(waker *waker) (bool, error) { //skipcq: GO-R1005
	log.Tracef(
		"Polling round %d, state = %+v, step = %T",
		vr.votes.Number(),
		vr.votes.State(),
		vr.state,
	)

	preState := vr.votes.State()
	err := vr.processIncoming(waker)
	if err != nil {
		return true, err
	}

	// we only cast votes when we have access to the previous round state.
	// we might have started this round as a prospect "future" round to
	// check whether the voter is lagging behind the current round.
	var lastRoundState *RoundState[Hash, Number]
	if vr.lastRoundState != nil {
		lrr := vr.lastRoundState.get(waker)
		lastRoundState = &lrr
	}
	if lastRoundState != nil {
		err := vr.primaryPropose(lastRoundState)
		if err != nil {
			return true, err
		}
		err = vr.prevote(waker, lastRoundState)
		if err != nil {
			return true, err
		}
		err = vr.precommit(waker, lastRoundState)
		if err != nil {
			return true, err
		}
	}

	ready, err := vr.outgoing.Poll(waker)
	if !ready {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	err = vr.processIncoming(waker) // in case we got a new message signed locally.
	if err != nil {
		return true, err
	}

	// broadcast finality notifications after attempting to cast votes
	postState := vr.votes.State()
	vr.notify(preState, postState)

	completable := vr.votes.Completable()
	// early exit if the current round is not completable
	if !completable {
		return false, nil
	}

	// make sure that the previous round estimate has been finalized
	var lastRoundEstimateFinalized bool
	switch {
	case lastRoundState != nil && lastRoundState.Estimate != nil && lastRoundState.Finalized != nil:
		// either it was already finalized in the previous round
		finalizedInLastRound := lastRoundState.Estimate.Number <= lastRoundState.Finalized.Number

		// or it must be finalized in the current round
		var finalizedInCurrentRound bool
		if vr.finalized() != nil {
			finalizedInCurrentRound = lastRoundState.Estimate.Number <= vr.finalized().Number
		}

		lastRoundEstimateFinalized = finalizedInLastRound || finalizedInCurrentRound
	case lastRoundState == nil:
		// NOTE: when we catch up to a round we complete the round
		// without any last round state. in this case we already started
		// a new round after we caught up so this guard is unneeded.
		lastRoundEstimateFinalized = true
	default:
		lastRoundEstimateFinalized = false
	}

	// the previous round estimate must be finalized
	if !lastRoundEstimateFinalized {
		log.Tracef("Round {} completable but estimate not finalized.", vr.roundNumber())
		vr.logParticipation(trace)
		return false, nil
	}

	log.Debugf(
		"Completed round %d, state = %+v, step = %T",
		vr.votes.Number(),
		vr.votes.State(),
		vr.state,
	)

	vr.logParticipation(debug)
	return true, nil
}

// Inspect the state of this round.
func (vr *votingRound[Hash, Number, Signature, ID, E]) State() any {
	return vr.state
}

// Get access to the underlying environment.
func (vr *votingRound[Hash, Number, Signature, ID, E]) Env() E {
	return vr.env
}

// Get the round number.
func (vr *votingRound[Hash, Number, Signature, ID, E]) roundNumber() uint64 {
	return vr.votes.Number()
}

// Get the round state.
func (vr *votingRound[Hash, Number, Signature, ID, E]) roundState() RoundState[Hash, Number] {
	return vr.votes.State()
}

// Get the base block in the dag.
func (vr *votingRound[Hash, Number, Signature, ID, E]) dagBase() HashNumber[Hash, Number] {
	return vr.votes.Base()
}

// Get the base block in the dag.
func (vr *votingRound[Hash, Number, Signature, ID, E]) voters() VoterSet[ID] {
	return vr.votes.Voters()
}

// Get the best block finalized in this round.
func (vr *votingRound[Hash, Number, Signature, ID, E]) finalized() *HashNumber[Hash, Number] {
	return vr.votes.State().Finalized
}

// Get the current total weight of prevotes.
func (vr *votingRound[Hash, Number, Signature, ID, E]) preVoteWeight() VoteWeight {
	weight, _ := vr.votes.PrevoteParticipation()
	return weight
}

// Get the current total weight of precommits.
func (vr *votingRound[Hash, Number, Signature, ID, E]) precommitWeight() VoteWeight {
	weight, _ := vr.votes.PrecommitParticipation()
	return weight
}

// Get the current total weight of prevotes.
func (vr *votingRound[Hash, Number, Signature, ID, E]) prevoteIDs() []ID {
	var ids []ID
	for _, pv := range vr.votes.Prevotes() {
		ids = append(ids, pv.ID)
	}
	return ids
}

// Get the current total weight of prevotes.
func (vr *votingRound[Hash, Number, Signature, ID, E]) precommitIDs() []ID {
	var ids []ID
	for _, pv := range vr.votes.Precommits() {
		ids = append(ids, pv.ID)
	}
	return ids
}

// Check a commit. If it's valid, import all the votes into the round as well.
// Returns the finalized base if it checks out.
func (vr *votingRound[Hash, Number, Signature, ID, E]) checkAndImportFromCommit(
	commit Commit[Hash, Number, Signature, ID],
) (*HashNumber[Hash, Number], error) {
	cvr, err := ValidateCommit[Hash, Number](commit, vr.voters(), vr.env)
	if err != nil {
		return nil, err
	}
	if !cvr.Valid() {
		return nil, nil
	}

	for _, signedPrecommit := range commit.Precommits {
		precommit := signedPrecommit.Precommit
		signature := signedPrecommit.Signature
		id := signedPrecommit.ID

		importResult, err := vr.votes.importPrecommit(vr.env, precommit, id, signature)
		if err != nil {
			return nil, err
		}
		if importResult.Equivocation != nil {
			vr.env.PrecommitEquivocation(vr.roundNumber(), *importResult.Equivocation)
		}
	}

	return &HashNumber[Hash, Number]{commit.TargetHash, commit.TargetNumber}, nil
}

// Get a clone of the finalized sender.
func (vr *votingRound[Hash, Number, Signature, ID, E]) FinalizedSender() chan finalizedNotification[Hash, Number, Signature, ID] { //nolint:lll
	return vr.finalizedSender
}

// call this when we build on top of a given round in order to get a handle
// to updates to the latest round-state.
func (vr *votingRound[Hash, Number, Signature, ID, E]) bridgeState() latterView[Hash, Number] {
	priorView, latterView := bridgeState(vr.votes.State())
	if vr.bridgedRoundState != nil {
		log.Warnf("Bridged state from round %d more than once", vr.votes.Number())
	}

	vr.bridgedRoundState = priorView
	return latterView
}

// Get a commit justifying the best finalized block.
func (vr *votingRound[Hash, Number, Signature, ID, E]) finalizingCommit() *Commit[Hash, Number, Signature, ID] {
	return vr.bestFinalized
}

// Return all votes for the round (prevotes and precommits), sorted by
// imported order and indicating the indices where we voted. At most two
// prevotes and two precommits per voter are present, further equivocations
// are not stored (as they are redundant).
func (vr *votingRound[Hash, Number, Signature, ID, E]) historicalVotes() HistoricalVotes[Hash, Number, Signature, ID] {
	return vr.votes.HistoricalVotes()
}

// Handle a vote manually.
func (vr *votingRound[Hash, Number, Signature, ID, E]) handleVote(vote SignedMessage[Hash, Number, Signature, ID]) error { //nolint:lll
	message := vote.Message
	if !vr.env.IsEqualOrDescendantOf(vr.votes.Base().Hash, message.Target().Hash) {
		return nil
	}

	switch message := message.inner.(type) {
	case Prevote[Hash, Number]:
		prevote := message
		importResult, err := vr.votes.importPrevote(vr.env, prevote, vote.ID, vote.Signature)
		if err != nil {
			return err
		}
		if importResult.Equivocation != nil {
			vr.env.PrevoteEquivocation(vr.votes.Number(), *importResult.Equivocation)
		}
	case Precommit[Hash, Number]:
		precommit := message
		importResult, err := vr.votes.importPrecommit(vr.env, precommit, vote.ID, vote.Signature)
		if err != nil {
			return err
		}
		if importResult.Equivocation != nil {
			vr.env.PrecommitEquivocation(vr.votes.Number(), *importResult.Equivocation)
		}
	case PrimaryPropose[Hash, Number]:
		primary := message
		primaryID, _ := vr.votes.PrimaryVoter()
		// note that id here refers to the party which has cast the vote
		// and not the id of the party which has received the vote message.
		if vote.ID == primaryID {
			vr.primaryBlock = &HashNumber[Hash, Number]{primary.TargetHash, primary.TargetNumber}
		}
	}

	return nil
}

func (vr *votingRound[Hash, Number, Signature, ID, E]) logParticipation(level logLevel) {
	totalWeight := vr.voters().TotalWeight()
	threshold := vr.voters().Threshold()
	nVoters := vr.voters().Len()
	number := vr.roundNumber()

	preVoteWeight, nPrevotes := vr.votes.PrevoteParticipation()
	precommitWeight, nPrecommits := vr.votes.PrecommitParticipation()

	var logf func(format string, values ...any)
	switch level {
	case debug:
		logf = log.Debugf
	case trace:
		logf = log.Tracef
	}

	logf("%s: Round %d: prevotes: %d/%d/%d weight, %d/%d actual",
		level, number, preVoteWeight, threshold, totalWeight, nPrevotes, nVoters)

	logf("%s: Round %d: precommits: %d/%d/%d weight, %d/%d actual",
		level, number, precommitWeight, threshold, totalWeight, nPrecommits, nVoters)
}

func (vr *votingRound[Hash, Number, Signature, ID, E]) processIncoming(waker *waker) error {
	vr.incoming.setWaker(waker)
	var (
		msgCount  = 0
		timer     *time.Timer
		timerChan <-chan time.Time
	)
while:
	for {
		select {
		case incoming := <-vr.incoming.channel():
			log.Tracef("Round %d: Got incoming message", vr.roundNumber())
			if timer != nil {
				timer.Stop()
				timer = nil
			}
			if incoming.Error != nil {
				return incoming.Error
			}
			err := vr.handleVote(incoming.SignedMessage)
			if err != nil {
				return err
			}
			msgCount++
		case <-timerChan:
			if msgCount > 0 {
				log.Tracef("processed %d messages", msgCount)
			}
			break while
		default:
			if timer == nil {
				// delay 1ms before exiting this loop
				timer = time.NewTimer(1 * time.Millisecond)
				timerChan = timer.C
			}
		}
	}
	return nil
}

func (vr *votingRound[Hash, Number, Signature, ID, E]) primaryPropose(lastRoundState *RoundState[Hash, Number]) error {
	state := vr.state
	vr.state = nil

	if state == nil {
		return nil
	}
	switch state := state.(type) {
	case stateStart[Timer]:
		prevoteTimer := state[0]
		precommitTimer := state[1]

		maybeEstimate := lastRoundState.Estimate
		switch {
		case maybeEstimate != nil && vr.voting.isPrimary():
			lastRoundEstimate := maybeEstimate
			maybeFinalized := lastRoundState.Finalized

			var shouldSendPrimary = true
			if maybeFinalized != nil {
				shouldSendPrimary = lastRoundEstimate.Number > maybeFinalized.Number
			}
			if shouldSendPrimary {
				log.Debugf("Sending primary block hint for round %d", vr.votes.Number())
				primary := PrimaryPropose[Hash, Number]{
					TargetHash:   lastRoundEstimate.Hash,
					TargetNumber: lastRoundEstimate.Number,
				}
				err := vr.env.Proposed(vr.roundNumber(), primary)
				if err != nil {
					return err
				}
				message := NewMessage(primary)
				vr.outgoing.Push(message)
				setState[Timer, hashBestChain[Hash, Number]](&vr.state, stateProposed[Timer]{prevoteTimer, precommitTimer})

				return nil
			}
			log.Debugf(
				"Last round estimate has been finalized, not sending primary block hint for round %d",
				vr.votes.Number(),
			)

		case maybeEstimate == nil && vr.voting.isPrimary():
			log.Debugf("Last round estimate does not exist, not sending primary block hint for round %d", vr.votes.Number())
		default:
		}
		setState[Timer, hashBestChain[Hash, Number]](&vr.state, stateStart[Timer]{prevoteTimer, precommitTimer})
	default:
		vr.state = state
	}
	return nil
}

func (vr *votingRound[Hash, Number, Signature, ID, E]) prevote(w *waker, lastRoundState *RoundState[Hash, Number]) error { //nolint:lll //skipcq: GO-R1005
	state := vr.state
	vr.state = nil

	var startPrevoting = func(prevoteTimer Timer, precommitTimer Timer, proposed bool, waker *waker) error {
		prevoteTimer.SetWaker(waker)
		var shouldPrevote bool
		elapsed, err := prevoteTimer.Elapsed()
		if elapsed {
			if err != nil {
				return err
			}
			shouldPrevote = true
		} else {
			shouldPrevote = vr.votes.Completable()
		}

		if shouldPrevote {
			if vr.voting.isActive() {
				log.Debugf("Constructing prevote for round %d", vr.votes.Number())

				base, bestChain := vr.constructPrevote(lastRoundState)

				// since we haven't polled the future above yet we need to
				// manually schedule the current task to be awoken so the
				// `bestChain` future is then polled below after we switch the
				// state to `Prevoting`.
				waker.wake()

				setState[Timer, hashBestChain[Hash, Number]](&vr.state, statePrevoting[Timer, hashBestChain[Hash, Number]]{
					precommitTimer, hashBestChain[Hash, Number]{base, bestChain},
				})
			} else {
				setState[Timer, hashBestChain[Hash, Number]](&vr.state, statePrevoted[Timer]{precommitTimer})
			}
		} else if proposed {
			setState[Timer, hashBestChain[Hash, Number]](&vr.state, stateProposed[Timer]{prevoteTimer, precommitTimer})
		} else {
			setState[Timer, hashBestChain[Hash, Number]](&vr.state, stateStart[Timer]{prevoteTimer, precommitTimer})
		}

		return nil
	}

	var finishPrevoting = func(precommitTimer Timer, base Hash, bestChain BestChain[Hash, Number], waker *waker) error {
		wakerChan := newWakerChan(bestChain)
		wakerChan.setWaker(waker)
		var best *HashNumber[Hash, Number]
		res := <-wakerChan.channel()
		switch {
		case res.Error != nil:
			return res.Error
		case res.Value != nil:
			best = res.Value
		default:
			setState[Timer, hashBestChain[Hash, Number]](&vr.state, statePrevoting[Timer, hashBestChain[Hash, Number]]{
				precommitTimer, hashBestChain[Hash, Number]{base, bestChain},
			})
			return nil
		}

		if best != nil {
			prevote := Prevote[Hash, Number]{best.Hash, best.Number}

			log.Debugf("Casting prevote for round {}", vr.votes.Number())
			err := vr.env.Prevoted(vr.roundNumber(), prevote)
			if err != nil {
				return err
			}
			vr.votes.SetPrevotedIdx()
			message := NewMessage(prevote)
			vr.outgoing.Push(message)
			setState[Timer, hashBestChain[Hash, Number]](&vr.state, statePrevoted[Timer]{precommitTimer})
		} else {
			log.Warnf("Could not cast prevote: previously known block %v has disappeared", base)

			// when we can't construct a prevote, we shouldn't precommit.
			vr.state = nil
			vr.voting = votingNo
		}

		return nil
	}

	if state == nil {
		return nil
	}
	switch state := state.(type) {
	case stateStart[Timer]:
		return startPrevoting(state[0], state[1], false, w)
	case stateProposed[Timer]:
		return startPrevoting(state[0], state[1], true, w)
	case statePrevoting[Timer, hashBestChain[Hash, Number]]:
		return finishPrevoting(state.T, state.U.Hash, state.U.BestChain, w)
	default:
		vr.state = state
	}

	return nil
}

func (vr *votingRound[Hash, Number, Signature, ID, E]) precommit(waker *waker, lastRoundState *RoundState[Hash, Number]) error { //nolint:lll
	state := vr.state
	vr.state = nil
	if state == nil {
		return nil
	}
	switch state := state.(type) {
	case statePrevoted[Timer]:
		precommitTimer := state[0]
		precommitTimer.SetWaker(waker)
		lastRoundEstimate := lastRoundState.Estimate
		if lastRoundEstimate == nil {
			panic("Rounds only started when prior round completable; qed")
		}

		var shouldPrecommit bool
		var ls bool
		st := vr.votes.State()
		pg := st.PrevoteGHOST
		if pg != nil {
			ls = *pg == *lastRoundEstimate || vr.env.IsEqualOrDescendantOf(lastRoundEstimate.Hash, pg.Hash)
		}
		var rs bool
		elapsed, err := precommitTimer.Elapsed()
		if elapsed {
			if err != nil {
				return err
			} else {
				rs = true
			}
		} else {
			rs = vr.votes.Completable()
		}
		shouldPrecommit = ls && rs

		if shouldPrecommit {
			if vr.voting.isActive() {
				log.Debugf("Casting precommit for round {}", vr.votes.Number())
				precommit := vr.constructPrecommit()
				err := vr.env.Precommitted(vr.roundNumber(), precommit)
				if err != nil {
					return err
				}
				vr.votes.SetPrecommittedIdx()
				message := NewMessage(precommit)
				vr.outgoing.Push(message)
			}
			setState[Timer, hashBestChain[Hash, Number]](&vr.state, statePrecommitted{})
		} else {
			setState[Timer, hashBestChain[Hash, Number]](&vr.state, statePrevoted[Timer]{precommitTimer})
		}
	default:
		vr.state = state
	}

	return nil
}

// construct a prevote message based on local state.
func (vr *votingRound[Hash, Number, Signature, ID, E]) constructPrevote(lastRoundState *RoundState[Hash, Number]) (h Hash, bc BestChain[Hash, Number]) { //nolint:lll
	lastRoundEstimate := lastRoundState.Estimate
	if lastRoundEstimate == nil {
		panic("Rounds only started when prior round completable; qed")
	}

	var findDescendentOf Hash
	switch primaryBlock := vr.primaryBlock; primaryBlock {
	case nil:
		// vote for best chain containing prior round-estimate.
		findDescendentOf = lastRoundEstimate.Hash
	default:
		// we will vote for the best chain containing `pHash` if
		// the last round's prevote-GHOST included that block and
		// that block is a strict descendent of the last round-estimate that we are
		// aware of.
		lastPrevoteG := lastRoundState.PrevoteGHOST
		if lastPrevoteG == nil {
			panic("Rounds only started when prior round completable; qed")
		}

		// if the blocks are equal, we don't check ancestry.
		if *primaryBlock == *lastPrevoteG {
			findDescendentOf = primaryBlock.Hash
		} else if primaryBlock.Hash >= lastPrevoteG.Hash {
			findDescendentOf = lastRoundEstimate.Hash
		} else {
			// from this point onwards, the number of the primary-broadcasted
			// block is less than the last prevote-GHOST's number.
			// if the primary block is in the ancestry of p-G we vote for the
			// best chain containing it.
			pHash := primaryBlock.Hash
			pNum := primaryBlock.Number
			ancestry, err := vr.env.Ancestry(lastRoundEstimate.Hash, lastPrevoteG.Hash)
			if err != nil {
				// This is only possible in case of massive equivocation
				log.Warnf(
					"Possible case of massive equivocation: last round prevote GHOST: %v"+
						" is not a descendant of last round estimate: %v",
					lastPrevoteG,
					lastRoundEstimate,
				)
				findDescendentOf = lastRoundEstimate.Hash
			} else {
				toSub := pNum + 1

				var offset uint
				if lastPrevoteG.Number < toSub {
					offset = 0
				} else {
					offset = uint(lastPrevoteG.Number - toSub)
				}

				if offset >= uint(len(ancestry)) {
					findDescendentOf = lastRoundEstimate.Hash
				} else {
					if ancestry[offset] == pHash {
						findDescendentOf = pHash
					} else {
						findDescendentOf = lastRoundEstimate.Hash
					}
				}
			}
		}
	}

	return findDescendentOf, vr.env.BestChainContaining(findDescendentOf)
}

// construct a precommit message based on local state.
func (vr *votingRound[Hash, Number, Signature, ID, E]) constructPrecommit() Precommit[Hash, Number] {
	var t HashNumber[Hash, Number]
	switch target := vr.votes.State().PrevoteGHOST; target {
	case nil:
		t = vr.votes.Base()
	default:
		t = *target
	}
	return Precommit[Hash, Number]{t.Hash, t.Number}
}

// notify when new blocks are finalized or when the round-estimate is updated
func (vr *votingRound[Hash, Number, Signature, ID, E]) notify(
	lastState RoundState[Hash, Number],
	newState RoundState[Hash, Number],
) {
	// `RoundState` attributes have pointers to values so comparison here is on pointer address.
	// It's assumed that the `Round` attributes will use a new address for new values.
	// Given the caller of this function, we know that new values will use new addresses
	// so no need for deep value comparison.
	if lastState != newState {
		if vr.bridgedRoundState != nil {
			vr.bridgedRoundState.update(newState)
		}
	}

	// send notification only when the round is completable and we've cast votes.
	// this is a workaround that ensures when we re-instantiate the voter after
	// a shutdown, we never re-create the same round with a base that was finalized
	// in this round or after.
	// we try to notify if either the round state changed or if we haven't
	// sent any notification yet (this is to guard against seeing enough
	// votes to finalize before having precommited)
	stateChanged := lastState.Finalized != newState.Finalized
	sentFinalityNotifications := vr.bestFinalized != nil

	if newState.Completable && (stateChanged || !sentFinalityNotifications) {
		_, precommited := vr.state.(statePrecommitted)
		// we only cast votes when we have access to the previous round state,
		// which won't be the case whenever we catch up to a later round.
		cantVote := vr.lastRoundState == nil

		if precommited || cantVote {
			if newState.Finalized != nil {
				precommits := vr.votes.FinalizingPrecommits(vr.env)
				if precommits == nil {
					panic("always returns none if something was finalized; this is checked above; qed")
				}
				commit := Commit[Hash, Number, Signature, ID]{
					TargetHash:   newState.Finalized.Hash,
					TargetNumber: newState.Finalized.Number,
					Precommits:   *precommits,
				}
				vr.finalizedSender <- finalizedNotification[Hash, Number, Signature, ID]{
					Hash:   newState.Finalized.Hash,
					Number: newState.Finalized.Number,
					Round:  vr.votes.Number(),
					Commit: commit,
				}
				vr.bestFinalized = &commit
			}
		}
	}

}
