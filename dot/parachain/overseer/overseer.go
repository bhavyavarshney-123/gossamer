// Copyright 2023 ChainSafe Systems (ON)
// SPDX-License-Identifier: LGPL-3.0-only

package overseer

import (
	"context"
	"fmt"
	"sync"
	"time"

	availability_store "github.com/ChainSafe/gossamer/dot/parachain/availability-store"
	"github.com/ChainSafe/gossamer/dot/parachain/backing"
	collatorprotocol "github.com/ChainSafe/gossamer/dot/parachain/collator-protocol"
	"github.com/ChainSafe/gossamer/dot/types"
	"github.com/ChainSafe/gossamer/lib/common"

	parachaintypes "github.com/ChainSafe/gossamer/dot/parachain/types"
	"github.com/ChainSafe/gossamer/internal/log"
)

var (
	logger = log.NewFromGlobal(log.AddContext("pkg", "parachain-overseer"))
)

type Overseer struct {
	ctx     context.Context
	cancel  context.CancelFunc
	errChan chan error // channel for overseer to send errors to service that started it

	blockState   BlockState
	activeLeaves map[common.Hash]uint32

	// block notification channels
	imported  chan *types.Block
	finalised chan *types.FinalisationInfo

	SubsystemsToOverseer chan Message[any, any]               // channel for subsystems to send messages to overseer
	subsystems           map[Subsystem]chan Message[any, any] // map[Subsystem]OverseerToSubSystem channel
	nameToSubsystem      map[parachaintypes.SubSystemName]Subsystem
	wg                   sync.WaitGroup
}

// BlockState interface for block state methods
type BlockState interface {
	GetImportedBlockNotifierChannel() chan *types.Block
	FreeImportedBlockNotifierChannel(ch chan *types.Block)
	GetFinalisedNotifierChannel() chan *types.FinalisationInfo
	FreeFinalisedNotifierChannel(ch chan *types.FinalisationInfo)
}

func NewOverseer(blockState BlockState) *Overseer {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	return &Overseer{
		ctx:                  ctx,
		cancel:               cancel,
		errChan:              make(chan error),
		blockState:           blockState,
		activeLeaves:         make(map[common.Hash]uint32),
		SubsystemsToOverseer: make(chan Message[any, any]),
		subsystems:           make(map[Subsystem]chan Message[any, any]),
		nameToSubsystem:      make(map[parachaintypes.SubSystemName]Subsystem),
	}
}

// RegisterSubsystem registers a subsystem with the overseer,
// Add OverseerToSubSystem channel to subsystem, which will be passed to subsystem's Run method.
func (o *Overseer) RegisterSubsystem(subsystem Subsystem) chan Message[any, any] {
	OverseerToSubSystem := make(chan Message[any, any])
	o.subsystems[subsystem] = OverseerToSubSystem
	o.nameToSubsystem[subsystem.Name()] = subsystem

	return OverseerToSubSystem
}

func (o *Overseer) Start() error {

	imported := o.blockState.GetImportedBlockNotifierChannel()
	finalised := o.blockState.GetFinalisedNotifierChannel()

	o.imported = imported
	o.finalised = finalised

	// start subsystems
	for subsystem, overseerToSubSystem := range o.subsystems {
		o.wg.Add(1)
		go func(sub Subsystem, overseerToSubSystem chan Message[any, any]) {
			err := sub.Run(o.ctx, overseerToSubSystem, o.SubsystemsToOverseer)
			if err != nil {
				logger.Errorf("running subsystem %v failed: %v", sub, err)
			}
			logger.Infof("subsystem %v stopped", sub)
			o.wg.Done()
		}(subsystem, overseerToSubSystem)
	}

	o.wg.Add(2)
	go o.processMessages()
	go o.handleBlockEvents()

	return nil
}

func (o *Overseer) processMessages() {
	for {
		select {
		case msg := <-o.SubsystemsToOverseer:
			var subsystem Subsystem

			switch msg.Data.(type) {
			case backing.GetBackedCandidates, backing.CanSecond, backing.Second, backing.Statement:
				subsystem = o.nameToSubsystem[parachaintypes.CandidateBacking]

			case collatorprotocol.CollateOn, collatorprotocol.DistributeCollation, collatorprotocol.ReportCollator,
				collatorprotocol.Backed, collatorprotocol.AdvertiseCollation, collatorprotocol.InvalidOverseerMsg,
				collatorprotocol.SecondedOverseerMsg:

				subsystem = o.nameToSubsystem[parachaintypes.CollationProtocol]

			case availability_store.QueryAvailableData, availability_store.QueryDataAvailability,
				availability_store.QueryChunk, availability_store.QueryChunkSize, availability_store.QueryAllChunks,
				availability_store.QueryChunkAvailability, availability_store.StoreChunk,
				availability_store.StoreAvailableData:

				subsystem = o.nameToSubsystem[parachaintypes.AvailabilityStore]

			default:
				logger.Error("unknown message type")
			}

			overseerToSubsystem := o.subsystems[subsystem]
			overseerToSubsystem <- msg

		case <-o.ctx.Done():
			if err := o.ctx.Err(); err != nil {
				logger.Errorf("ctx error: %v\n", err)
			}
			o.wg.Done()
			return
		}
	}
}

func (o *Overseer) handleBlockEvents() {
	for {
		select {
		case <-o.ctx.Done():
			if err := o.ctx.Err(); err != nil {
				logger.Errorf("ctx error: %v\n", err)
			}
			o.wg.Done()
			return
		case imported := <-o.imported:
			blockNumber, ok := o.activeLeaves[imported.Header.Hash()]
			if ok {
				if blockNumber != uint32(imported.Header.Number) {
					panic("block number mismatch")
				}
				return
			}

			o.activeLeaves[imported.Header.Hash()] = uint32(imported.Header.Number)
			delete(o.activeLeaves, imported.Header.ParentHash)

			// TODO:
			/*
				- Add active leaf only if given head supports parachain consensus.
				- You do that by checking the parachain host runtime api version.
				- If the parachain host runtime api version is at least 1, then the parachain consensus is supported.

					#[async_trait::async_trait]
					impl<Client> HeadSupportsParachains for Arc<Client>
					where
						Client: RuntimeApiSubsystemClient + Sync + Send,
					{
						async fn head_supports_parachains(&self, head: &Hash) -> bool {
							// Check that the `ParachainHost` runtime api is at least with version 1 present on chain.
							self.api_version_parachain_host(*head).await.ok().flatten().unwrap_or(0) >= 1
						}
					}

			*/
			activeLeavesUpdate := parachaintypes.ActiveLeavesUpdateSignal{
				Activated: &parachaintypes.ActivatedLeaf{
					Hash:   imported.Header.Hash(),
					Number: uint32(imported.Header.Number),
				},
				Deactivated: []common.Hash{imported.Header.ParentHash},
			}

			o.broadcast(
				Message[any, any]{
					Data:     activeLeavesUpdate,
					Response: nil,
				})

		case finalised := <-o.finalised:
			deactivated := make([]common.Hash, 0)

			for hash, blockNumber := range o.activeLeaves {
				if blockNumber <= uint32(finalised.Header.Number) && hash != finalised.Header.Hash() {
					deactivated = append(deactivated, hash)
					delete(o.activeLeaves, hash)
				}
			}

			o.broadcast(Message[any, any]{
				Data: parachaintypes.BlockFinalizedSignal{
					Hash:        finalised.Header.Hash(),
					BlockNumber: uint32(finalised.Header.Number),
				},
				Response: nil,
			})

			// If there are no leaves being deactivated, we don't need to send an update.
			//
			// Our peers will be informed about our finalized block the next time we
			// activating/deactivating some leaf.
			if len(deactivated) > 0 {
				o.broadcast(
					Message[any, any]{
						Data: parachaintypes.ActiveLeavesUpdateSignal{
							Deactivated: deactivated,
						},
						Response: nil,
					})
			}
		}
	}
}

func (o *Overseer) broadcast(msg Message[any, any]) {
	for _, overseerToSubSystem := range o.subsystems {
		overseerToSubSystem <- msg
	}
}

func (o *Overseer) Stop() error {
	o.cancel()

	o.blockState.FreeImportedBlockNotifierChannel(o.imported)
	o.blockState.FreeFinalisedNotifierChannel(o.finalised)

	// close the errorChan to unblock any listeners on the errChan
	close(o.errChan)

	for _, sub := range o.subsystems {
		close(sub)
	}

	// wait for subsystems to stop
	// TODO: determine reasonable timeout duration for production, currently this is just for testing
	timedOut := waitTimeout(&o.wg, 500*time.Millisecond)
	fmt.Printf("timedOut: %v\n", timedOut)

	return nil
}

func waitTimeout(wg *sync.WaitGroup, timeout time.Duration) (timeouted bool) {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	timeoutTimer := time.NewTimer(timeout)
	select {
	case <-c:
		if !timeoutTimer.Stop() {
			<-timeoutTimer.C
		}
		return false // completed normally
	case <-timeoutTimer.C:
		return true // timed out
	}
}