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

	parachaintypes "github.com/ChainSafe/gossamer/dot/parachain/types"
	"github.com/ChainSafe/gossamer/internal/log"
)

var (
	logger = log.NewFromGlobal(log.AddContext("pkg", "parachain-overseer"))
)

type Overseer struct {
	ctx                  context.Context
	cancel               context.CancelFunc
	errChan              chan error // channel for overseer to send errors to service that started it
	SubsystemsToOverseer chan any
	subsystems           map[Subsystem]chan any // map[Subsystem]OverseerToSubSystem channel
	nameToSubsystem      map[parachaintypes.SubSystemName]Subsystem
	wg                   sync.WaitGroup
}

func NewOverseer() *Overseer {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	return &Overseer{
		ctx:                  ctx,
		cancel:               cancel,
		errChan:              make(chan error),
		SubsystemsToOverseer: make(chan any),
		subsystems:           make(map[Subsystem]chan any),
		nameToSubsystem:      make(map[parachaintypes.SubSystemName]Subsystem),
	}
}

// RegisterSubsystem registers a subsystem with the overseer,
// Add OverseerToSubSystem channel to subsystem, which will be passed to subsystem's Run method.
func (o *Overseer) RegisterSubsystem(subsystem Subsystem) chan any {
	OverseerToSubSystem := make(chan any)
	o.subsystems[subsystem] = OverseerToSubSystem
	o.nameToSubsystem[subsystem.Name()] = subsystem

	return OverseerToSubSystem
}

func (o *Overseer) Start() error {
	// start subsystems
	for subsystem, overseerToSubSystem := range o.subsystems {
		o.wg.Add(1)
		go func(sub Subsystem, overseerToSubSystem chan any) {
			err := sub.Run(o.ctx, overseerToSubSystem, o.SubsystemsToOverseer)
			if err != nil {
				logger.Errorf("running subsystem %v failed: %v", sub, err)
			}
			logger.Infof("subsystem %v stopped", sub)
			o.wg.Done()
		}(subsystem, overseerToSubSystem)
	}

	o.wg.Add(1)
	go o.processMessages()

	// TODO: add logic to start listening for Block Imported events and Finalisation events
	return nil
}

func (o *Overseer) processMessages() {
	for {
		select {
		case msg := <-o.SubsystemsToOverseer:
			var subsystem Subsystem

			switch msg.(type) {
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
			logger.Info("overseer stopping")
			return
		}
	}
}

func (o *Overseer) Stop() error {
	o.cancel()

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

// sendActiveLeavesUpdate sends an ActiveLeavesUpdate to the subsystem
func (o *Overseer) sendActiveLeavesUpdate(update ActiveLeavesUpdate, subsystem Subsystem) {
	o.subsystems[subsystem] <- update
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