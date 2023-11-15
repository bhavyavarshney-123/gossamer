// Copyright 2023 ChainSafe Systems (ON)
// SPDX-License-Identifier: LGPL-3.0-only

package availabilitystore

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	parachaintypes "github.com/ChainSafe/gossamer/dot/parachain/types"
	"github.com/ChainSafe/gossamer/internal/database"
	"github.com/ChainSafe/gossamer/internal/log"
	"github.com/ChainSafe/gossamer/lib/common"
)

var logger = log.NewFromGlobal(log.AddContext("pkg", "parachain-availability-store"))

const (
	avaliableDataPrefix = "available"
	chunkPrefix         = "chunk"
	metaPrefix          = "meta"
	unfinalizedPrefix   = "unfinalized"
	pruneByTimePrefix   = "prune_by_time"
	tombstoneValue      = " "

	// Unavailable blocks are kept for 1 hour.
	KEEP_UNAVAILABLE_FOR = time.Hour

	// Finalized data is kept for 25 hours.
	KEEP_FINALIZED_FOR = time.Hour * 25

	// The pruning interval.
	PRUNING_INTERVAL = time.Minute * 5
)

type BETimestamp uint64

func (b BETimestamp) ToBytes() []byte {
	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes, uint64(b))
	return bytes
}

type SubsystemClock struct {
}

func (SubsystemClock) Now() BETimestamp {
	return BETimestamp(time.Now().Unix())
}

// PruningConfig Struct holding pruning timing configuration.
// The only purpose of this structure is to use different timing
// configurations in production and in testing.
type PruningConfig struct {
	keepUnavailableFor time.Duration
	keepFinalizedFor   time.Duration
	pruningInterval    time.Duration
}

var DefaultPruningConfig = PruningConfig{
	keepUnavailableFor: KEEP_UNAVAILABLE_FOR,
	keepFinalizedFor:   KEEP_FINALIZED_FOR,
	pruningInterval:    PRUNING_INTERVAL,
}

// AvailabilityStoreSubsystem is the struct that holds subsystem data for the availability store
type AvailabilityStoreSubsystem struct {
	SubSystemToOverseer chan<- any
	OverseerToSubSystem <-chan any
	availabilityStore   *AvailabilityStore
	pruningConfig       PruningConfig
	clock               SubsystemClock
	//TODO: metrics       Metrics
}

func NewAvailabilityStoreSubsystem(db database.Database) (*AvailabilityStoreSubsystem, error) {
	av := NewAvailabilityStore(db)

	return &AvailabilityStoreSubsystem{
		availabilityStore: av,
		pruningConfig:     DefaultPruningConfig,
		clock:             SubsystemClock{},
	}, nil
}

// AvailabilityStore is the struct that holds data for the availability store
type AvailabilityStore struct {
	mtx            *sync.Mutex
	availableTable database.Table
	chunkTable     database.Table
	metaTable      database.Table
	//TODO: unfinalizedTable database.Table
	pruneByTimeTable database.Table
}

// NewAvailabilityStore creates a new instance of AvailabilityStore
func NewAvailabilityStore(db database.Database) *AvailabilityStore {
	return &AvailabilityStore{
		mtx:              &sync.Mutex{},
		availableTable:   database.NewTable(db, avaliableDataPrefix),
		chunkTable:       database.NewTable(db, chunkPrefix),
		metaTable:        database.NewTable(db, metaPrefix),
		pruneByTimeTable: database.NewTable(db, pruneByTimePrefix),
	}
}

// loadAvailableData loads available data from the availability store
func (as *AvailabilityStore) loadAvailableData(candidate common.Hash) (*AvailableData, error) {
	resultBytes, err := as.availableTable.Get(candidate[:])
	if err != nil {
		return nil, fmt.Errorf("getting candidate %v from available table: %w", candidate, err)
	}
	result := AvailableData{}
	err = json.Unmarshal(resultBytes, &result)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling available data: %w", err)
	}
	return &result, nil
}

// loadMetaData loads metadata from the availability store
func (as *AvailabilityStore) loadMetaData(candidate common.Hash) (*CandidateMeta, error) {
	resultBytes, err := as.metaTable.Get(candidate[:])
	if err != nil {
		return nil, fmt.Errorf("getting candidate %v from available table: %w", candidate, err)
	}
	result := CandidateMeta{}
	err = json.Unmarshal(resultBytes, &result)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling candidate meta: %w", err)
	}
	return &result, nil
}

func (as *AvailabilityStore) tryTransaction(transactionFn func(availableBatch, chunkBatch,
	metaBatch, pruneTime database.Batch) error) error {
	as.mtx.Lock()
	defer as.mtx.Unlock()

	batchA := as.availableTable.NewBatch()
	batchB := as.chunkTable.NewBatch()
	batchC := as.metaTable.NewBatch()
	batchD := as.pruneByTimeTable.NewBatch()

	err := transactionFn(batchA, batchB, batchC, batchD)
	if err != nil {
		batchA.Reset()
		batchB.Reset()
		batchC.Reset()
		batchD.Reset()
	} else {
		err := batchA.Flush()
		if err != nil {
			return err
		}
		err = batchB.Flush()
		// TODO: determine how to revert batchA if batchB fails
		if err != nil {
			return err
		}
		err = batchC.Flush()
		// TODO: determine how to revert batchA and batchB if batchC fails
		if err != nil {
			return err
		}
		// TODO: determine how to revert batchA, batchB, and batchC if batchD fails
		err = batchD.Flush()
		if err != nil {
			return err
		}
	}
	return nil
}

// storeMetaData stores metadata in the availability stor
func (as *AvailabilityStore) storeMetaData(candidate common.Hash, meta CandidateMeta) error {
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshalling meta for candidate: %w", err)
	}
	err = as.metaTable.Put(candidate[:], metaBytes)
	if err != nil {
		return fmt.Errorf("storing metadata for candidate %v: %w", candidate, err)
	}
	return nil
}

// loadChunk loads a chunk from the availability store
func (as *AvailabilityStore) loadChunk(candidate common.Hash, validatorIndex uint32) (*ErasureChunk, error) {
	resultBytes, err := as.chunkTable.Get(append(candidate[:], uint32ToBytes(validatorIndex)...))
	if err != nil {
		return nil, fmt.Errorf("getting candidate %v, index %d from chunk table: %w", candidate, validatorIndex, err)
	}
	result := ErasureChunk{}
	err = json.Unmarshal(resultBytes, &result)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling chunk: %w", err)
	}
	return &result, nil
}

// storeChunk stores a chunk in the availability store
func (as *AvailabilityStore) storeChunk(candidate common.Hash, chunk ErasureChunk) error {
	meta, err := as.loadMetaData(candidate)
	if err != nil {

		if errors.Is(err, database.ErrNotFound) {
			// TODO: were creating metadata here, but we should be doing it in the parachain block import?
			// TODO: also we need to determine how many chunks we need to store
			meta = &CandidateMeta{
				ChunksStored: make([]bool, 16),
			}
		} else {
			return fmt.Errorf("load metadata: %w", err)
		}
	}

	txFunc := func(availableBatch, chunkBatch, metaBatch, pruneTimeBatch database.Batch) error {
		if meta.ChunksStored[chunk.Index] {
			logger.Debugf("Chunk %d already stored", chunk.Index)
			return nil // already stored
		} else {
			dataBytes, err := json.Marshal(chunk)
			if err != nil {
				return fmt.Errorf("marshalling chunk: %w", err)
			}
			err = chunkBatch.Put(append(candidate[:], uint32ToBytes(chunk.Index)...), dataBytes)
			if err != nil {
				return fmt.Errorf("storing chunk for candidate %v, index %d: %w", candidate, chunk.Index, err)
			}

			meta.ChunksStored[chunk.Index] = true
			err = as.storeMetaData(candidate, *meta)
			if err != nil {
				return fmt.Errorf("storing metadata for candidate %v: %w", candidate, err)
			}
		}
		return nil
	}
	err = as.tryTransaction(txFunc)
	if err != nil {
		return fmt.Errorf("transaction: %w", err)
	}
	logger.Debugf("stored chuck %d for %v", chunk.Index, candidate)
	return nil
}

func writePruningKey(pruneTimeBatch database.Batch, pruneAt BETimestamp, candidate common.Hash) error {
	pruneKey := append([]byte(pruneByTimePrefix), pruneAt.ToBytes()...)
	pruneKey = append(pruneKey, candidate[:]...)
	return pruneTimeBatch.Put(pruneKey, []byte(tombstoneValue))
}

// storeAvailableData stores available data in the availability store
func (as *AvailabilityStore) storeAvailableData(subsystem *AvailabilityStoreSubsystem, candidate common.Hash,
	data AvailableData) error {
	// TODO check if data is already stored

	dataBytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshalling available data: %w", err)
	}
	txFunc := func(availableBatch, chunkBatch, metaBatch, pruneTimeBatch database.Batch) error {
		pruneAt := subsystem.clock.Now() + BETimestamp(subsystem.pruningConfig.keepUnavailableFor.Seconds())
		err := writePruningKey(pruneTimeBatch, pruneAt, candidate)
		if err != nil {
			return err
		}
		err = availableBatch.Put(candidate[:], dataBytes)
		if err != nil {
			return err
		}
		return nil
	}
	return as.tryTransaction(txFunc)
}

func uint32ToBytes(value uint32) []byte {
	result := make([]byte, 4)
	binary.LittleEndian.PutUint32(result, value)
	return result
}

// Run runs the availability store subsystem
func (av *AvailabilityStoreSubsystem) Run(ctx context.Context, OverseerToSubsystem chan any,
	SubsystemToOverseer chan any) error {
	av.processMessages()
	return nil
}

// Name returns the name of the availability store subsystem
func (*AvailabilityStoreSubsystem) Name() parachaintypes.SubSystemName {
	return parachaintypes.AvailabilityStore
}

func (av *AvailabilityStoreSubsystem) processMessages() {
	for msg := range av.OverseerToSubSystem {
		logger.Debugf("received message %v", msg)
		switch msg := msg.(type) {
		case QueryAvailableData:
			err := av.handleQueryAvailableData(msg)
			if err != nil {
				logger.Errorf("failed to handle available data: %w", err)
			}
		case QueryDataAvailability:
			err := av.handleQueryDataAvailability(msg)
			if err != nil {
				logger.Errorf("failed to handle query data availability: %w", err)
			}
		case QueryChunk:
			err := av.handleQueryChunk(msg)
			if err != nil {
				logger.Errorf("failed to handle query chunk: %w", err)
			}
		case QueryChunkSize:
			err := av.handleQueryChunkSize(msg)
			if err != nil {
				logger.Errorf("failed to handle query chunk size: %w", err)
			}
		case QueryAllChunks:
			err := av.handleQueryAllChunks(msg)
			if err != nil {
				logger.Errorf("failed to handle query all chunks: %w", err)
			}
		case QueryChunkAvailability:
			err := av.handleQueryChunkAvailability(msg)
			if err != nil {
				logger.Errorf("failed to handle query chunk availability: %w", err)
			}
		case StoreChunk:
			err := av.handleStoreChunk(msg)
			if err != nil {
				logger.Errorf("failed to handle store chunk: %w", err)
			}
		case StoreAvailableData:
			err := av.handleStoreAvailableData(msg)
			if err != nil {
				logger.Errorf("failed to handle store available data: %w", err)
			}
		}
	}
}

func (av *AvailabilityStoreSubsystem) handleQueryAvailableData(msg QueryAvailableData) error {
	result, err := av.availabilityStore.loadAvailableData(msg.CandidateHash)
	if err != nil {
		msg.Sender <- AvailableData{}
		return fmt.Errorf("load available data: %w", err)
	}
	msg.Sender <- *result
	return nil
}

func (av *AvailabilityStoreSubsystem) handleQueryDataAvailability(msg QueryDataAvailability) error {
	_, err := av.availabilityStore.loadMetaData(msg.CandidateHash)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			msg.Sender <- false
			return nil
		} else {
			return fmt.Errorf("load metadata: %w", err)
		}
	}
	msg.Sender <- err == nil
	return nil
}

func (av *AvailabilityStoreSubsystem) handleQueryChunk(msg QueryChunk) error {
	result, err := av.availabilityStore.loadChunk(msg.CandidateHash, msg.ValidatorIndex)
	if err != nil {
		msg.Sender <- ErasureChunk{}
		return fmt.Errorf("load chunk: %w", err)
	}
	msg.Sender <- *result
	return nil
}

func (av *AvailabilityStoreSubsystem) handleQueryChunkSize(msg QueryChunkSize) error {
	meta, err := av.availabilityStore.loadMetaData(msg.CandidateHash)
	if err != nil {
		return fmt.Errorf("load metadata: %w", err)
	}
	var validatorIndex uint32
	for i, v := range meta.ChunksStored {
		if v {
			validatorIndex = uint32(i)
			break
		}
	}

	chunk, err := av.availabilityStore.loadChunk(msg.CandidateHash, validatorIndex)
	if err != nil {
		return fmt.Errorf("load chunk: %w", err)
	}
	msg.Sender <- uint32(len(chunk.Chunk))
	return nil
}

func (av *AvailabilityStoreSubsystem) handleQueryAllChunks(msg QueryAllChunks) error {
	meta, err := av.availabilityStore.loadMetaData(msg.CandidateHash)
	if err != nil {
		msg.Sender <- []ErasureChunk{}
		return fmt.Errorf("load metadata: %w", err)
	}
	chunks := []ErasureChunk{}
	for i, v := range meta.ChunksStored {
		if v {
			chunk, err := av.availabilityStore.loadChunk(msg.CandidateHash, uint32(i))
			if err != nil {
				logger.Errorf("load chunk: %w", err)
			}
			chunks = append(chunks, *chunk)
		} else {
			logger.Warnf("chunk %d not stored for %v", i, msg.CandidateHash)
		}
	}
	msg.Sender <- chunks
	return nil
}

func (av *AvailabilityStoreSubsystem) handleQueryChunkAvailability(msg QueryChunkAvailability) error {
	meta, err := av.availabilityStore.loadMetaData(msg.CandidateHash)
	if err != nil {
		msg.Sender <- false
		return fmt.Errorf("load metadata: %w", err)
	}
	msg.Sender <- meta.ChunksStored[msg.ValidatorIndex]
	return nil
}

func (av *AvailabilityStoreSubsystem) handleStoreChunk(msg StoreChunk) error {
	err := av.availabilityStore.storeChunk(msg.CandidateHash, msg.Chunk)
	if err != nil {
		msg.Sender <- err
		return fmt.Errorf("store chunk: %w", err)
	}
	msg.Sender <- nil
	return nil
}

func (av *AvailabilityStoreSubsystem) handleStoreAvailableData(msg StoreAvailableData) error {
	err := av.availabilityStore.storeAvailableData(av, msg.CandidateHash, msg.AvailableData)
	if err != nil {
		msg.Sender <- err
		return fmt.Errorf("store available data: %w", err)
	}
	msg.Sender <- err // TODO: determine how to replicate Rust's Result type
	return nil
}
