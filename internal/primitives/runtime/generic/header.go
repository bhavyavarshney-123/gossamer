// Copyright 2024 ChainSafe Systems (ON)
// SPDX-License-Identifier: LGPL-3.0-only

package generic

import (
	"io"

	"github.com/ChainSafe/gossamer/internal/primitives/core/hash"
	"github.com/ChainSafe/gossamer/internal/primitives/runtime"
	"github.com/ChainSafe/gossamer/pkg/scale"
)

// Abstraction over a block header for a substrate chain.
type Header[N runtime.Number, H runtime.Hash, Hasher runtime.Hasher[H]] struct {
	// The parent hash.
	parentHash H
	// The block number.
	number N
	// The state trie merkle root
	stateRoot H
	// The merkle root of the extrinsics.
	extrinsicsRoot H
	// A chain-specific digest of data useful for light clients or referencing auxiliary data.
	digest runtime.Digest
}

// Returns a reference to the header number.
func (h Header[N, H, Hasher]) Number() N {
	return h.number
}

// Returns a reference to the parent hash.
func (h Header[N, H, Hasher]) ParentHash() H {
	return h.parentHash
}

func (h Header[N, H, Hasher]) MarshalSCALE() ([]byte, error) {
	type helper struct {
		ParentHash H
		// uses compact encoding so we need to cast to uint
		// https://github.com/paritytech/substrate/blob/e374a33fe1d99d59eb24a08981090bdb4503e81b/primitives/runtime/src/generic/header.rs#L47
		Number         uint
		StateRoot      H
		ExtrinsicsRoot H
		Digest         runtime.Digest
	}
	help := helper{h.parentHash, uint(h.number), h.stateRoot, h.extrinsicsRoot, h.digest}
	return scale.Marshal(help)
}

func (h *Header[N, H, Hasher]) UnmarshalSCALE(r io.Reader) error {
	type helper struct {
		ParentHash H
		// uses compact encoding so we need to cast to uint
		// https://github.com/paritytech/substrate/blob/e374a33fe1d99d59eb24a08981090bdb4503e81b/primitives/runtime/src/generic/header.rs#L47
		Number         uint
		StateRoot      H
		ExtrinsicsRoot H
		Digest         runtime.Digest
	}

	var header helper
	decoder := scale.NewDecoder(r)
	err := decoder.Decode(&header)
	if err != nil {
		return err
	}
	h.parentHash = header.ParentHash
	h.number = N(header.Number)
	h.stateRoot = header.StateRoot
	h.extrinsicsRoot = header.ExtrinsicsRoot
	h.digest = header.Digest
	return nil
}

// Returns the hash of the header.
func (h Header[N, H, Hasher]) Hash() H {
	hasher := *new(Hasher)
	return hasher.HashOf(h)
}

func NewHeader[N runtime.Number, H runtime.Hash, Hasher runtime.Hasher[H]](
	number N,
	extrinsicsRoot H,
	stateRoot H,
	parentHash H,
	digest runtime.Digest,
) Header[N, H, Hasher] {
	return Header[N, H, Hasher]{
		number:         number,
		extrinsicsRoot: extrinsicsRoot,
		stateRoot:      stateRoot,
		parentHash:     parentHash,
		digest:         digest,
	}
}

var _ runtime.Header[uint64, hash.H256] = &Header[uint64, hash.H256, runtime.BlakeTwo256]{}