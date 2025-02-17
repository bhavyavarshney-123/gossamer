// Copyright 2024 ChainSafe Systems (ON)
// SPDX-License-Identifier: LGPL-3.0-only

package codec

import (
	"fmt"
	"io"

	"github.com/ChainSafe/gossamer/lib/common"
	"github.com/ChainSafe/gossamer/pkg/scale"
)

const ChildrenCapacity = 16

// MerkleValue is a helper enum to differentiate between inline and hashed nodes
// https://spec.polkadot.network/chap-state#defn-merkle-value
type MerkleValue interface {
	IsHashed() bool
}

type (
	// InlineNode contains bytes of the encoded node data
	InlineNode []byte
	// HashedNode contains a hash used to lookup in db for encoded node data
	HashedNode common.Hash
)

func (InlineNode) IsHashed() bool { return false }
func (HashedNode) IsHashed() bool { return true }

// EncodedValue is a helper enum to differentiate between inline and hashed values
type EncodedValue interface {
	IsHashed() bool
	Write(writer io.Writer) error
}

type (
	// InlineValue contains bytes for the value in this node
	InlineValue []byte
	// HashedValue contains a hash used to lookup in db for real value
	HashedValue common.Hash
)

func (InlineValue) IsHashed() bool { return false }
func (v InlineValue) Write(writer io.Writer) error {
	encoder := scale.NewEncoder(writer)
	err := encoder.Encode(v)
	if err != nil {
		return fmt.Errorf("scale encoding storage value: %w", err)
	}
	return nil
}

func (HashedValue) IsHashed() bool { return true }
func (v HashedValue) Write(writer io.Writer) error {
	if len(v) != common.HashLength {
		panic("invalid hash length")
	}

	_, err := writer.Write(v[:])
	if err != nil {
		return fmt.Errorf("writing hashed storage value: %w", err)
	}
	return nil
}

// EncodedNode is the object representation of a encoded node
type EncodedNode interface {
	GetPartialKey() []byte
	GetValue() EncodedValue
}

type (
	// Empty node
	Empty struct{}
	// Leaf always contains values
	Leaf struct {
		PartialKey []byte
		Value      EncodedValue
	}
	// Branch could has or not has values
	Branch struct {
		PartialKey []byte
		Children   [ChildrenCapacity]MerkleValue
		Value      EncodedValue
	}
)

func (Empty) GetPartialKey() []byte     { return nil }
func (Empty) GetValue() EncodedValue    { return nil }
func (l Leaf) GetPartialKey() []byte    { return l.PartialKey }
func (l Leaf) GetValue() EncodedValue   { return l.Value }
func (b Branch) GetPartialKey() []byte  { return b.PartialKey }
func (b Branch) GetValue() EncodedValue { return b.Value }

// NodeKind is an enum to represent the different types of nodes (Leaf, Branch, etc.)
type NodeKind int

const (
	LeafNode NodeKind = iota
	BranchWithoutValue
	BranchWithValue
	LeafWithHashedValue
	BranchWithHashedValue
)

func EncodeHeader(partialKey []byte, kind NodeKind, writer io.Writer) (err error) {
	partialKeyLength := len(partialKey)
	if partialKeyLength > int(maxPartialKeyLength) {
		panic(fmt.Sprintf("partial key length is too big: %d", partialKeyLength))
	}

	// Merge variant byte and partial key length together
	var nodeVariant variant

	switch kind {
	case LeafNode:
		nodeVariant = leafVariant
	case LeafWithHashedValue:
		nodeVariant = leafWithHashedValueVariant
	case BranchWithoutValue:
		nodeVariant = branchVariant
	case BranchWithValue:
		nodeVariant = branchWithValueVariant
	case BranchWithHashedValue:
		nodeVariant = branchWithHashedValueVariant
	}

	buffer := make([]byte, 1)
	buffer[0] = nodeVariant.bits
	partialKeyLengthMask := nodeVariant.partialKeyLengthHeaderMask()

	if partialKeyLength < int(partialKeyLengthMask) {
		// Partial key length fits in header byte
		buffer[0] |= byte(partialKeyLength)
		_, err = writer.Write(buffer)
		return err
	}

	// Partial key length does not fit in header byte only
	buffer[0] |= partialKeyLengthMask
	partialKeyLength -= int(partialKeyLengthMask)
	_, err = writer.Write(buffer)
	if err != nil {
		return err
	}

	for {
		buffer[0] = 255
		if partialKeyLength < 255 {
			buffer[0] = byte(partialKeyLength)
		}

		_, err = writer.Write(buffer)
		if err != nil {
			return err
		}

		partialKeyLength -= int(buffer[0])

		if buffer[0] < 255 {
			break
		}
	}

	return nil
}
