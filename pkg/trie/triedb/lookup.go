// Copyright 2024 ChainSafe Systems (ON)
// SPDX-License-Identifier: LGPL-3.0-only

package triedb

import (
	"bytes"

	"github.com/ChainSafe/gossamer/lib/common"
	"github.com/ChainSafe/gossamer/pkg/trie/cache"
	"github.com/ChainSafe/gossamer/pkg/trie/db"
	"github.com/ChainSafe/gossamer/pkg/trie/triedb/codec"
)

type TrieLookup struct {
	// db to query from
	db db.DBGetter
	// hash to start at
	hash common.Hash
	// cache to speed up the db lookups
	cache cache.TrieCache
	// Optional recorder for recording trie accesses
	recorder *Recorder
}

func NewTrieLookup(db db.DBGetter, hash common.Hash, cache cache.TrieCache, recorder *Recorder) TrieLookup {
	return TrieLookup{
		db:       db,
		hash:     hash,
		cache:    cache,
		recorder: recorder,
	}
}

func (l *TrieLookup) lookupNode(keyNibbles []byte) (codec.EncodedNode, error) {
	// Start from root node and going downwards
	partialKey := keyNibbles
	hash := l.hash[:]

	// Iterates through non inlined nodes
	for {
		// Get node from DB
		var nodeData []byte
		if l.cache != nil {
			nodeData = l.cache.GetNode(hash)
		}

		if nodeData == nil {
			var err error
			nodeData, err = l.db.Get(hash)
			if err != nil {
				return nil, ErrIncompleteDB
			}

			if l.cache != nil {
				l.cache.SetNode(hash, nodeData)
			}

			l.recordAccess(encodedNodeAccess{hash: common.BytesToHash(hash), encodedNode: nodeData})
		}

	InlinedChildrenIterator:
		for {
			// Decode node
			reader := bytes.NewReader(nodeData)
			decodedNode, err := codec.Decode(reader)
			if err != nil {
				return nil, err
			}

			var nextNode codec.MerkleValue

			switch n := decodedNode.(type) {
			case codec.Empty:
				return nil, nil
			case codec.Leaf:
				// We are in the node we were looking for
				if bytes.Equal(partialKey, n.PartialKey) {
					return n, nil
				}

				l.recordAccess(nonExistingNodeAccess{fullKey: keyNibbles})

				return nil, nil
			case codec.Branch:
				nodePartialKey := n.PartialKey

				// This is unusual but could happen if for some reason one
				// branch has a hashed child node that points to a node that
				// doesn't share the prefix we are expecting
				if !bytes.HasPrefix(partialKey, nodePartialKey) {
					l.recordAccess(nonExistingNodeAccess{fullKey: keyNibbles})
					return nil, nil
				}

				// We are in the node we were looking for
				if bytes.Equal(partialKey, nodePartialKey) {
					if n.Value != nil {
						return n, nil
					}

					l.recordAccess(nonExistingNodeAccess{fullKey: keyNibbles})
					return nil, nil
				}

				// This is not the node we were looking for but it might be in
				// one of its children
				childIdx := int(partialKey[len(nodePartialKey)])
				nextNode = n.Children[childIdx]
				if nextNode == nil {
					l.recordAccess(nonExistingNodeAccess{fullKey: keyNibbles})
					return nil, nil
				}

				// Advance the partial key consuming the part we already checked
				partialKey = partialKey[len(nodePartialKey)+1:]
			}

			// Next node could be inlined or hashed (pointer to a node)
			// https://spec.polkadot.network/chap-state#defn-merkle-value
			switch merkleValue := nextNode.(type) {
			case codec.HashedNode:
				// If it's hashed we set the hash to look for it in next loop
				hash = merkleValue[:]
				break InlinedChildrenIterator
			case codec.InlineNode:
				// If it is inlined we just need to decode it in the next loop
				nodeData = merkleValue
			}
		}
	}
}

func (l *TrieLookup) lookupValue(keyNibbles []byte) (value []byte, err error) {
	if l.cache != nil {
		if value = l.cache.GetValue(keyNibbles); value != nil {
			return value, nil
		}
	}

	node, err := l.lookupNode(keyNibbles)
	if err != nil {
		return nil, err
	}

	// node not found so we return nil
	if node == nil {
		return nil, nil
	}

	if nodeValue := node.GetValue(); nodeValue != nil {
		value, err = l.fetchValue(node.GetPartialKey(), keyNibbles, nodeValue)
		if err != nil {
			return nil, err
		}

		if l.cache != nil {
			l.cache.SetValue(keyNibbles, value)
		}

		return value, nil
	}

	return nil, nil
}

// fetchValue gets the value from the node, if it is inlined we can return it
// directly. But if it is hashed (V1) we have to look up for its value in the DB
func (l *TrieLookup) fetchValue(prefix []byte, fullKey []byte, value codec.EncodedValue) ([]byte, error) {
	switch v := value.(type) {
	case codec.InlineValue:
		l.recordAccess(inlineValueAccess{fullKey: fullKey})
		return v, nil
	case codec.HashedValue:
		prefixedKey := bytes.Join([][]byte{prefix, v[:]}, nil)
		if l.cache != nil {
			if value := l.cache.GetValue(prefixedKey); value != nil {
				return value, nil
			}
		}

		nodeData, err := l.db.Get(prefixedKey)
		if err != nil {
			return nil, ErrIncompleteDB
		}

		if l.cache != nil {
			l.cache.SetValue(prefixedKey, nodeData)
		}

		l.recordAccess(valueAccess{hash: common.Hash(v), fullKey: fullKey, value: nodeData})

		return nodeData, nil
	default:
		panic("unreachable")
	}
}

func (l *TrieLookup) recordAccess(access trieAccess) {
	if l.recorder != nil {
		l.recorder.record(access)
	}
}
