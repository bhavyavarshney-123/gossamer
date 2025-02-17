// Copyright 2023 ChainSafe Systems (ON)
// SPDX-License-Identifier: LGPL-3.0-only

package grandpa

import (
	"fmt"
	"math"
	"math/big"
)

type VoteWeight uint64

type VoterWeight uint64

func (vw *VoterWeight) checkedAdd(add VoterWeight) (err error) {
	sum := new(big.Int).SetUint64(uint64(*vw))
	sum.Add(sum, new(big.Int).SetUint64(uint64(add)))
	if sum.Cmp(new(big.Int).SetUint64(uint64(math.MaxUint64))) > 0 {
		return fmt.Errorf("VoterWeight overflow for CheckedAdd")
	}
	*vw = VoterWeight(sum.Uint64())
	return nil
}
