// Copyright 2021 ChainSafe Systems (ON)
// SPDX-License-Identifier: LGPL-3.0-only

package transaction

import (
	"testing"

	"github.com/ChainSafe/gossamer/pkg/scale"
	"github.com/stretchr/testify/require"
)

func TestValidTransaction_Encode(t *testing.T) {
	validity := &Validity{
		Priority:  0x3e8,
		Requires:  [][]byte{{0xb5, 0x47, 0xb1, 0x90, 0x37, 0x10, 0x7e, 0x1f, 0x79, 0x4c, 0xa8, 0x69, 0x0, 0xa1, 0xb5, 0x98}},
		Provides:  [][]byte{{0xe4, 0x80, 0x7d, 0x1b, 0x67, 0x49, 0x37, 0xbf, 0xc7, 0x89, 0xbb, 0xdd, 0x88, 0x6a, 0xdd, 0xd6}},
		Longevity: 0x40,
		Propagate: true,
	}

	extrinsic := []byte("nootwashere")

	vt := NewValidTransaction(extrinsic, validity)
	enc, err := scale.Marshal(vt)
	require.NoError(t, err)

	if len(enc) == 0 {
		t.Fatal("Fail: Encode returned empty slice")
	}
}
