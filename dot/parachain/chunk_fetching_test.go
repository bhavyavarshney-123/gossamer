// Copyright 2023 ChainSafe Systems (ON)
// SPDX-License-Identifier: LGPL-3.0-only

package parachain

import (
	"testing"

	parachaintypes "github.com/ChainSafe/gossamer/dot/parachain/types"
	"github.com/ChainSafe/gossamer/lib/common"
	"github.com/ChainSafe/gossamer/pkg/scale"
	"github.com/stretchr/testify/require"
)

func TestEncodeChunkFetchingRequest(t *testing.T) {
	chunkFetchingRequest := ChunkFetchingRequest{
		CandidateHash: CandidateHash{
			common.MustHexToHash("0x677811d2f3ded2489685468dbdb2e4fa280a249fba9356acceb2e823820e2c19"),
		},
		Index: parachaintypes.ValidatorIndex(8),
	}

	actualEncode, err := chunkFetchingRequest.Encode()
	require.NoError(t, err)

	expextedEncode := common.MustHexToBytes("0x677811d2f3ded2489685468dbdb2e4fa280a249fba9356acceb2e823820e2c1908000000")
	require.Equal(t, expextedEncode, actualEncode)
}

func TestChunkFetchingResponse(t *testing.T) {
	t.Parallel()

	testBytes := common.MustHexToBytes("0x677811d2f3ded2489685468dbdb2e4fa280a249fba9356acceb2e823820e2c19")
	testCases := []struct {
		name        string
		value       scale.VaryingDataTypeValue
		encodeValue []byte
	}{
		{
			name: "chunkResponse",
			value: ChunkResponse{
				Chunk: testBytes,
				Proof: [][]byte{testBytes},
			},
			encodeValue: common.MustHexToBytes("0x0080677811d2f3ded2489685468dbdb2e4fa280a249fba9356acceb2e823820e2c190480677811d2f3ded2489685468dbdb2e4fa280a249fba9356acceb2e823820e2c19"), //nolint:lll
		},
		{
			name:        "NoSuchChunk",
			value:       NoSuchChunk{},
			encodeValue: []byte{1},
		},
	}

	for _, c := range testCases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			t.Run("encode", func(t *testing.T) {
				t.Parallel()

				chunkFetchingResponse := NewChunkFetchingResponse()
				err := chunkFetchingResponse.Set(c.value)
				require.NoError(t, err)

				actualEncode, err := chunkFetchingResponse.Encode()
				require.NoError(t, err)

				require.Equal(t, c.encodeValue, actualEncode)
			})

			t.Run("decode", func(t *testing.T) {
				t.Parallel()

				chunkFetchingResponse := NewChunkFetchingResponse()
				err := chunkFetchingResponse.Decode(c.encodeValue)
				require.NoError(t, err)

				actualData, err := chunkFetchingResponse.Value()
				require.NoError(t, err)

				require.EqualValues(t, c.value, actualData)
			})

		})
	}
}
