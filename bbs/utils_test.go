/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_pokPayload(t *testing.T) {
	payload := NewPoKPayload(4, []int{0, 2})
	require.Equal(t, 3, payload.LenInBytes())

	bytes, err := payload.ToBytes()
	require.NoError(t, err)
	require.Len(t, bytes, 3)

	payloadParsed, err := ParsePoKPayload(bytes)
	require.NoError(t, err)
	require.Equal(t, payload, payloadParsed)

	payloadParsed, err = ParsePoKPayload([]byte{})
	require.Error(t, err)
	require.Nil(t, payloadParsed)
}

func Test_pokPayloadFail(t *testing.T) {
	payload := NewPoKPayload(1, []int{0, 2, 4, 5, 9})
	require.Equal(t, 3, payload.LenInBytes())

	_, err := payload.ToBytes()
	require.EqualError(t, err, "invalid size of PoK payload")

	bytes := []byte{9, 0}
	payloadParsed, err := ParsePoKPayload(bytes)
	require.EqualError(t, err, "invalid size of PoK payload")
	require.Nil(t, payloadParsed)
}
