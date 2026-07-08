/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries_test

import (
	"testing"

	"github.com/IBM/idemix/bccsp/schemes/aries"
	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUser(t *testing.T) {
	issuer := &aries.Issuer{Curve: math.Curves[math.BLS12_381_BBS]}

	attrs := []string{
		"attr1",
		"attr2",
		"attr3",
		"attr4",
	}

	isk, err := issuer.NewKey(attrs)
	require.NoError(t, err)

	ipk := isk.Public()

	rand, err := math.Curves[math.BLS12_381_BBS].Rand()
	require.NoError(t, err)

	user := &aries.User{
		Curve: math.Curves[math.BLS12_381_BBS],
		Rng:   rand,
	}

	sk, err := user.NewKey()
	require.NoError(t, err)

	t.Run("key_roundtrip", func(t *testing.T) {
		sk1, err := user.NewKeyFromBytes(sk.Bytes())
		require.NoError(t, err)
		assert.NotNil(t, sk1)
		assert.Equal(t, sk, sk1)
	})

	nym, r, err := user.MakeNym(sk, ipk)
	require.NoError(t, err)

	nymBytes := nym.Bytes()
	rBytes := r.Bytes()
	bothBytes := []byte{}
	bothBytes = append(bothBytes, rBytes...)
	bothBytes = append(bothBytes, nymBytes...)

	t.Run("public_nym_roundtrip", func(t *testing.T) {
		nym1, err := user.NewPublicNymFromBytes(nymBytes)
		require.NoError(t, err)
		assert.NotNil(t, nym1)
		assert.True(t, nym.Equals(nym1))
	})

	t.Run("nym_roundtrip", func(t *testing.T) {
		nym1, r1, err := user.NewNymFromBytes(bothBytes)
		require.NoError(t, err)
		assert.NotNil(t, nym1)
		assert.True(t, nym.Equals(nym1))
		assert.NotNil(t, r1)
		assert.Equal(t, r, r1)
	})

	t.Run("corrupted_public_nym_bytes", func(t *testing.T) {
		corrupted := make([]byte, len(nymBytes))
		copy(corrupted, nymBytes)
		corrupted[len(corrupted)-1] = 0
		_, err := user.NewPublicNymFromBytes(corrupted)
		assert.EqualError(t, err, "failure [set bytes failed [invalid point: subgroup check failed]]")
	})

	t.Run("corrupted_nym_bytes", func(t *testing.T) {
		corrupted := make([]byte, len(bothBytes))
		copy(corrupted, bothBytes)
		corrupted[len(corrupted)-1] = 0
		_, _, err := user.NewNymFromBytes(corrupted)
		assert.EqualError(t, err, "failure [set bytes failed [invalid point: subgroup check failed]]")
	})

	t.Run("invalid_key_bytes", func(t *testing.T) {
		_, err := user.NewKeyFromBytes([]byte("yän-dər"))
		assert.EqualError(t, err, "invalid length, expected [32], got [9]")
	})

	t.Run("invalid_public_nym_length", func(t *testing.T) {
		_, err := user.NewPublicNymFromBytes([]byte("yän-dər"))
		assert.EqualError(t, err, "invalid length, expected [96], got [9]")
	})

	t.Run("invalid_nym_length", func(t *testing.T) {
		_, _, err := user.NewNymFromBytes([]byte("yän-dər"))
		assert.EqualError(t, err, "invalid length, expected [128], got [9]")
	})
}
