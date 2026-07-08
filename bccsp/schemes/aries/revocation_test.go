/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package aries_test

import (
	"testing"

	"github.com/IBM/idemix/bccsp/schemes/aries"
	idemix "github.com/IBM/idemix/bccsp/types"
	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRevocation(t *testing.T) {
	curve := math.Curves[math.BLS12_381_BBS]
	rand, err := curve.Rand()
	require.NoError(t, err)

	rev := &aries.RevocationAuthority{
		Rng:   rand,
		Curve: curve,
	}

	revocationKey, err := rev.NewKey()
	require.NoError(t, err)

	epoch := 0
	cri, err := rev.Sign(revocationKey, [][]byte{}, epoch, idemix.AlgNoRevocation)
	require.NoError(t, err)

	t.Run("sign_and_verify_happy_path", func(t *testing.T) {
		err := rev.Verify(&revocationKey.PublicKey, cri, epoch, idemix.AlgNoRevocation)
		assert.NoError(t, err)
	})

	t.Run("wrong_epoch_fails", func(t *testing.T) {
		err := rev.Verify(&revocationKey.PublicKey, cri, epoch+1, idemix.AlgNoRevocation)
		assert.Error(t, err)
	})

	t.Run("key_roundtrip", func(t *testing.T) {
		bytes := revocationKey.D.Bytes()
		restoredKey, err := rev.NewKeyFromBytes(bytes)
		require.NoError(t, err)

		err = rev.Verify(&restoredKey.PublicKey, cri, epoch, idemix.AlgNoRevocation)
		assert.NoError(t, err)
	})
}
