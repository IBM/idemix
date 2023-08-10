/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package aries_test

import (
	"testing"

	idemix "github.com/IBM/idemix/bccsp/types"
	"github.com/IBM/idemix/bccsp/schemes/aries"
	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRevocation(t *testing.T) {
	curve := math.Curves[math.BLS12_381_BBS]
	rand, err := curve.Rand()
	assert.NoError(t, err)

	rev := &aries.RevocationAuthority{
		Rng:   rand,
		Curve: curve,
	}

	// Generate a revocation key pair
	revocationKey, err := rev.NewKey()
	require.NoError(t, err)

	// Create CRI that contains no revocation mechanism
	epoch := 0
	cri, err := rev.Sign(revocationKey, [][]byte{}, epoch, idemix.AlgNoRevocation)
	require.NoError(t, err)
	err = rev.Verify(&revocationKey.PublicKey, cri, epoch, idemix.AlgNoRevocation)
	require.NoError(t, err)

	// make sure that epoch pk is not valid in future epoch
	err = rev.Verify(&revocationKey.PublicKey, cri, epoch+1, idemix.AlgNoRevocation)
	require.Error(t, err)

	bytes := revocationKey.D.Bytes()
	revocationKey, err = rev.NewKeyFromBytes(bytes)
	require.NoError(t, err)

	err = rev.Verify(&revocationKey.PublicKey, cri, epoch, idemix.AlgNoRevocation)
	require.NoError(t, err)

}
