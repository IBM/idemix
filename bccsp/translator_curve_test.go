/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix_test

import (
	"testing"

	idemix "github.com/IBM/idemix/bccsp"
	"github.com/IBM/idemix/bccsp/schemes/dlog/crypto/translator/amcl"
	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRejectsMismatchedTranslator(t *testing.T) {
	bn := math.Curves[math.BN254]
	bls := math.Curves[math.BLS12_381_BBS]
	fp := math.Curves[math.FP256BN_AMCL]

	_, err := idemix.New(NewDummyKeyStore(), bls, &amcl.Gurvy{C: bn}, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid curve/translator pair")

	_, err = idemix.NewAries(NewDummyKeyStore(), bls, &amcl.Gurvy{C: bn}, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid curve/translator pair")

	_, err = idemix.NewAries(NewDummyKeyStore(), bn, &amcl.Fp256bn{C: fp}, true)
	require.Error(t, err)

	// matching pairs are still accepted
	_, err = idemix.New(NewDummyKeyStore(), fp, &amcl.Fp256bn{C: fp}, true)
	require.NoError(t, err)
	_, err = idemix.NewAries(NewDummyKeyStore(), bls, &amcl.Gurvy{C: bls}, true)
	require.NoError(t, err)
}
