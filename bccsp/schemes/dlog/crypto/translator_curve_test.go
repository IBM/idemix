/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"testing"

	"github.com/IBM/idemix/bccsp/schemes/dlog/crypto/translator/amcl"
	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// legacyTranslator implements Translator but not CurveTranslator.
type legacyTranslator struct {
	Translator
}

func TestCheckTranslatorCurve(t *testing.T) {
	fp := math.Curves[math.FP256BN_AMCL]
	miracl := math.Curves[math.FP256BN_AMCL_MIRACL]
	bn := math.Curves[math.BN254]
	bls := math.Curves[math.BLS12_381_BBS]

	// matching pairs are accepted
	require.NoError(t, CheckTranslatorCurve(fp, &amcl.Fp256bn{C: fp}))
	require.NoError(t, CheckTranslatorCurve(miracl, &amcl.Fp256bnMiracl{C: miracl}))
	require.NoError(t, CheckTranslatorCurve(bn, &amcl.Gurvy{C: bn}))
	require.NoError(t, CheckTranslatorCurve(bls, &amcl.Gurvy{C: bls}))

	// mismatched pairs are rejected
	err := CheckTranslatorCurve(bls, &amcl.Gurvy{C: bn})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match")
	require.Error(t, CheckTranslatorCurve(miracl, &amcl.Fp256bn{C: fp}))
	require.Error(t, CheckTranslatorCurve(fp, &amcl.Fp256bnMiracl{C: miracl}))
	require.Error(t, CheckTranslatorCurve(bn, &amcl.Fp256bn{C: fp}))

	// a translator not bound to any curve is rejected
	err = CheckTranslatorCurve(bn, &amcl.Gurvy{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not bound to a curve")

	// nil curve
	require.Error(t, CheckTranslatorCurve(nil, &amcl.Gurvy{C: bn}))

	// translators not implementing CurveTranslator are accepted as before
	require.NoError(t, CheckTranslatorCurve(bls, &legacyTranslator{Translator: &amcl.Gurvy{C: bn}}))
	require.NoError(t, CheckTranslatorCurve(bls, nil))
}
