/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mathlibfindings

import (
	"bytes"
	"testing"

	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/require"
)

// F10: on FP256BN_AMCL, Gt.Exp(0) returns the base instead of 1: the AMCL
// FP12.Pow loop runs from nbits(3e)-2 down to 1 and never executes for e=0,
// returning the input unchanged.
func TestFindingGtExpZero(t *testing.T) {
	forEachCurve(t, func(t *testing.T, c *math.Curve) {
		t.Helper()
		require.True(t, c.GenGt.Exp(c.NewZrFromInt(0)).IsUnity(), "GenGt^0 != 1")

		rng, err := c.Rand()
		require.NoError(t, err)
		g := c.GenGt.Exp(c.NewRandomZr(rng))
		require.True(t, g.Exp(c.NewZrFromInt(0)).IsUnity(), "g^0 != 1")
	})
}

// F11: NewGtFromBytes performs no subgroup (or even cyclotomic) membership
// check: an arbitrary Fp12 element is accepted as a Gt element.
func TestFindingGtFromBytesNoSubgroupCheck(t *testing.T) {
	forEachCurve(t, func(t *testing.T, c *math.Curve) {
		t.Helper()
		raw := bytes.Repeat([]byte{0x01}, len(c.GenGt.Bytes()))

		g, err := c.NewGtFromBytes(raw)
		if err == nil {
			require.False(t, g.Exp(c.GroupOrder).IsUnity(), "sanity: element is in the order-r subgroup")
		}
		require.Error(t, err, "Fp12 element outside the order-r subgroup accepted as Gt")
	})
}
