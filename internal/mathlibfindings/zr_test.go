/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mathlibfindings

import (
	"bytes"
	"math/big"
	"testing"

	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/require"
)

// F5: on the common.BaseZr drivers (FP256BN_AMCL, BN254, FP256BN_AMCL_MIRACL,
// BLS12_377_GURVY) Zr values are stored unreduced, and Zr.Equals / Zr.IsZero /
// Zr.IsOne compare the raw big.Int. Scalars that are equal modulo the group
// order (and behave identically in G1.Mul etc.) compare as different. The
// BLS12-381 drivers reduce on input and behave correctly, so the same bytes
// give different answers depending on the curve.
func TestFindingZrEqualsNotModular(t *testing.T) {
	forEachCurve(t, func(t *testing.T, c *math.Curve) {
		t.Helper()
		q := order(c)
		zero := c.NewZrFromInt(0)
		one := c.NewZrFromInt(1)

		zq := c.NewZrFromBytes(enc32(q))
		require.True(t, c.GenG1.Mul(zq).IsInfinity(), "sanity: q acts as 0")
		require.True(t, zq.IsZero(), "Zr decoded from bytes(q) is not IsZero()")
		require.True(t, zq.Equals(zero), "Zr decoded from bytes(q) is not Equal to 0")

		zq1 := c.NewZrFromBytes(enc32(new(big.Int).Add(q, big.NewInt(1))))
		require.True(t, c.GenG1.Mul(zq1).Equals(c.GenG1), "sanity: q+1 acts as 1")
		require.True(t, zq1.IsOne(), "Zr decoded from bytes(q+1) is not IsOne()")
		require.True(t, zq1.Equals(one), "Zr decoded from bytes(q+1) is not Equal to 1")

		minus1 := c.NewZrFromInt(-1)
		qm1 := c.NewZrFromBytes(enc32(new(big.Int).Sub(q, big.NewInt(1))))
		require.True(t, minus1.Equals(qm1), "Zr(-1) is not Equal to Zr(q-1)")
	})
}

// F6: Zr.Bytes() is not canonical on the BaseZr drivers for the value q:
// BaseZr.Bytes only reduces when value > modulus (off-by-one, should be >=),
// so a Zr equal to q serialises as bytes(q) instead of 32 zero bytes.
func TestFindingZrBytesOfOrderNotReduced(t *testing.T) {
	forEachCurve(t, func(t *testing.T, c *math.Curve) {
		t.Helper()
		z := c.NewZrFromBigInt(order(c))
		require.Equal(t, make([]byte, c.ScalarByteSize), z.Bytes(), "Bytes() of q is not the canonical encoding of 0")
	})
}

// F7: NewZrFromBytes has no error path and accepts any byte string: values >= q
// and inputs of any length (shorter or longer than ScalarByteSize) are accepted
// and silently interpreted. Distinct byte strings therefore decode to the same
// scalar (malleability of every serialized Zr: proof responses, credential E/S,
// BBS+ e/s, ...). The safe behaviour asserted here is "decoding is canonical":
// re-encoding a decoded scalar yields the input bytes. The fix adds
// Curve.NewZrFromBytesCanonical, which rejects every such encoding.
func TestFindingZrFromBytesNonCanonical(t *testing.T) {
	forEachCurve(t, func(t *testing.T, c *math.Curve) {
		t.Helper()
		q := order(c)
		inputs := map[string][]byte{
			"q+1 (32 bytes, >= order)":    enc32(new(big.Int).Add(q, big.NewInt(1))),
			"1 left-padded to 33 bytes":   append([]byte{0x00}, enc32(big.NewInt(1))...),
			"1 as a single byte":          {0x01},
			"empty slice":                 {},
			"64 bytes (2*ScalarByteSize)": bytes.Repeat([]byte{0xff}, 64),
		}
		// NewZrFromBytes keeps reducing its input for compatibility; untrusted scalars must go
		// through NewZrFromBytesCanonical, which rejects every non-canonical encoding.
		for name, in := range inputs {
			_, err := c.NewZrFromBytesCanonical(in)
			require.Error(t, err, "non-canonical scalar encoding accepted: %s", name)
		}

		one := enc32(big.NewInt(1))
		z, err := c.NewZrFromBytesCanonical(one)
		require.NoError(t, err)
		require.Equal(t, one, z.Bytes())
	})
}

// F8: Zr.Clone on the BaseZr drivers copies only the absolute value
// (big.Int.Bytes() drops the sign), so cloning a negative scalar (e.g. after
// Neg(), or NewZrFromInt(-x)) yields its opposite.
func TestFindingZrCloneDropsSign(t *testing.T) {
	forEachCurve(t, func(t *testing.T, c *math.Curve) {
		t.Helper()
		z := c.NewZrFromInt(5)
		z.Neg()

		w := c.NewZrFromInt(0)
		w.Clone(z)

		require.True(t, c.GenG1.Mul(w).Equals(c.GenG1.Mul(z)), "Clone(-5) does not act as -5")
	})
}

// F9: NewZrFromBigInt on the BaseZr drivers copies the big.Int struct by value
// (shallow copy), so the returned Zr aliases the caller's limb array; later
// mutation of the caller's big.Int silently changes the scalar.
func TestFindingZrFromBigIntAliases(t *testing.T) {
	forEachCurve(t, func(t *testing.T, c *math.Curve) {
		t.Helper()
		i := new(big.Int).Lsh(big.NewInt(1), 200)
		z := c.NewZrFromBigInt(i)
		before := z.Bytes()

		i.SetUint64(7) // reuses i's backing array

		require.Equal(t, before, z.Bytes(), "Zr changed after mutating the big.Int it was created from")
	})
}
