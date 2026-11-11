/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mathlibfindings

import (
	"encoding/hex"
	"testing"

	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/require"
)

// F1: on the AMCL drivers (FP256BN_AMCL, FP256BN_AMCL_MIRACL) a G1 encoding that
// is NOT on the curve is silently decoded to the point at infinity instead of
// returning an error.
func TestFindingG1OffCurveDecodesToInfinity(t *testing.T) {
	forEachCurve(t, func(t *testing.T, c *math.Curve) {
		t.Helper()
		b := c.GenG1.Bytes()
		b[len(b)-1] ^= 0x01 // flip a bit of Y: (x, y') is no longer on the curve

		p, err := c.NewG1FromBytes(b)
		require.Error(t, err, "off-curve G1 point accepted (decoded as infinity=%v)", p != nil && p.IsInfinity())
	})
}

// F1 (variant): an encoding with an invalid prefix byte (0x00 instead of
// 0x02/0x03/0x04) is accepted by the AMCL drivers and decoded to infinity.
func TestFindingG1InvalidPrefixDecodesToInfinity(t *testing.T) {
	for _, id := range []math.CurveID{math.FP256BN_AMCL, math.FP256BN_AMCL_MIRACL} {
		c := math.Curves[id]
		t.Run(math.CurveIDToString(id), func(t *testing.T) {
			b := c.GenG1.Bytes()
			b[0] = 0x00

			p, err := c.NewG1FromBytes(b)
			require.Error(t, err, "G1 encoding with invalid prefix accepted (infinity=%v)", p != nil && p.IsInfinity())
		})
	}
}

// F2: the AMCL G2 decoders perform only an on-curve check, no subgroup check.
// The point below has x = 1 + 0*i on the FP256BN sextic twist; it lies on the
// twist but is not in the order-r subgroup G2 ([r]P != O).
var (
	// FP256BN_AMCL G2 layout: Xa||Xb||Ya||Yb (4*32 bytes).
	fp256bnTwistPointNotInG2 = "0000000000000000000000000000000000000000000000000000000000000001" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"c8931067e59cbf08d406b44ddde32960f67bcad8fe69bc5e469e9ba74ccc1225" +
		"a646cec84f20954d589dba3331ab71ba4321d1663c8aea6da59fb69d261559ca"
	// FP256BN_AMCL_MIRACL G2 layout: 0x04||Xb||Xa||Yb||Ya.
	fp256bnMiraclTwistPointNotInG2 = "04" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000001" +
		"59b93137b0dc5b7fee48382bbcc632e4c9ba9494d60d20152d89773e88bdd649" +
		"376cef981a6031c472df3e11108e7b3e16609b22142e4e248c8a923462071dee"
)

func TestFindingG2NoSubgroupCheck(t *testing.T) {
	cases := map[math.CurveID]string{
		math.FP256BN_AMCL:        fp256bnTwistPointNotInG2,
		math.FP256BN_AMCL_MIRACL: fp256bnMiraclTwistPointNotInG2,
	}
	for id, h := range cases {
		c := math.Curves[id]
		raw, err := hex.DecodeString(h)
		require.NoError(t, err)
		t.Run(math.CurveIDToString(id), func(t *testing.T) {
			p, err := c.NewG2FromBytes(raw)
			if err == nil {
				// Sanity: document that the accepted point really is outside G2.
				require.False(t, p.Equals(c.NewG2()), "decoded to identity")
				require.False(t, p.Mul(c.GroupOrder).Equals(c.NewG2()), "[r]P == O, point is in G2")
			}
			require.Error(t, err, "point on the twist but outside the order-r subgroup was accepted as a G2 element")

			_, err = c.NewG2FromCompressed(raw)
			require.Error(t, err, "point outside G2 accepted by NewG2FromCompressed")
		})
	}
}

// F3: deserializers accept inputs of the wrong length. Trailing bytes are
// silently ignored (multiple byte strings decode to the same point) and
// compressed/uncompressed formats are accepted interchangeably.
func TestFindingPointWrongLengthAccepted(t *testing.T) {
	forEachCurve(t, func(t *testing.T, c *math.Curve) {
		t.Helper()
		_, err := c.NewG1FromBytes(append(c.GenG1.Bytes(), 0x01))
		require.Error(t, err, "NewG1FromBytes accepted %d bytes (expected %d)", c.G1ByteSize+1, c.G1ByteSize)

		_, err = c.NewG1FromCompressed(append(c.GenG1.Compressed(), 0x01))
		require.Error(t, err, "NewG1FromCompressed accepted %d bytes (expected %d)", c.CompressedG1ByteSize+1, c.CompressedG1ByteSize)

		_, err = c.NewG2FromBytes(append(c.GenG2.Bytes(), 0x01))
		require.Error(t, err, "NewG2FromBytes accepted %d bytes (expected %d)", c.G2ByteSize+1, c.G2ByteSize)

		_, err = c.NewG2FromCompressed(append(c.GenG2.Compressed(), 0x01))
		require.Error(t, err, "NewG2FromCompressed accepted %d bytes (expected %d)", c.CompressedG2ByteSize+1, c.CompressedG2ByteSize)

		if c.G1ByteSize != c.CompressedG1ByteSize {
			_, err = c.NewG1FromBytes(c.GenG1.Compressed())
			require.Error(t, err, "NewG1FromBytes accepted a compressed encoding")
			_, err = c.NewG1FromCompressed(c.GenG1.Bytes())
			require.Error(t, err, "NewG1FromCompressed accepted an uncompressed encoding")
		}
	})
}

// F4: G1.String() panics (index out of range) on the point at infinity, on
// every driver: the regexp used to format the point does not match "O" /
// "infinity".
func TestFindingG1StringPanicsOnInfinity(t *testing.T) {
	forEachCurve(t, func(t *testing.T, c *math.Curve) {
		t.Helper()
		require.NotPanics(t, func() { _ = c.NewG1().String() })
	})
}
