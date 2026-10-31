/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package amcl

import (
	"testing"

	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type translator interface {
	G1ToProto(*math.G1) *ECP
	G1FromProto(*ECP) (*math.G1, error)
	G1FromRawBytes([]byte) (*math.G1, error)
	G2ToProto(*math.G2) *ECP2
	G2FromProto(*ECP2) (*math.G2, error)
	Curve() *math.Curve
}

func amclTranslators() map[string]translator {
	return map[string]translator{
		"FP256BN_AMCL":        &Fp256bn{C: math.Curves[math.FP256BN_AMCL]},
		"FP256BN_AMCL_MIRACL": &Fp256bnMiracl{C: math.Curves[math.FP256BN_AMCL_MIRACL]},
	}
}

func gurvyTranslators() map[string]translator {
	res := map[string]translator{}
	for name, id := range map[string]math.CurveID{
		"BN254":               math.BN254,
		"BLS12_377_GURVY":     math.BLS12_377_GURVY,
		"BLS12_381":           math.BLS12_381,
		"BLS12_381_GURVY":     math.BLS12_381_GURVY,
		"BLS12_381_BBS":       math.BLS12_381_BBS,
		"BLS12_381_BBS_GURVY": math.BLS12_381_BBS_GURVY,
	} {
		res[name] = &Gurvy{C: math.Curves[id]}
	}

	return res
}

func cloneECP(e *ECP) *ECP {
	return &ECP{X: append([]byte{}, e.X...), Y: append([]byte{}, e.Y...)}
}

func cloneECP2(e *ECP2) *ECP2 {
	return &ECP2{
		Xa: append([]byte{}, e.Xa...),
		Xb: append([]byte{}, e.Xb...),
		Ya: append([]byte{}, e.Ya...),
		Yb: append([]byte{}, e.Yb...),
	}
}

func TestTranslatorCurveAccessor(t *testing.T) {
	for name, tr := range amclTranslators() {
		assert.Equal(t, name, curveName(tr.Curve().ID()))
	}
	for name, tr := range gurvyTranslators() {
		assert.Equal(t, name, curveName(tr.Curve().ID()))
	}

	assert.Nil(t, (*Fp256bn)(nil).Curve())
	assert.Nil(t, (*Fp256bnMiracl)(nil).Curve())
	assert.Nil(t, (*Gurvy)(nil).Curve())
}

func curveName(id math.CurveID) string {
	return map[math.CurveID]string{
		math.FP256BN_AMCL:        "FP256BN_AMCL",
		math.FP256BN_AMCL_MIRACL: "FP256BN_AMCL_MIRACL",
		math.BN254:               "BN254",
		math.BLS12_377_GURVY:     "BLS12_377_GURVY",
		math.BLS12_381:           "BLS12_381",
		math.BLS12_381_GURVY:     "BLS12_381_GURVY",
		math.BLS12_381_BBS:       "BLS12_381_BBS",
		math.BLS12_381_BBS_GURVY: "BLS12_381_BBS_GURVY",
	}[id]
}

// The AMCL decoder maps invalid encodings to the identity without an error:
// the translators must turn that into an error.
func TestAmclTranslatorRejectsInvalidPoints(t *testing.T) {
	bn254 := math.Curves[math.BN254]
	foreign := bn254.GenG1.Mul(bn254.NewZrFromInt(5)).Bytes()

	for name, tr := range amclTranslators() {
		t.Run(name, func(t *testing.T) {
			c := tr.Curve()
			rng, err := c.Rand()
			require.NoError(t, err)

			// honest encodings still round-trip
			g1 := c.GenG1.Mul(c.NewRandomZr(rng))
			honest := tr.G1ToProto(g1)
			p, err := tr.G1FromProto(cloneECP(honest))
			require.NoError(t, err)
			assert.True(t, p.Equals(g1))
			p, err = tr.G1FromRawBytes(append(append([]byte{}, honest.X...), honest.Y...))
			require.NoError(t, err)
			assert.True(t, p.Equals(g1))

			g2 := c.GenG2.Mul(c.NewRandomZr(rng))
			honest2 := tr.G2ToProto(g2)
			p2, err := tr.G2FromProto(cloneECP2(honest2))
			require.NoError(t, err)
			assert.True(t, p2.Equals(g2))

			// G1: identity
			_, err = tr.G1FromProto(tr.G1ToProto(c.NewG1()))
			assert.EqualError(t, err, errInvalidG1Point.Error())

			// G1: off-curve
			bad := cloneECP(honest)
			bad.Y[len(bad.Y)-1] ^= 1
			_, err = tr.G1FromProto(bad)
			assert.EqualError(t, err, errInvalidG1Point.Error())
			_, err = tr.G1FromRawBytes(append(append([]byte{}, bad.X...), bad.Y...))
			assert.EqualError(t, err, errInvalidG1Point.Error())

			// G1: coordinate not reduced modulo p
			bad = cloneECP(honest)
			for i := range bad.X {
				bad.X[i] = 0xff
			}
			_, err = tr.G1FromProto(bad)
			assert.EqualError(t, err, errInvalidG1Point.Error())

			// G1: point of another curve with the same coordinate size
			_, err = tr.G1FromRawBytes(foreign)
			assert.EqualError(t, err, errInvalidG1Point.Error())

			// G2: identity
			_, err = tr.G2FromProto(tr.G2ToProto(c.NewG2()))
			assert.EqualError(t, err, errInvalidG2Point.Error())

			// G2: off-curve
			bad2 := cloneECP2(honest2)
			bad2.Yb[len(bad2.Yb)-1] ^= 1
			_, err = tr.G2FromProto(bad2)
			assert.EqualError(t, err, errInvalidG2Point.Error())

			// G2: coordinate not reduced modulo p
			bad2 = cloneECP2(honest2)
			for i := range bad2.Xa {
				bad2.Xa[i] = 0xff
			}
			_, err = tr.G2FromProto(bad2)
			assert.EqualError(t, err, errInvalidG2Point.Error())

			// G2: point of another curve
			_, err = tr.G2FromProto(tr.G2ToProto(bn254.GenG2))
			require.Error(t, err)

			// nil and lengths
			_, err = tr.G1FromProto(nil)
			assert.EqualError(t, err, errNilArgument.Error())
			_, err = tr.G2FromProto(nil)
			assert.EqualError(t, err, errNilArgument.Error())
			_, err = tr.G1FromRawBytes(nil)
			assert.EqualError(t, err, errInvalidLength.Error())
		})
	}
}

func TestGurvyTranslatorRejectsMalformedInput(t *testing.T) {
	for name, tr := range gurvyTranslators() {
		t.Run(name, func(t *testing.T) {
			c := tr.Curve()
			rng, err := c.Rand()
			require.NoError(t, err)

			g1 := c.GenG1.Mul(c.NewRandomZr(rng))
			honest := tr.G1ToProto(g1)
			require.Len(t, honest.X, c.CoordByteSize)
			require.Len(t, honest.Y, c.CoordByteSize)

			// honest encodings still round-trip
			p, err := tr.G1FromProto(cloneECP(honest))
			require.NoError(t, err)
			assert.True(t, p.Equals(g1))
			raw := append(append([]byte{}, honest.X...), honest.Y...)
			p, err = tr.G1FromRawBytes(raw)
			require.NoError(t, err)
			assert.True(t, p.Equals(g1))

			g2 := c.GenG2.Mul(c.NewRandomZr(rng))
			honest2 := tr.G2ToProto(g2)
			p2, err := tr.G2FromProto(cloneECP2(honest2))
			require.NoError(t, err)
			assert.True(t, p2.Equals(g2))

			// nil arguments must not panic
			assert.NotPanics(t, func() {
				_, err = tr.G1FromProto(nil)
			})
			assert.EqualError(t, err, errNilArgument.Error())
			assert.NotPanics(t, func() {
				_, err = tr.G2FromProto(nil)
			})
			assert.EqualError(t, err, errNilArgument.Error())
			assert.NotPanics(t, func() {
				_, err = tr.G1FromRawBytes(nil)
			})
			require.ErrorIs(t, err, errInvalidLength)

			// wrong coordinate sizes
			for _, e := range []*ECP{
				{},
				{X: honest.X},
				{X: honest.X[1:], Y: honest.Y},
				{X: honest.X, Y: append(append([]byte{}, honest.Y...), 0)},
				{X: append([]byte{0}, honest.X...), Y: append([]byte{0}, honest.Y...)},
			} {
				_, err = tr.G1FromProto(e)
				assert.EqualError(t, err, errInvalidLength.Error())
			}

			for _, e := range []*ECP2{
				{},
				{Xa: honest2.Xa, Xb: honest2.Xb, Ya: honest2.Ya},
				{Xa: honest2.Xa[1:], Xb: honest2.Xb, Ya: honest2.Ya, Yb: honest2.Yb},
				{Xa: honest2.Xa, Xb: honest2.Xb, Ya: honest2.Ya, Yb: append(append([]byte{}, honest2.Yb...), 0)},
			} {
				_, err = tr.G2FromProto(e)
				assert.EqualError(t, err, errInvalidLength.Error())
			}

			// raw bytes: 0x04 prefix, trailing data, compressed form, truncation
			for _, r := range [][]byte{
				append([]byte{0x04}, raw...),
				append(append([]byte{}, raw...), 0),
				g1.Compressed(),
				raw[:len(raw)-1],
			} {
				_, err = tr.G1FromRawBytes(r)
				require.ErrorIs(t, err, errInvalidLength)
			}

			// unbound translator
			_, err = (&Gurvy{}).G1FromProto(cloneECP(honest))
			assert.EqualError(t, err, errNilCurve.Error())
			_, err = (&Gurvy{}).G2FromProto(cloneECP2(honest2))
			assert.EqualError(t, err, errNilCurve.Error())
			_, err = (&Gurvy{}).G1FromRawBytes(raw)
			assert.EqualError(t, err, errNilCurve.Error())
		})
	}
}
