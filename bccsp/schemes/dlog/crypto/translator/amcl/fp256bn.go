/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package amcl

import (
	"errors"

	math "github.com/IBM/mathlib"
)

var (
	errNilArgument    = errors.New("nil argument")
	errInvalidLength  = errors.New("invalid marshalled length")
	errInvalidG1Point = errors.New("invalid G1 point: not on the curve or the identity")
	errInvalidG2Point = errors.New("invalid G2 point: not on the curve or the identity")
	errNilCurve       = errors.New("translator is not bound to a curve")
)

// checkFp256bnG1 rejects the identity. The AMCL decoder maps every
// malformed encoding (coordinates not reduced modulo p, off-curve points,
// points of another curve) to the point at infinity without reporting an
// error, so the identity is what an invalid encoding looks like after
// decoding. No honest code path serializes the identity of G1.
func checkFp256bnG1(p *math.G1, err error) (*math.G1, error) {
	if err != nil {
		return nil, err
	}
	if p == nil || p.IsInfinity() {
		return nil, errInvalidG1Point
	}

	return p, nil
}

// checkFp256bnG2 is the G2 counterpart of checkFp256bnG1.
func checkFp256bnG2(c *math.Curve, p *math.G2, err error) (*math.G2, error) {
	if err != nil {
		return nil, err
	}
	if p == nil || p.Equals(c.NewG2()) {
		return nil, errInvalidG2Point
	}

	return p, nil
}

type Fp256bn struct {
	C *math.Curve
}

// Curve returns the curve this translator is bound to.
func (a *Fp256bn) Curve() *math.Curve {
	if a == nil {
		return nil
	}

	return a.C
}

func (a *Fp256bn) G1ToProto(g1 *math.G1) *ECP {
	if g1 == nil {
		panic("nil argument")
	}

	bytes := g1.Bytes()[1:]
	l := len(bytes) / 2

	return &ECP{
		X: bytes[:l],
		Y: bytes[l:],
	}
}

func (a *Fp256bn) G1FromRawBytes(raw []byte) (*math.G1, error) {
	l := len(raw) / 2

	return a.G1FromProto(&ECP{
		X: raw[:l],
		Y: raw[l:],
	})
}

func (a *Fp256bn) G1FromProto(e *ECP) (*math.G1, error) {
	if e == nil {
		return nil, errNilArgument
	}

	if a.C == nil {
		return nil, errNilCurve
	}

	if len(e.X) != a.C.CoordByteSize || len(e.Y) != a.C.CoordByteSize {
		return nil, errInvalidLength
	}

	bytes := make([]byte, len(e.X)*2+1)
	l := len(e.X)
	bytes[0] = 0x04
	copy(bytes[1:], e.X)
	copy(bytes[l+1:], e.Y)

	return checkFp256bnG1(a.C.NewG1FromBytes(bytes))
}

func (a *Fp256bn) G2ToProto(g2 *math.G2) *ECP2 {
	if g2 == nil {
		panic("nil argument")
	}

	bytes := g2.Bytes()
	l := len(bytes) / 4

	return &ECP2{
		Xa: bytes[0:l],
		Xb: bytes[l : 2*l],
		Ya: bytes[2*l : 3*l],
		Yb: bytes[3*l:],
	}
}

func (a *Fp256bn) G2FromProto(e *ECP2) (*math.G2, error) {
	if e == nil {
		return nil, errNilArgument
	}

	if a.C == nil {
		return nil, errNilCurve
	}

	if len(e.Xa) != a.C.CoordByteSize || len(e.Xb) != a.C.CoordByteSize || len(e.Ya) != a.C.CoordByteSize || len(e.Yb) != a.C.CoordByteSize {
		return nil, errInvalidLength
	}

	bytes := make([]byte, len(e.Xa)*4)
	l := len(e.Xa)
	copy(bytes[0:l], e.Xa)
	copy(bytes[l:2*l], e.Xb)
	copy(bytes[2*l:3*l], e.Ya)
	copy(bytes[3*l:], e.Yb)

	p, err := a.C.NewG2FromBytes(bytes)

	return checkFp256bnG2(a.C, p, err)
}

type Fp256bnMiracl struct {
	C *math.Curve
}

// Curve returns the curve this translator is bound to.
func (a *Fp256bnMiracl) Curve() *math.Curve {
	if a == nil {
		return nil
	}

	return a.C
}

func (a *Fp256bnMiracl) G1ToProto(g1 *math.G1) *ECP {
	if g1 == nil {
		panic("nil argument")
	}

	bytes := g1.Bytes()[1:]
	l := len(bytes) / 2

	return &ECP{
		X: bytes[:l],
		Y: bytes[l:],
	}
}

func (a *Fp256bnMiracl) G1FromRawBytes(raw []byte) (*math.G1, error) {
	l := len(raw) / 2

	return a.G1FromProto(&ECP{
		X: raw[:l],
		Y: raw[l:],
	})
}

func (a *Fp256bnMiracl) G1FromProto(e *ECP) (*math.G1, error) {
	if e == nil {
		return nil, errNilArgument
	}

	if a.C == nil {
		return nil, errNilCurve
	}

	if len(e.X) != a.C.CoordByteSize || len(e.Y) != a.C.CoordByteSize {
		return nil, errInvalidLength
	}

	bytes := make([]byte, len(e.X)*2+1)
	l := len(e.X)
	bytes[0] = 0x04
	copy(bytes[1:], e.X)
	copy(bytes[l+1:], e.Y)

	return checkFp256bnG1(a.C.NewG1FromBytes(bytes))
}

func (a *Fp256bnMiracl) G2ToProto(g2 *math.G2) *ECP2 {
	if g2 == nil {
		panic("nil argument")
	}

	bytes := g2.Bytes()[1:]
	l := len(bytes) / 4

	return &ECP2{
		Xa: bytes[0:l],
		Xb: bytes[l : 2*l],
		Ya: bytes[2*l : 3*l],
		Yb: bytes[3*l:],
	}
}

func (a *Fp256bnMiracl) G2FromProto(e *ECP2) (*math.G2, error) {
	if e == nil {
		return nil, errNilArgument
	}

	if a.C == nil {
		return nil, errNilCurve
	}

	if len(e.Xa) != a.C.CoordByteSize || len(e.Xb) != a.C.CoordByteSize || len(e.Ya) != a.C.CoordByteSize || len(e.Yb) != a.C.CoordByteSize {
		return nil, errInvalidLength
	}

	bytes := make([]byte, 1+len(e.Xa)*4)
	bytes[0] = 0x04
	l := len(e.Xa)
	copy(bytes[1:], e.Xa)
	copy(bytes[1+l:], e.Xb)
	copy(bytes[1+2*l:], e.Ya)
	copy(bytes[1+3*l:], e.Yb)

	p, err := a.C.NewG2FromBytes(bytes)

	return checkFp256bnG2(a.C, p, err)
}
