/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	"io"

	"github.com/IBM/idemix/bccsp/handlers"
	math "github.com/IBM/mathlib"
	"github.com/pkg/errors"
)

type User struct {
	Curve *math.Curve
	Rng   io.Reader
}

// NewKey generates a new User secret key
func (u *User) NewKey() (*math.Zr, error) {
	r := u.Curve.NewRandomZr(u.Rng)

	return r, nil
}

// NewKeyFromBytes converts the passed bytes to a User secret key
func (u *User) NewKeyFromBytes(raw []byte) (*math.Zr, error) {
	if len(raw) != u.Curve.ScalarByteSize {
		return nil, errors.Errorf("invalid length, expected [%d], got [%d]", u.Curve.ScalarByteSize, len(raw))
	}

	return u.Curve.NewZrFromBytes(raw), nil
}

// MakeNym creates a new unlinkable pseudonym
func (u *User) MakeNym(sk *math.Zr, key handlers.IssuerPublicKey) (*math.G1, *math.Zr, error) {
	ipk, ok := key.(*IssuerPublicKey)
	if !ok {
		return nil, nil, errors.Errorf("invalid issuer public key, expected *IssuerPublicKey, got [%T]", ipk)
	}

	// Construct a commitment to the sk
	// Nym = h_0^r \cdot h_1^sk

	rnd := u.Curve.NewRandomZr(u.Rng)

	nym := ipk.PKwG.H0.Mul2(rnd, ipk.PKwG.H[0], sk)

	return nym, rnd, nil
}

func (u *User) NewNymFromBytes(raw []byte) (*math.G1, *math.Zr, error) {
	if len(raw) != u.Curve.ScalarByteSize+u.Curve.G1ByteSize {
		return nil, nil, errors.Errorf("invalid length, expected [%d], got [%d]", u.Curve.ScalarByteSize+u.Curve.G1ByteSize, len(raw))
	}

	rnd := u.Curve.NewZrFromBytes(raw[:u.Curve.ScalarByteSize])
	nym, err := u.Curve.NewG1FromBytes(raw[u.Curve.ScalarByteSize:])
	if err != nil {
		return nil, nil, err
	}

	return nym, rnd, err
}

// NewPublicNymFromBytes converts the passed bytes to a public nym
func (u *User) NewPublicNymFromBytes(raw []byte) (*math.G1, error) {
	if len(raw) != u.Curve.G1ByteSize {
		return nil, errors.Errorf("invalid length, expected [%d], got [%d]", u.Curve.G1ByteSize, len(raw))
	}

	nym, err := u.Curve.NewG1FromBytes(raw)
	if err != nil {
		return nil, err
	}

	return nym, err
}
