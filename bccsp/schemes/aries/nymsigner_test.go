/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package aries_test

import (
	"testing"

	"github.com/IBM/idemix/bccsp/schemes/aries"
	math "github.com/IBM/mathlib"
	"github.com/ale-linux/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
	"github.com/stretchr/testify/assert"
)

func TestNymSigner(t *testing.T) {
	curve := math.Curves[math.BLS12_381_BBS]
	rand, err := curve.Rand()
	assert.NoError(t, err)

	issuerProto := &aries.Issuer{curve}

	attrs := []string{
		"attr1",
		"attr2",
		"eid",
		"rh",
	}

	isk, err := issuerProto.NewKey(attrs)
	assert.NoError(t, err)
	assert.NotNil(t, isk)

	_ipk := isk.Public()
	ipk := _ipk.(*aries.IssuerPublicKey)

	signer := &aries.NymSigner{
		Curve: curve,
		Rng:   rand,
	}

	sk := curve.NewRandomZr(rand)
	rNym := curve.NewRandomZr(rand)

	for skPos := range attrs {
		signer.UserSecretKeyIndex = skPos

		cb := bbs12381g2pub.NewCommitmentBuilder(2)
		cb.Add(ipk.PKwG.H0, rNym)
		cb.Add(ipk.PKwG.H[skPos], sk)
		nym := cb.Build()

		sig, err := signer.Sign(sk, nym, rNym, _ipk, []byte("ciao"))
		assert.NoError(t, err)

		err = signer.Verify(_ipk, nym, sig, []byte("ciao"), skPos)
		assert.NoError(t, err)

		sig, err = signer.Sign(sk, nym, curve.NewRandomZr(rand), _ipk, []byte("ciao"))
		assert.NoError(t, err)

		err = signer.Verify(_ipk, nym, sig, []byte("ciao"), skPos)
		assert.EqualError(t, err, "contribution is not zero")

		sig, err = signer.Sign(curve.NewRandomZr(rand), nym, rNym, _ipk, []byte("ciao"))
		assert.NoError(t, err)

		err = signer.Verify(_ipk, nym, sig, []byte("ciao"), skPos)
		assert.EqualError(t, err, "contribution is not zero")

		sig, err = signer.Sign(sk, curve.GenG1.Mul(curve.NewRandomZr(rand)), rNym, _ipk, []byte("ciao"))
		assert.NoError(t, err)

		err = signer.Verify(_ipk, nym, sig, []byte("ciao"), skPos)
		assert.EqualError(t, err, "contribution is not zero")

		sig, err = signer.Sign(sk, nym, rNym, _ipk, []byte("ciao"))
		assert.NoError(t, err)

		err = signer.Verify(_ipk, curve.GenG1.Mul(curve.NewRandomZr(rand)), sig, []byte("ciao"), skPos)
		assert.EqualError(t, err, "contribution is not zero")
	}
}
