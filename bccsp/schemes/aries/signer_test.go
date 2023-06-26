/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries_test

import (
	"testing"

	bccsp "github.com/IBM/idemix/bccsp/schemes"
	"github.com/IBM/idemix/bccsp/schemes/aries"
	math "github.com/IBM/mathlib"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
	"github.com/stretchr/testify/assert"
)

func TestSigner(t *testing.T) {
	credProto := &aries.Cred{
		Bls:   bbs12381g2pub.New(),
		Curve: math.Curves[math.BLS12_381_BBS],
	}
	issuerProto := &aries.Issuer{}

	attrs := []string{
		"attr1",
		"attr2",
		"attr3",
		"attr4",
	}

	isk, err := issuerProto.NewKey(attrs)
	assert.NoError(t, err)
	assert.NotNil(t, isk)

	ipk := isk.Public()

	cr := &aries.CredRequest{
		Curve: math.Curves[math.BLS12_381_BBS],
	}

	rand, err := math.Curves[math.BLS12_381_BBS].Rand()
	assert.NoError(t, err)

	userProto := &aries.User{
		Curve: math.Curves[math.BLS12_381_BBS],
		Rng:   rand,
	}

	sk, err := userProto.NewKey()
	assert.NoError(t, err)

	credReq, blinding, err := cr.Blind(sk, ipk, []byte("la la land"))
	assert.NoError(t, err)

	err = cr.BlindVerify(credReq, ipk, []byte("la la land"))
	assert.NoError(t, err)

	idemixAttrs := []bccsp.IdemixAttribute{
		{
			Type:  bccsp.IdemixBytesAttribute,
			Value: []byte("msg1"),
		},
		{
			Type:  bccsp.IdemixBytesAttribute,
			Value: []byte("msg2"),
		},
		{
			Type:  bccsp.IdemixIntAttribute,
			Value: 35,
		},
		{
			Type:  bccsp.IdemixBytesAttribute,
			Value: []byte("msg4"),
		},
	}

	cred, err := credProto.Sign(isk, credReq, idemixAttrs)
	assert.NoError(t, err)

	cred, err = cr.Unblind(cred, blinding)
	assert.NoError(t, err)

	err = credProto.Verify(sk, ipk, cred, idemixAttrs)
	assert.NoError(t, err)

	signer := &aries.Signer{
		Curve: math.Curves[math.BLS12_381_BBS],
	}

	idemixAttrs = []bccsp.IdemixAttribute{
		{
			Type: bccsp.IdemixHiddenAttribute,
		},
		{
			Type:  bccsp.IdemixBytesAttribute,
			Value: []byte("msg2"),
		},
		{
			Type:  bccsp.IdemixIntAttribute,
			Value: 35,
		},
		{
			Type: bccsp.IdemixHiddenAttribute,
		},
	}

	Nym, RNmy, err := userProto.MakeNym(sk, ipk)
	assert.NoError(t, err)

	commit := bbs12381g2pub.NewProverCommittingG1()
	commit.Commit(ipk.(*aries.IssuerPublicKey).PKwG.H0)
	commit.Commit(ipk.(*aries.IssuerPublicKey).PKwG.H[0])
	commitNym := commit.Finish()

	chal := math.Curves[math.BLS12_381_BBS].NewRandomZr(rand)

	proof := commitNym.GenerateProof(chal, []*math.Zr{RNmy, sk})
	err = proof.Verify([]*math.G1{ipk.(*aries.IssuerPublicKey).PKwG.H0, ipk.(*aries.IssuerPublicKey).PKwG.H[0]}, Nym, chal)
	assert.NoError(t, err)

	sig, _, err := signer.Sign(cred, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), 0, 0, nil, bccsp.Standard, nil)
	assert.NoError(t, err)

	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, 0, 0, nil, 0, bccsp.Basic, nil)
	assert.NoError(t, err)
}
