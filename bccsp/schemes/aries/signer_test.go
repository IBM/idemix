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
	curve := math.Curves[math.BLS12_381_BBS]

	credProto := &aries.Cred{
		Bls:   bbs12381g2pub.New(),
		Curve: curve,
	}
	issuerProto := &aries.Issuer{}

	attrs := []string{
		"attr1",
		"attr2",
		"eid",
		"rh",
	}

	rhIndex, eidIndex := 3, 2

	isk, err := issuerProto.NewKey(attrs)
	assert.NoError(t, err)
	assert.NotNil(t, isk)

	ipk := isk.Public()

	cr := &aries.CredRequest{
		Curve: curve,
	}

	rand, err := curve.Rand()
	assert.NoError(t, err)

	userProto := &aries.User{
		Curve: curve,
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
			Type:  bccsp.IdemixIntAttribute,
			Value: 34,
		},
		{
			Type:  bccsp.IdemixIntAttribute,
			Value: 35,
		},
		{
			Type:  bccsp.IdemixIntAttribute,
			Value: 36,
		},
	}

	cred, err := credProto.Sign(isk, credReq, idemixAttrs)
	assert.NoError(t, err)

	cred, err = cr.Unblind(cred, blinding)
	assert.NoError(t, err)

	err = credProto.Verify(sk, ipk, cred, idemixAttrs)
	assert.NoError(t, err)

	signer := &aries.Signer{
		Curve: curve,
		Rng:   rand,
	}

	idemixAttrs = []bccsp.IdemixAttribute{
		{
			Type:  bccsp.IdemixBytesAttribute,
			Value: []byte("msg1"),
		},
		{
			Type:  bccsp.IdemixIntAttribute,
			Value: 34,
		},
		{
			Type: bccsp.IdemixHiddenAttribute,
		},
		{
			Type: bccsp.IdemixHiddenAttribute,
		},
	}

	Nym, RNmy, err := userProto.MakeNym(sk, ipk)
	assert.NoError(t, err)

	// commit := bbs12381g2pub.NewProverCommittingG1()
	// commit.Commit(ipk.(*aries.IssuerPublicKey).PKwG.H0)
	// commit.Commit(ipk.(*aries.IssuerPublicKey).PKwG.H[0])
	// commitNym := commit.Finish()

	// chal := curve.NewRandomZr(rand)

	// proof := commitNym.GenerateProof(chal, []*math.Zr{RNmy, sk})
	// err = proof.Verify([]*math.G1{ipk.(*aries.IssuerPublicKey).PKwG.H0, ipk.(*aries.IssuerPublicKey).PKwG.H[0]}, Nym, chal)
	// assert.NoError(t, err)

	////////////////////
	// base signature //
	////////////////////

	sig, _, err := signer.Sign(cred, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, bccsp.Standard, nil)
	assert.NoError(t, err)

	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, nil, 0, bccsp.Basic, nil)
	assert.NoError(t, err)

	//////////////////////
	// eidNym signature //
	//////////////////////

	sig, _, err = signer.Sign(cred, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, bccsp.EidNym, nil)
	assert.NoError(t, err)

	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, nil, 0, bccsp.ExpectEidNym, nil)
	assert.NoError(t, err)

	//////////////////////
	// eidNym signature // (nym supplied)
	//////////////////////

	rNym := curve.NewRandomZr(rand)

	cb := bbs12381g2pub.NewCommitmentBuilder(2)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H0, rNym)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H[eidIndex+1], curve.NewZrFromInt(35))
	nym := cb.Build()

	meta := &bccsp.IdemixSignerMetadata{
		EidNym: nym.Bytes(),
		EidNymAuditData: &bccsp.AttrNymAuditData{
			Nym:  nym,
			Rand: rNym,
			Attr: curve.NewZrFromInt(35),
		},
	}

	sig, _, err = signer.Sign(cred, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, bccsp.EidNym, meta)
	assert.NoError(t, err)

	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, nil, 0, bccsp.ExpectEidNym, nil)
	assert.NoError(t, err)

	//////////////////////
	// eidNym signature // (wrong nym supplied)
	//////////////////////

	rNym = curve.NewRandomZr(rand)

	cb = bbs12381g2pub.NewCommitmentBuilder(2)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H0, rNym)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H[eidIndex+1], curve.NewZrFromInt(36))
	nym = cb.Build()

	meta = &bccsp.IdemixSignerMetadata{
		EidNym: nym.Bytes(),
		EidNymAuditData: &bccsp.AttrNymAuditData{
			Nym:  nym,
			Rand: rNym,
			Attr: curve.NewZrFromInt(35),
		},
	}

	_, _, err = signer.Sign(cred, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, bccsp.EidNym, meta)
	assert.EqualError(t, err, "NymEid supplied in metadata cannot be recomputed")

	//////////////////////
	// eidNym signature // (but eid disclosed)
	//////////////////////

	idemixAttrs = []bccsp.IdemixAttribute{
		{
			Type:  bccsp.IdemixBytesAttribute,
			Value: []byte("msg1"),
		},
		{
			Type:  bccsp.IdemixIntAttribute,
			Value: 34,
		},
		{
			Type:  bccsp.IdemixIntAttribute,
			Value: 35,
		},
		{
			Type: bccsp.IdemixHiddenAttribute,
		},
	}

	_, _, err = signer.Sign(cred, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, bccsp.EidNym, nil)
	assert.EqualError(t, err, "error determining index for NymEid: attribute not found")
}
