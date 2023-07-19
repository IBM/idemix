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
			Type:  bccsp.IdemixBytesAttribute,
			Value: []byte("nymeid"),
		},
		{
			Type:  bccsp.IdemixBytesAttribute,
			Value: []byte("nymrh"),
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

	sig, m, err := signer.Sign(cred, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, bccsp.EidNym, nil)
	assert.NoError(t, err)

	cb := bbs12381g2pub.NewCommitmentBuilder(2)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H0, m.EidNymAuditData.Rand)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H[eidIndex+1], m.EidNymAuditData.Attr)
	assert.True(t, cb.Build().Equals(m.EidNymAuditData.Nym))

	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, nil, 0, bccsp.ExpectEidNym, nil)
	assert.NoError(t, err)

	//////////////////////
	// eidNym signature // (nym supplied)
	//////////////////////

	rNym := curve.NewRandomZr(rand)

	cb = bbs12381g2pub.NewCommitmentBuilder(2)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H0, rNym)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H[eidIndex+1], bbs12381g2pub.FrFromOKM([]byte("nymeid")))
	nym := cb.Build()

	meta := &bccsp.IdemixSignerMetadata{
		EidNym: nym.Bytes(),
		EidNymAuditData: &bccsp.AttrNymAuditData{
			Nym:  nym,
			Rand: rNym,
			Attr: bbs12381g2pub.FrFromOKM([]byte("nymeid")),
		},
	}

	sig, _, err = signer.Sign(cred, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, bccsp.EidNym, meta)
	assert.NoError(t, err)

	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, nil, 0, bccsp.ExpectEidNym, nil)
	assert.NoError(t, err)

	// supply correct metadata for verification
	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs,
		rhIndex, eidIndex, nil, 0, bccsp.ExpectEidNym, meta)
	assert.NoError(t, err)

	meta = &bccsp.IdemixSignerMetadata{
		EidNym: nym.Bytes(),
		EidNymAuditData: &bccsp.AttrNymAuditData{
			Nym:  nym,
			Rand: rNym,
			Attr: curve.NewZrFromInt(36),
		},
	}

	// supply wrong metadata for verification
	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs,
		rhIndex, eidIndex, nil, 0, bccsp.ExpectEidNym, meta)
	assert.EqualError(t, err, "signature invalid: nym eid validation failed, does not match regenerated nym eid")

	meta = &bccsp.IdemixSignerMetadata{
		EidNym: nym.Bytes(),
		EidNymAuditData: &bccsp.AttrNymAuditData{
			Nym:  curve.GenG1.Mul(curve.NewRandomZr(rand)),
			Rand: rNym,
			Attr: bbs12381g2pub.FrFromOKM([]byte("nymeid")),
		},
	}

	// supply wrong metadata for verification
	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs,
		rhIndex, eidIndex, nil, 0, bccsp.ExpectEidNym, meta)
	assert.EqualError(t, err, "signature invalid: nym eid validation failed, does not match metadata")

	// audit with AuditNymEid - it should succeed with the right nym and randomness
	err = signer.AuditNymEid(ipk, eidIndex, sig, "nymeid", rNym, bccsp.AuditExpectSignature)
	assert.NoError(t, err)

	// audit with AuditNymEid - it should fail with the wrong nym
	err = signer.AuditNymEid(ipk, eidIndex, sig, "not so much the nymeid", rNym, bccsp.AuditExpectSignature)
	assert.EqualError(t, err, "eid nym does not match")

	// audit with AuditNymEid - it should fail with the wrong randomness
	err = signer.AuditNymEid(ipk, eidIndex, sig, "nymeid", curve.NewRandomZr(rand), bccsp.AuditExpectSignature)
	assert.EqualError(t, err, "eid nym does not match")

	// audit with AuditNymEid - it should succeed with the right nym and randomness
	err = signer.AuditNymEid(ipk, eidIndex, nym.Bytes(), "nymeid", rNym, bccsp.AuditExpectEidNym)
	assert.NoError(t, err)

	// audit with AuditNymEid - it should fail with the wrong nym
	err = signer.AuditNymEid(ipk, eidIndex, nym.Bytes(), "not so much the nymeid", rNym, bccsp.AuditExpectEidNym)
	assert.EqualError(t, err, "eid nym does not match")

	// audit with AuditNymEid - it should fail with the wrong randomness
	err = signer.AuditNymEid(ipk, eidIndex, nym.Bytes(), "nymeid", curve.NewRandomZr(rand), bccsp.AuditExpectEidNym)
	assert.EqualError(t, err, "eid nym does not match")

	// audit with AuditNymEid - it should succeed with the right nym and randomness
	err = signer.AuditNymEid(ipk, eidIndex, nym.Bytes(), "nymeid", rNym, bccsp.AuditExpectEidNymRhNym)
	assert.NoError(t, err)

	// audit with AuditNymEid - it should fail with the wrong nym
	err = signer.AuditNymEid(ipk, eidIndex, nym.Bytes(), "not so much the nymeid", rNym, bccsp.AuditExpectEidNymRhNym)
	assert.EqualError(t, err, "eid nym does not match")

	// audit with AuditNymEid - it should fail with the wrong randomness
	err = signer.AuditNymEid(ipk, eidIndex, nym.Bytes(), "nymeid", curve.NewRandomZr(rand), bccsp.AuditExpectEidNymRhNym)
	assert.EqualError(t, err, "eid nym does not match")

	//////////////////////
	// eidNym signature // (wrong nym supplied)
	//////////////////////

	rNym = curve.NewRandomZr(rand)

	cb = bbs12381g2pub.NewCommitmentBuilder(2)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H0, rNym)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H[eidIndex+1], curve.HashToZr([]byte("Not the nymeid")))
	nym = cb.Build()

	meta = &bccsp.IdemixSignerMetadata{
		EidNym: nym.Bytes(),
		EidNymAuditData: &bccsp.AttrNymAuditData{
			Nym:  nym,
			Rand: rNym,
			Attr: bbs12381g2pub.FrFromOKM([]byte("nymeid")),
		},
	}

	_, _, err = signer.Sign(cred, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, bccsp.EidNym, meta)
	assert.EqualError(t, err, "nym supplied in metadata cannot be recomputed")

	/////////////////////
	// NymRh signature //
	/////////////////////

	sig, m, err = signer.Sign(cred, sk, Nym, RNmy, ipk, idemixAttrs, []byte("tome"), rhIndex, eidIndex, nil, bccsp.EidNymRhNym, nil)
	assert.NoError(t, err)

	cb = bbs12381g2pub.NewCommitmentBuilder(2)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H0, m.EidNymAuditData.Rand)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H[eidIndex+1], m.EidNymAuditData.Attr)
	assert.True(t, cb.Build().Equals(m.EidNymAuditData.Nym))

	cb = bbs12381g2pub.NewCommitmentBuilder(2)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H0, m.RhNymAuditData.Rand)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H[rhIndex+1], m.RhNymAuditData.Attr)
	assert.True(t, cb.Build().Equals(m.RhNymAuditData.Nym))

	err = signer.Verify(ipk, sig, []byte("tome"), idemixAttrs, rhIndex, eidIndex, nil, 0, bccsp.ExpectEidNymRhNym, nil)
	assert.NoError(t, err)

	/////////////////////
	// NymRh signature // (nym supplied)
	/////////////////////

	rNym = curve.NewRandomZr(rand)

	cb = bbs12381g2pub.NewCommitmentBuilder(2)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H0, rNym)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H[rhIndex+1], bbs12381g2pub.FrFromOKM([]byte("nymrh")))
	nym = cb.Build()

	meta = &bccsp.IdemixSignerMetadata{
		RhNym: nym.Bytes(),
		RhNymAuditData: &bccsp.AttrNymAuditData{
			Nym:  nym,
			Rand: rNym,
			Attr: bbs12381g2pub.FrFromOKM([]byte("nymrh")),
		},
	}

	sig, _, err = signer.Sign(cred, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, bccsp.EidNymRhNym, meta)
	assert.NoError(t, err)

	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, nil, 0, bccsp.ExpectEidNymRhNym, nil)
	assert.NoError(t, err)

	// supply correct metadata for verification
	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, nil, 0, bccsp.ExpectEidNymRhNym, meta)
	assert.NoError(t, err)

	meta = &bccsp.IdemixSignerMetadata{
		RhNym: nym.Bytes(),
		RhNymAuditData: &bccsp.AttrNymAuditData{
			Nym:  nym,
			Rand: rNym,
			Attr: curve.NewZrFromInt(37),
		},
	}

	// supply wrong metadata for verification
	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, nil, 0, bccsp.ExpectEidNymRhNym, meta)
	assert.EqualError(t, err, "signature invalid: nym rh validation failed, does not match regenerated nym rh")

	meta = &bccsp.IdemixSignerMetadata{
		RhNym: nym.Bytes(),
		RhNymAuditData: &bccsp.AttrNymAuditData{
			Nym:  curve.GenG1.Mul(curve.NewRandomZr(rand)),
			Rand: rNym,
			Attr: bbs12381g2pub.FrFromOKM([]byte("nymrh")),
		},
	}

	// supply wrong metadata for verification
	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, nil, 0, bccsp.ExpectEidNymRhNym, meta)
	assert.EqualError(t, err, "signature invalid: nym rh validation failed, does not match metadata")

	// audit with AuditNymEid - it should succeed with the right nym and randomness
	err = signer.AuditNymRh(ipk, rhIndex, sig, "nymrh", rNym, bccsp.AuditExpectSignature)
	assert.NoError(t, err)

	// audit with AuditNymEid - it should fail with the wrong nym
	err = signer.AuditNymRh(ipk, rhIndex, sig, "not so much the nymrh", rNym, bccsp.AuditExpectSignature)
	assert.EqualError(t, err, "rh nym does not match")

	// audit with AuditNymEid - it should fail with the wrong randomness
	err = signer.AuditNymRh(ipk, rhIndex, sig, "nymrh", curve.NewRandomZr(rand), bccsp.AuditExpectSignature)
	assert.EqualError(t, err, "rh nym does not match")

	// audit with AuditNymEid - it should succeed with the right nym and randomness
	err = signer.AuditNymRh(ipk, rhIndex, nym.Bytes(), "nymrh", rNym, bccsp.AuditExpectEidNymRhNym)
	assert.NoError(t, err)

	// audit with AuditNymEid - it should fail with the wrong nym
	err = signer.AuditNymRh(ipk, rhIndex, nym.Bytes(), "not so much the nymrh", rNym, bccsp.AuditExpectEidNymRhNym)
	assert.EqualError(t, err, "rh nym does not match")

	// audit with AuditNymEid - it should fail with the wrong randomness
	err = signer.AuditNymRh(ipk, rhIndex, nym.Bytes(), "nymrh", curve.NewRandomZr(rand), bccsp.AuditExpectEidNymRhNym)
	assert.EqualError(t, err, "rh nym does not match")

	// audit with AuditNymEid - it should fail with AuditExpectEidNym
	err = signer.AuditNymRh(ipk, rhIndex, nym.Bytes(), "nymrh", rNym, bccsp.AuditExpectEidNym)
	assert.EqualError(t, err, "invalid audit type [1]")

	/////////////////////
	// NymRh signature // (wrong nym supplied)
	/////////////////////

	rNym = curve.NewRandomZr(rand)

	cb = bbs12381g2pub.NewCommitmentBuilder(2)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H0, rNym)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H[rhIndex+1], curve.NewZrFromInt(37))
	nym = cb.Build()

	meta = &bccsp.IdemixSignerMetadata{
		RhNym: nym.Bytes(),
		RhNymAuditData: &bccsp.AttrNymAuditData{
			Nym:  nym,
			Rand: rNym,
			Attr: bbs12381g2pub.FrFromOKM([]byte("nymrh")),
		},
	}

	_, _, err = signer.Sign(cred, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, bccsp.EidNymRhNym, meta)
	assert.EqualError(t, err, "nym supplied in metadata cannot be recomputed")

	//////////////////////
	// eidNym signature // (eidNym missing but expected)
	//////////////////////

	sig, _, err = signer.Sign(cred, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, bccsp.Standard, nil)
	assert.NoError(t, err)

	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, nil, 0, bccsp.ExpectEidNym, nil)
	assert.EqualError(t, err, "parse nym proof: invalid size of G1 signature proof")

	/////////////////////
	// rhNym signature // (rhNym missing but expected)
	/////////////////////

	sig, _, err = signer.Sign(cred, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, bccsp.EidNym, nil)
	assert.NoError(t, err)

	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, nil, 0, bccsp.ExpectEidNymRhNym, nil)
	assert.EqualError(t, err, "parse rh proof: invalid size of G1 signature proof")

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
			Type:  bccsp.IdemixBytesAttribute,
			Value: []byte("nymeid"),
		},
		{
			Type: bccsp.IdemixHiddenAttribute,
		},
	}

	_, _, err = signer.Sign(cred, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, bccsp.EidNym, nil)
	assert.EqualError(t, err, "error determining index for attribute: attribute not found")

	/////////////////////
	// rhNym signature // (but rh disclosed)
	/////////////////////

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
			Type:  bccsp.IdemixIntAttribute,
			Value: 36,
		},
	}

	_, _, err = signer.Sign(cred, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, bccsp.EidNymRhNym, nil)
	assert.EqualError(t, err, "error determining index for attribute: attribute not found")
}
