/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries_test

import (
	"os"
	"testing"

	"github.com/IBM/idemix/bccsp/schemes/aries"
	"github.com/IBM/idemix/bccsp/types"
	math "github.com/IBM/mathlib"
	"github.com/ale-linux/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	bbs12381g2pub.SetCurve(math.Curves[math.BLS12_381_BBS])

	m.Run()
}

func TestSmartcardSigner(t *testing.T) {
	sc, curve := getSmartcard(t)
	defer func() {
		// reset the curve to the one other tests use
		bbs12381g2pub.SetCurve(math.Curves[math.BLS12_381_BBS])
	}()

	pubKey, privKey, err := generateKeyPairRandom()
	assert.NoError(t, err)

	privKeyBytes, err := privKey.Marshal()
	assert.NoError(t, err)

	pkwg, err := pubKey.ToPublicKeyWithGenerators(5)
	assert.NoError(t, err)

	ou, role, eid, rh := "ou", 34, "eid", "rh"
	messagesCount := 5 // includes the sk

	msgsZr := []*bbs12381g2pub.SignatureMessage{
		{
			Idx: 1,
			FR:  bbs12381g2pub.FrFromOKM([]byte(ou)),
		},
		{
			Idx: 2,
			FR:  curve.NewZrFromInt(int64(role)),
		},
		{
			Idx: 3,
			FR:  bbs12381g2pub.FrFromOKM([]byte(eid)),
		},
		{
			Idx: 4,
			FR:  bbs12381g2pub.FrFromOKM([]byte(rh)),
		},
	}

	sc.H0 = pkwg.H0
	sc.H1 = pkwg.H[0]
	sc.H2 = pkwg.H[3]
	sc.EID = bbs12381g2pub.FrFromOKM([]byte(eid))

	proofBytes, err := sc.Spend(nil, nil)
	assert.NoError(t, err)

	seed := proofBytes[0:16]
	r := sc.PRF(seed, sc.PRF_K1)

	B, err := sc.Curve.NewG1FromBytes(proofBytes[16 : 16+curve.G1ByteSize])
	assert.NoError(t, err)

	sig_, err := aries.BlindSign(msgsZr, messagesCount, B, privKeyBytes)
	assert.NoError(t, err)

	sigBytes, err := aries.UnblindSign(sig_, r, curve)
	assert.NoError(t, err)

	attrs := make([][]byte, len(msgsZr))
	for i, msg := range msgsZr {
		attrs[i] = msg.FR.Bytes()
	}

	cred := &aries.Credential{
		Cred:  sigBytes,
		Attrs: attrs,
	}

	credBytes, err := proto.Marshal(cred)
	assert.NoError(t, err)

	issuerProto := &aries.Issuer{}
	credProto := &aries.Cred{
		Bls:   bbs12381g2pub.New(),
		Curve: curve,
	}

	idemixAttrs := []types.IdemixAttribute{
		{
			Type:  types.IdemixBytesAttribute,
			Value: []byte(ou),
		},
		{
			Type:  types.IdemixIntAttribute,
			Value: role,
		},
		{
			Type:  types.IdemixBytesAttribute,
			Value: []byte(eid),
		},
		{
			Type:  types.IdemixBytesAttribute,
			Value: []byte(rh),
		},
	}

	isk, err := issuerProto.NewKeyFromBytes(privKeyBytes, []string{"", "", "", ""})
	assert.NoError(t, err)

	err = credProto.Verify(sc.Uid_sk, isk.Public(), credBytes, idemixAttrs)
	assert.NoError(t, err)

	rand, err := curve.Rand()
	assert.NoError(t, err)

	signer := &aries.Signer{
		Curve: curve,
		Rng:   rand,
	}

	rhIndex, eidIndex := 3, 2

	idemixAttrs = []types.IdemixAttribute{
		{
			Type:  types.IdemixBytesAttribute,
			Value: []byte(ou),
		},
		{
			Type:  types.IdemixIntAttribute,
			Value: role,
		},
		{
			Type: types.IdemixHiddenAttribute,
		},
		{
			Type: types.IdemixHiddenAttribute,
		},
	}

	sig, _, err := signer.Sign(credBytes, nil, B, r, isk.Public(), idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, types.Smartcard, nil)
	assert.NoError(t, err)

	err = signer.Verify(isk.Public(), sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, nil, 0, types.ExpectSmartcard, nil)
	assert.NoError(t, err)

	/**************************************************/

	// supply as eid nym the one received from the smartcard

	rNymEid, NymEid := sc.Receive()
	assert.True(t, NymEid.Equals(sc.H0.Mul2(rNymEid, sc.H2, bbs12381g2pub.FrFromOKM([]byte(eid)))))

	meta := &types.IdemixSignerMetadata{
		EidNym: NymEid.Bytes(),
		EidNymAuditData: &types.AttrNymAuditData{
			Nym:  NymEid,
			Rand: rNymEid,
			Attr: bbs12381g2pub.FrFromOKM([]byte(eid)),
		},
	}

	sig, _, err = signer.Sign(credBytes, nil, B, r, isk.Public(), idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, types.Smartcard, meta)
	assert.NoError(t, err)

	err = signer.Verify(isk.Public(), sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, nil, 0, types.ExpectSmartcard, meta)
	assert.NoError(t, err)
}

func readFile(t *testing.T, name string) []byte {
	bytes, err := os.ReadFile(name)
	assert.NoError(t, err)

	return bytes
}

/*

Test fixtures generated with

idemixgen ca-keygen --curve="FP256BN_AMCL_MIRACL" --aries --output="./testdata/idemix/"
idemixgen signerconfig --curve="FP256BN_AMCL_MIRACL" --aries --output="./testdata/idemix/" --ca-input="./testdata/idemix/" --enrollmentId=my-enrollment-id --revocationHandle=my-revocation-handle --org-unit=my-ou

*/

func TestSmartcardSigner1(t *testing.T) {
	sc, curve := getSmartcard(t)
	defer func() {
		// reset the curve to the one other tests use
		bbs12381g2pub.SetCurve(math.Curves[math.BLS12_381_BBS])
	}()

	rng, err := curve.Rand()
	assert.NoError(t, err)

	issuer := &aries.Issuer{}

	verifier := &aries.Signer{
		Curve: curve,
		Rng:   rng,
	}

	ipk, err := issuer.NewPublicKeyFromBytes(readFile(t, "testdata/idemix/msp/IssuerPublicKey"), []string{"", "", "", ""})
	assert.NoError(t, err)

	conf := &IdemixMSPSignerConfig{}
	err = proto.Unmarshal(readFile(t, "testdata/idemix/user/SignerConfig"), conf)
	assert.NoError(t, err)

	eid := conf.EnrollmentId
	ou := conf.OrganizationalUnitIdentifier
	role := int(conf.Role)

	// set the idemix bases, the eid and the secret key in the card

	sc.H0 = ipk.(*aries.IssuerPublicKey).PKwG.H0
	sc.H1 = ipk.(*aries.IssuerPublicKey).PKwG.H[0]
	sc.H2 = ipk.(*aries.IssuerPublicKey).PKwG.H[3]
	sc.EID = bbs12381g2pub.FrFromOKM([]byte(eid))
	sc.Uid_sk = curve.NewZrFromBytes(conf.Sk)

	// make nym eid
	rNymEid, NymEid := sc.Receive()

	msg, tau := []byte("tx"), []byte("tau (output of Bob's receive)")

	/*****************/
	// nym signature //
	/*****************/

	// make nym signature
	nymSig, err := sc.Spend(msg, tau /*, NymEid*/)
	assert.NoError(t, err)

	// verify nym signature
	err = sc.Verify(nymSig, NymEid.Bytes(), tau, msg)
	assert.NoError(t, err)

	/**********************/
	// standard signature //
	/**********************/

	// make idemix signature
	sig, err := idemixScSign(nymSig, conf.Cred, ipk, sc, NymEid, rNymEid, ou, role, eid)
	assert.NoError(t, err)

	// verify idemix signature
	err = verifier.Verify(ipk, sig, nil, []types.IdemixAttribute{
		{
			Type:  types.IdemixBytesAttribute,
			Value: []byte(ou),
		},
		{
			Type:  types.IdemixIntAttribute,
			Value: role,
		},
		{
			Type: types.IdemixHiddenAttribute,
		},
		{
			Type: types.IdemixHiddenAttribute,
		},
	}, 3, 2, nil, -1, types.ExpectSmartcard, &types.IdemixSignerMetadata{EidNym: NymEid.Bytes()})
	assert.NoError(t, err)
}

func idemixScSign(
	nymSig []byte,
	cred []byte,
	ipk types.IssuerPublicKey,
	sc *aries.Smartcard,
	NymEid *math.G1,
	rNymEid *math.Zr,
	ou string,
	role int,
	eid string,
) ([]byte, error) {

	seed := nymSig[0:16]

	rNym := sc.PRF(seed, sc.PRF_K1)
	nym, err := sc.Curve.NewG1FromBytes(nymSig[16 : 16+sc.Curve.G1ByteSize])
	if err != nil {
		return nil, err
	}

	rhIndex, eidIndex := 3, 2

	idemixAttrs := []types.IdemixAttribute{
		{
			Type:  types.IdemixBytesAttribute,
			Value: []byte(ou),
		},
		{
			Type:  types.IdemixIntAttribute,
			Value: role,
		},
		{
			Type: types.IdemixHiddenAttribute,
		},
		{
			Type: types.IdemixHiddenAttribute,
		},
	}

	meta := &types.IdemixSignerMetadata{
		EidNym: NymEid.Bytes(),
		EidNymAuditData: &types.AttrNymAuditData{
			Nym:  NymEid,
			Rand: rNymEid,
			Attr: bbs12381g2pub.FrFromOKM([]byte(eid)),
		},
	}

	rand, err := sc.Curve.Rand()
	if err != nil {
		return nil, err
	}

	signer := &aries.Signer{
		Curve: sc.Curve,
		Rng:   rand,
	}

	sig, _, err := signer.Sign(cred, nil, nym, rNym, ipk, idemixAttrs, nil, rhIndex, eidIndex, nil, types.Smartcard, meta)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

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

	idemixAttrs := []types.IdemixAttribute{
		{
			Type:  types.IdemixBytesAttribute,
			Value: []byte("msg1"),
		},
		{
			Type:  types.IdemixIntAttribute,
			Value: 34,
		},
		{
			Type:  types.IdemixBytesAttribute,
			Value: []byte("nymeid"),
		},
		{
			Type:  types.IdemixBytesAttribute,
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

	idemixAttrs = []types.IdemixAttribute{
		{
			Type:  types.IdemixBytesAttribute,
			Value: []byte("msg1"),
		},
		{
			Type:  types.IdemixIntAttribute,
			Value: 34,
		},
		{
			Type: types.IdemixHiddenAttribute,
		},
		{
			Type: types.IdemixHiddenAttribute,
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

	sig, _, err := signer.Sign(cred, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, types.Standard, nil)
	assert.NoError(t, err)

	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, nil, 0, types.Basic, nil)
	assert.NoError(t, err)

	//////////////////////
	// eidNym signature //
	//////////////////////

	sig, m, err := signer.Sign(cred, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, types.EidNym, nil)
	assert.NoError(t, err)

	cb := bbs12381g2pub.NewCommitmentBuilder(2)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H0, m.EidNymAuditData.Rand)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H[eidIndex+1], m.EidNymAuditData.Attr)
	assert.True(t, cb.Build().Equals(m.EidNymAuditData.Nym))

	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, nil, 0, types.ExpectEidNym, nil)
	assert.NoError(t, err)

	//////////////////////
	// eidNym signature // (nym supplied)
	//////////////////////

	rNym := curve.NewRandomZr(rand)

	cb = bbs12381g2pub.NewCommitmentBuilder(2)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H0, rNym)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H[eidIndex+1], bbs12381g2pub.FrFromOKM([]byte("nymeid")))
	nym := cb.Build()

	meta := &types.IdemixSignerMetadata{
		EidNym: nym.Bytes(),
		EidNymAuditData: &types.AttrNymAuditData{
			Nym:  nym,
			Rand: rNym,
			Attr: bbs12381g2pub.FrFromOKM([]byte("nymeid")),
		},
	}

	sig, _, err = signer.Sign(cred, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, types.EidNym, meta)
	assert.NoError(t, err)

	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, nil, 0, types.ExpectEidNym, nil)
	assert.NoError(t, err)

	// supply correct metadata for verification
	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs,
		rhIndex, eidIndex, nil, 0, types.ExpectEidNym, meta)
	assert.NoError(t, err)

	meta = &types.IdemixSignerMetadata{
		EidNym: nym.Bytes(),
		EidNymAuditData: &types.AttrNymAuditData{
			Nym:  nym,
			Rand: rNym,
			Attr: curve.NewZrFromInt(36),
		},
	}

	// supply wrong metadata for verification
	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs,
		rhIndex, eidIndex, nil, 0, types.ExpectEidNym, meta)
	assert.EqualError(t, err, "signature invalid: nym eid validation failed, does not match regenerated nym eid")

	meta = &types.IdemixSignerMetadata{
		EidNym: curve.GenG1.Bytes(),
	}

	// supply wrong metadata for verification
	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs,
		rhIndex, eidIndex, nil, 0, types.ExpectEidNym, meta)
	assert.EqualError(t, err, "signature invalid: nym eid validation failed, signature nym eid does not match metadata")

	meta = &types.IdemixSignerMetadata{
		EidNym: []byte("garbage"),
	}

	// supply wrong metadata for verification
	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs,
		rhIndex, eidIndex, nil, 0, types.ExpectEidNym, meta)
	assert.EqualError(t, err, "signature invalid: nym eid validation failed, failed to unmarshal meta nym eid")

	meta = &types.IdemixSignerMetadata{
		EidNym: nym.Bytes(),
		EidNymAuditData: &types.AttrNymAuditData{
			Nym:  curve.GenG1.Mul(curve.NewRandomZr(rand)),
			Rand: rNym,
			Attr: bbs12381g2pub.FrFromOKM([]byte("nymeid")),
		},
	}

	// supply wrong metadata for verification
	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs,
		rhIndex, eidIndex, nil, 0, types.ExpectEidNym, meta)
	assert.EqualError(t, err, "signature invalid: nym eid validation failed, does not match metadata")

	// audit with AuditNymEid - it should succeed with the right nym and randomness
	err = signer.AuditNymEid(ipk, eidIndex, sig, "nymeid", rNym, types.AuditExpectSignature)
	assert.NoError(t, err)

	// audit with AuditNymEid - it should fail with the wrong nym
	err = signer.AuditNymEid(ipk, eidIndex, sig, "not so much the nymeid", rNym, types.AuditExpectSignature)
	assert.EqualError(t, err, "eid nym does not match")

	// audit with AuditNymEid - it should fail with the wrong randomness
	err = signer.AuditNymEid(ipk, eidIndex, sig, "nymeid", curve.NewRandomZr(rand), types.AuditExpectSignature)
	assert.EqualError(t, err, "eid nym does not match")

	// audit with AuditNymEid - it should succeed with the right nym and randomness
	err = signer.AuditNymEid(ipk, eidIndex, nym.Bytes(), "nymeid", rNym, types.AuditExpectEidNym)
	assert.NoError(t, err)

	// audit with AuditNymEid - it should fail with the wrong nym
	err = signer.AuditNymEid(ipk, eidIndex, nym.Bytes(), "not so much the nymeid", rNym, types.AuditExpectEidNym)
	assert.EqualError(t, err, "eid nym does not match")

	// audit with AuditNymEid - it should fail with the wrong randomness
	err = signer.AuditNymEid(ipk, eidIndex, nym.Bytes(), "nymeid", curve.NewRandomZr(rand), types.AuditExpectEidNym)
	assert.EqualError(t, err, "eid nym does not match")

	// audit with AuditNymEid - it should succeed with the right nym and randomness
	err = signer.AuditNymEid(ipk, eidIndex, nym.Bytes(), "nymeid", rNym, types.AuditExpectEidNymRhNym)
	assert.NoError(t, err)

	// audit with AuditNymEid - it should fail with the wrong nym
	err = signer.AuditNymEid(ipk, eidIndex, nym.Bytes(), "not so much the nymeid", rNym, types.AuditExpectEidNymRhNym)
	assert.EqualError(t, err, "eid nym does not match")

	// audit with AuditNymEid - it should fail with the wrong randomness
	err = signer.AuditNymEid(ipk, eidIndex, nym.Bytes(), "nymeid", curve.NewRandomZr(rand), types.AuditExpectEidNymRhNym)
	assert.EqualError(t, err, "eid nym does not match")

	//////////////////////
	// eidNym signature // (wrong nym supplied)
	//////////////////////

	rNym = curve.NewRandomZr(rand)

	cb = bbs12381g2pub.NewCommitmentBuilder(2)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H0, rNym)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H[eidIndex+1], curve.HashToZr([]byte("Not the nymeid")))
	nym = cb.Build()

	meta = &types.IdemixSignerMetadata{
		EidNym: nym.Bytes(),
		EidNymAuditData: &types.AttrNymAuditData{
			Nym:  nym,
			Rand: rNym,
			Attr: bbs12381g2pub.FrFromOKM([]byte("nymeid")),
		},
	}

	_, _, err = signer.Sign(cred, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, types.EidNym, meta)
	assert.EqualError(t, err, "nym supplied in metadata cannot be recomputed")

	/////////////////////
	// NymRh signature //
	/////////////////////

	sig, m, err = signer.Sign(cred, sk, Nym, RNmy, ipk, idemixAttrs, []byte("tome"), rhIndex, eidIndex, nil, types.EidNymRhNym, nil)
	assert.NoError(t, err)

	cb = bbs12381g2pub.NewCommitmentBuilder(2)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H0, m.EidNymAuditData.Rand)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H[eidIndex+1], m.EidNymAuditData.Attr)
	assert.True(t, cb.Build().Equals(m.EidNymAuditData.Nym))

	cb = bbs12381g2pub.NewCommitmentBuilder(2)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H0, m.RhNymAuditData.Rand)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H[rhIndex+1], m.RhNymAuditData.Attr)
	assert.True(t, cb.Build().Equals(m.RhNymAuditData.Nym))

	err = signer.Verify(ipk, sig, []byte("tome"), idemixAttrs, rhIndex, eidIndex, nil, 0, types.ExpectEidNymRhNym, nil)
	assert.NoError(t, err)

	/////////////////////
	// NymRh signature // (nym supplied)
	/////////////////////

	rNym = curve.NewRandomZr(rand)

	cb = bbs12381g2pub.NewCommitmentBuilder(2)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H0, rNym)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H[rhIndex+1], bbs12381g2pub.FrFromOKM([]byte("nymrh")))
	nym = cb.Build()

	meta = &types.IdemixSignerMetadata{
		RhNym: nym.Bytes(),
		RhNymAuditData: &types.AttrNymAuditData{
			Nym:  nym,
			Rand: rNym,
			Attr: bbs12381g2pub.FrFromOKM([]byte("nymrh")),
		},
	}

	sig, _, err = signer.Sign(cred, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, types.EidNymRhNym, meta)
	assert.NoError(t, err)

	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, nil, 0, types.ExpectEidNymRhNym, nil)
	assert.NoError(t, err)

	// supply correct metadata for verification
	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, nil, 0, types.ExpectEidNymRhNym, meta)
	assert.NoError(t, err)

	meta = &types.IdemixSignerMetadata{
		RhNym: nym.Bytes(),
		RhNymAuditData: &types.AttrNymAuditData{
			Nym:  nym,
			Rand: rNym,
			Attr: curve.NewZrFromInt(37),
		},
	}

	// supply wrong metadata for verification
	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, nil, 0, types.ExpectEidNymRhNym, meta)
	assert.EqualError(t, err, "signature invalid: nym rh validation failed, does not match regenerated nym rh")

	meta = &types.IdemixSignerMetadata{
		RhNym: curve.GenG1.Bytes(),
	}

	// supply wrong metadata for verification
	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, nil, 0, types.ExpectEidNymRhNym, meta)
	assert.EqualError(t, err, "signature invalid: rh nym validation failed, signature rh nym does not match metadata")

	meta = &types.IdemixSignerMetadata{
		RhNym: []byte("garbage"),
	}

	// supply wrong metadata for verification
	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, nil, 0, types.ExpectEidNymRhNym, meta)
	assert.EqualError(t, err, "signature invalid: rh nym validation failed, failed to unmarshal meta rh nym")

	meta = &types.IdemixSignerMetadata{
		RhNym: nym.Bytes(),
		RhNymAuditData: &types.AttrNymAuditData{
			Nym:  curve.GenG1.Mul(curve.NewRandomZr(rand)),
			Rand: rNym,
			Attr: bbs12381g2pub.FrFromOKM([]byte("nymrh")),
		},
	}

	// supply wrong metadata for verification
	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, nil, 0, types.ExpectEidNymRhNym, meta)
	assert.EqualError(t, err, "signature invalid: nym rh validation failed, does not match metadata")

	// audit with AuditNymEid - it should succeed with the right nym and randomness
	err = signer.AuditNymRh(ipk, rhIndex, sig, "nymrh", rNym, types.AuditExpectSignature)
	assert.NoError(t, err)

	// audit with AuditNymEid - it should fail with the wrong nym
	err = signer.AuditNymRh(ipk, rhIndex, sig, "not so much the nymrh", rNym, types.AuditExpectSignature)
	assert.EqualError(t, err, "rh nym does not match")

	// audit with AuditNymEid - it should fail with the wrong randomness
	err = signer.AuditNymRh(ipk, rhIndex, sig, "nymrh", curve.NewRandomZr(rand), types.AuditExpectSignature)
	assert.EqualError(t, err, "rh nym does not match")

	// audit with AuditNymEid - it should succeed with the right nym and randomness
	err = signer.AuditNymRh(ipk, rhIndex, nym.Bytes(), "nymrh", rNym, types.AuditExpectEidNymRhNym)
	assert.NoError(t, err)

	// audit with AuditNymEid - it should fail with the wrong nym
	err = signer.AuditNymRh(ipk, rhIndex, nym.Bytes(), "not so much the nymrh", rNym, types.AuditExpectEidNymRhNym)
	assert.EqualError(t, err, "rh nym does not match")

	// audit with AuditNymEid - it should fail with the wrong randomness
	err = signer.AuditNymRh(ipk, rhIndex, nym.Bytes(), "nymrh", curve.NewRandomZr(rand), types.AuditExpectEidNymRhNym)
	assert.EqualError(t, err, "rh nym does not match")

	// audit with AuditNymEid - it should fail with AuditExpectEidNym
	err = signer.AuditNymRh(ipk, rhIndex, nym.Bytes(), "nymrh", rNym, types.AuditExpectEidNym)
	assert.EqualError(t, err, "invalid audit type [1]")

	/////////////////////
	// NymRh signature // (wrong nym supplied)
	/////////////////////

	rNym = curve.NewRandomZr(rand)

	cb = bbs12381g2pub.NewCommitmentBuilder(2)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H0, rNym)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H[rhIndex+1], curve.NewZrFromInt(37))
	nym = cb.Build()

	meta = &types.IdemixSignerMetadata{
		RhNym: nym.Bytes(),
		RhNymAuditData: &types.AttrNymAuditData{
			Nym:  nym,
			Rand: rNym,
			Attr: bbs12381g2pub.FrFromOKM([]byte("nymrh")),
		},
	}

	_, _, err = signer.Sign(cred, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, types.EidNymRhNym, meta)
	assert.EqualError(t, err, "nym supplied in metadata cannot be recomputed")

	//////////////////////
	// eidNym signature // (eidNym missing but expected)
	//////////////////////

	sig, _, err = signer.Sign(cred, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, types.Standard, nil)
	assert.NoError(t, err)

	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, nil, 0, types.ExpectEidNym, nil)
	assert.EqualError(t, err, "no EidNym provided but ExpectEidNym required")

	/////////////////////
	// rhNym signature // (rhNym missing but expected)
	/////////////////////

	sig, _, err = signer.Sign(cred, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, types.EidNym, nil)
	assert.NoError(t, err)

	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, nil, 0, types.ExpectEidNymRhNym, nil)
	assert.EqualError(t, err, "no RhNym provided but ExpectEidNymRhNym required")

	//////////////////////
	// eidNym signature // (but eid disclosed)
	//////////////////////

	idemixAttrs = []types.IdemixAttribute{
		{
			Type:  types.IdemixBytesAttribute,
			Value: []byte("msg1"),
		},
		{
			Type:  types.IdemixIntAttribute,
			Value: 34,
		},
		{
			Type:  types.IdemixBytesAttribute,
			Value: []byte("nymeid"),
		},
		{
			Type: types.IdemixHiddenAttribute,
		},
	}

	_, _, err = signer.Sign(cred, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, types.EidNym, nil)
	assert.EqualError(t, err, "cannot create idemix signature: disclosure of enrollment ID requested for EidNym signature")

	/////////////////////
	// rhNym signature // (but rh disclosed)
	/////////////////////

	idemixAttrs = []types.IdemixAttribute{
		{
			Type:  types.IdemixBytesAttribute,
			Value: []byte("msg1"),
		},
		{
			Type:  types.IdemixIntAttribute,
			Value: 34,
		},
		{
			Type: types.IdemixHiddenAttribute,
		},
		{
			Type:  types.IdemixIntAttribute,
			Value: 36,
		},
	}

	_, _, err = signer.Sign(cred, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, types.EidNymRhNym, nil)
	assert.EqualError(t, err, "cannot create idemix signature: disclosure of enrollment ID or RH requested for EidNymRhNym signature")
}
