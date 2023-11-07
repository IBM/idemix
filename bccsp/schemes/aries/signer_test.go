/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries_test

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"testing"

	"github.com/IBM/idemix/bccsp/schemes/aries"
	"github.com/IBM/idemix/bccsp/types"
	math "github.com/IBM/mathlib"
	"github.com/ale-linux/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/assert"
)

func TestSmartcardSigner(t *testing.T) {
	sc, curve := getSmartcard(t)

	pubKey, privKey, err := generateKeyPairRandom(curve)
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
			FR:  bbs12381g2pub.FrFromOKM([]byte(ou), curve),
		},
		{
			Idx: 2,
			FR:  curve.NewZrFromInt(int64(role)),
		},
		{
			Idx: 3,
			FR:  bbs12381g2pub.FrFromOKM([]byte(eid), curve),
		},
		{
			Idx: 4,
			FR:  bbs12381g2pub.FrFromOKM([]byte(rh), curve),
		},
	}

	sc.H0 = pkwg.H0
	sc.H1 = pkwg.H[0]
	sc.H2 = pkwg.H[3]
	sc.EID = bbs12381g2pub.FrFromOKM([]byte(eid), curve)

	proofBytes, err := sc.NymSign(nil)
	assert.NoError(t, err)

	seed := proofBytes[0:16]
	r := sc.PRF(seed, sc.PRF_K1)

	B, err := sc.Curve.NewG1FromBytes(proofBytes[16 : 16+curve.G1ByteSize])
	assert.NoError(t, err)

	sig_, err := aries.BlindSign(msgsZr, messagesCount, B, privKeyBytes, curve)
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

	issuerProto := &aries.Issuer{curve}
	credProto := &aries.Cred{
		Bls:   bbs12381g2pub.New(curve),
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

	err = signer.Verify(isk.Public(), sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, 0, nil, 0, types.ExpectSmartcard, nil)
	assert.NoError(t, err)

	idemixAttrs = []types.IdemixAttribute{
		{
			Type: types.IdemixHiddenAttribute,
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

	sig, _, err = signer.Sign(credBytes, nil, B, r, isk.Public(), idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, types.Smartcard, nil)
	assert.NoError(t, err)

	err = signer.Verify(isk.Public(), sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, 0, nil, 0, types.ExpectSmartcard, nil)
	assert.NoError(t, err)

	idemixAttrs = []types.IdemixAttribute{
		{
			Type:  types.IdemixBytesAttribute,
			Value: []byte(ou),
		},
		{
			Type: types.IdemixHiddenAttribute,
		},
		{
			Type: types.IdemixHiddenAttribute,
		},
		{
			Type: types.IdemixHiddenAttribute,
		},
	}

	sig, _, err = signer.Sign(credBytes, nil, B, r, isk.Public(), idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, types.Smartcard, nil)
	assert.NoError(t, err)

	err = signer.Verify(isk.Public(), sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, 0, nil, 0, types.ExpectSmartcard, nil)
	assert.NoError(t, err)

	idemixAttrs = []types.IdemixAttribute{
		{
			Type: types.IdemixHiddenAttribute,
		},
		{
			Type: types.IdemixHiddenAttribute,
		},
		{
			Type: types.IdemixHiddenAttribute,
		},
		{
			Type: types.IdemixHiddenAttribute,
		},
	}

	sig, _, err = signer.Sign(credBytes, nil, B, r, isk.Public(), idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, types.Smartcard, nil)
	assert.NoError(t, err)

	err = signer.Verify(isk.Public(), sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, 0, nil, 0, types.ExpectSmartcard, nil)
	assert.NoError(t, err)

	/**************************************************/

	// supply as eid nym the one received from the smartcard

	rNymEid, NymEid := sc.NymEid()
	assert.True(t, NymEid.Equals(sc.H0.Mul2(rNymEid, sc.H2, bbs12381g2pub.FrFromOKM([]byte(eid), curve))))

	meta := &types.IdemixSignerMetadata{
		EidNym: NymEid.Bytes(),
		EidNymAuditData: &types.AttrNymAuditData{
			Nym:  NymEid,
			Rand: rNymEid,
			Attr: bbs12381g2pub.FrFromOKM([]byte(eid), curve),
		},
	}

	sig, _, err = signer.Sign(credBytes, nil, B, r, isk.Public(), idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, types.Smartcard, meta)
	assert.NoError(t, err)

	err = signer.Verify(isk.Public(), sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, 0, nil, 0, types.ExpectSmartcard, meta)
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

	rng, err := curve.Rand()
	assert.NoError(t, err)

	issuer := &aries.Issuer{curve}

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
	sc.EID = bbs12381g2pub.FrFromOKM([]byte(eid), curve)
	sc.Uid_sk = curve.NewZrFromBytes(conf.Sk)

	// make nym eid
	rNymEid, NymEid := sc.NymEid()

	msg, tau := []byte("tx"), []byte("tau (output of Bob's receive)")

	/*****************/
	// nym signature //
	/*****************/

	// make nym signature
	nymSig, err := sc.NymSign(append(append([]byte{}, tau...), msg...))
	assert.NoError(t, err)

	// verify nym signature
	err = sc.NymVerify(nymSig, NymEid, append(append([]byte{}, tau...), msg...))
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
	}, 3, 2, 0, nil, -1, types.ExpectSmartcard, &types.IdemixSignerMetadata{EidNym: NymEid.Bytes()})
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
			Attr: bbs12381g2pub.FrFromOKM([]byte(eid), sc.Curve),
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

func TestW3CCred(t *testing.T) {
	curve := math.Curves[math.BLS12_381_BBS]

	rand, err := curve.Rand()
	assert.NoError(t, err)

	pkHex := `87fae47132975f345b38fafd53149f7a009b89dd94fdc54d5d051a29e185ed4870acc2453fbd2e307d1543dfb7fbfdb30cf0008df96c75e2e43975b7f92864b4bc6e3f2f1495748d80a36691f6feaeb8fe151c1bb35de9bff5ac21ff9e57aebe`
	sigBase64 := "tQ4rHLBIh7a9dk5MVoly8ccb80pGeoEqybhYnYZO8VmguaFDyuCN7rFdBPCVs1/SYUHlKfzccE4m7waZyoLEkBLFiK2g54Q2i+CdtYBgDdkUDsoULSBMcH1MwGHwdjfXpldFNFrHFx/IAvLVniyeMQ=="

	messagesBytes := [][]byte{
		[]byte(`_:c14n0 <http://purl.org/dc/terms/created> "2023-11-03T11:12:17Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`),
		[]byte(`_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#BbsBlsSignature2020> .`),
		[]byte(`_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .`),
		[]byte(`_:c14n0 <https://w3id.org/security#verificationMethod> <did:key:zUC73gNPc1EnZmDDjYJzE8Bk89VRhuZPQYXFnSiSUZvX9N1i7N5VtMbJyowDR46rtARHLJYRVf7WMbGLb43s9tfTyKF9KFF22vBjXZRomcwtoQJmMNUSY7tfzyhLEy58dwUz3WD#zUC73gNPc1EnZmDDjYJzE8Bk89VRhuZPQYXFnSiSUZvX9N1i7N5VtMbJyowDR46rtARHLJYRVf7WMbGLb43s9tfTyKF9KFF22vBjXZRomcwtoQJmMNUSY7tfzyhLEy58dwUz3WD> .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <cbdccard:cbdcdata> _:c14n0 .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <http://schema.org/birthDate> "1990-11-22"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <http://schema.org/familyName> "Bowen" .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <http://schema.org/gender> "Male" .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <http://schema.org/givenName> "Jace" .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <cbdccard:CBDC> .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResident> .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <https://w3id.org/citizenship#birthCountry> "Bahamas" .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <https://w3id.org/citizenship#lprCategory> "C09" .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <https://w3id.org/citizenship#lprNumber> "223-45-198" .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <https://w3id.org/citizenship#residentSince> "2015-01-01"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <https://w3id.org/vdl#portraitMetadata> "{\"hash\":\"de701215430a0c4f940ffe830efd27f54cae0d9655d78dc3849272e7641c05eedd066588345caf9d4181d9f325e73a9950a967d6fe766a4a62e02876e73255ad\",\"key\":\"aab053a5e11e3360679ce1a42c7733063843854a1002c19186743d7432a2e467\",\"link\":\"https://dev.lcn-cluster-dev-qa-app-583c1d2c1a459ad4539801325cd4ba78-0000.us-south.containers.appdomain.cloud/api/public/v1/object/70a62792-eb95-4491-a77f-e53dde8034fb\"}"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON> .`),
		[]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <http://schema.org/name> "Permanent Resident Card" .`),
		[]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResidentCard> .`),
		[]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .`),
		[]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#credentialSubject> <did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> .`),
		[]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#expirationDate> "2029-12-03T12:19:52Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`),
		[]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#issuanceDate> "2019-12-03T12:19:52Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`),
		[]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#issuer> <did:key:zUC73gNPc1EnZmDDjYJzE8Bk89VRhuZPQYXFnSiSUZvX9N1i7N5VtMbJyowDR46rtARHLJYRVf7WMbGLb43s9tfTyKF9KFF22vBjXZRomcwtoQJmMNUSY7tfzyhLEy58dwUz3WD> .`),
		[]byte(`_:c14n0 <cbdccard:1_usk> "chgA6VtGQeRd/0rf1P6fCFm8t7ZU1Q8eMPM/+E9gsw8=" .`),
		[]byte(`_:c14n0 <cbdccard:2_ou> "mytopos-mychannel-token-chaincode.example.com" .`),
		[]byte(`_:c14n0 <cbdccard:3_role> "2"^^<http://www.w3.org/2001/XMLSchema#integer> .`),
		[]byte(`_:c14n0 <cbdccard:4_eid> "alice.remote" .`),
		[]byte(`_:c14n0 <cbdccard:5_rh> "111" .`),
	}

	pkBytes, err := hex.DecodeString(pkHex)
	assert.NoError(t, err)
	sigBytes, err := base64.StdEncoding.DecodeString(sigBase64)
	assert.NoError(t, err)

	bls := bbs12381g2pub.New(math.Curves[math.BLS12_381_BBS])

	err = bls.Verify(messagesBytes, sigBytes, pkBytes)
	assert.NoError(t, err)

	attributeNames := []string{
		"_:c14n0 <http://www.w3.",
		"_:c14n0 <https://w3id.o",
		"_:c14n0 <https://w3id.o",
		"<did:key:z6MknntgQWCT8Z",
		"<did:key:z6MknntgQWCT8Z",
		"<did:key:z6MknntgQWCT8Z",
		"<did:key:z6MknntgQWCT8Z",
		"<did:key:z6MknntgQWCT8Z",
		"<did:key:z6MknntgQWCT8Z",
		"<did:key:z6MknntgQWCT8Z",
		"<did:key:z6MknntgQWCT8Z",
		"<did:key:z6MknntgQWCT8Z",
		"<did:key:z6MknntgQWCT8Z",
		"<did:key:z6MknntgQWCT8Z",
		"<did:key:z6MknntgQWCT8Z",
		"<did:key:z6MknntgQWCT8Z",
		"<https://issuer.oidp.us",
		"<https://issuer.oidp.us",
		"<https://issuer.oidp.us",
		"<https://issuer.oidp.us",
		"<https://issuer.oidp.us",
		"<https://issuer.oidp.us",
		"<https://issuer.oidp.us",
		"_:c14n0 <cbdccard:1_usk",
		"_:c14n0 <cbdccard:2_ou>",
		"_:c14n0 <cbdccard:3_rol",
		"_:c14n0 <cbdccard:4_eid",
		"_:c14n0 <cbdccard:5_rh>",
	}

	attributes := make([][]byte, len(attributeNames))
	for i, msg := range messagesBytes[1:] {
		attributes[i] = bbs12381g2pub.FrFromOKM(msg, curve).Bytes()
	}

	sk := bbs12381g2pub.FrFromOKM(messagesBytes[0], curve)

	cred := &aries.Credential{
		Cred:  sigBytes,
		Attrs: attributes,
	}
	credBytes, err := proto.Marshal(cred)
	assert.NoError(t, err)

	credProto := &aries.Cred{
		Bls:   bbs12381g2pub.New(curve),
		Curve: curve,
	}

	issuerProto := &aries.Issuer{curve}

	ipk, err := issuerProto.NewPublicKeyFromBytes(pkBytes, attributeNames)
	assert.NoError(t, err)

	idemixAttrs := []types.IdemixAttribute{}
	for _, msg := range messagesBytes[1:] {
		idemixAttrs = append(idemixAttrs, types.IdemixAttribute{
			Type:  types.IdemixBytesAttribute,
			Value: msg,
		})
	}

	err = credProto.Verify(sk, ipk, credBytes, idemixAttrs)
	assert.NoError(t, err)

	signer := &aries.Signer{
		Curve: curve,
		Rng:   rand,
	}

	userProto := &aries.User{
		Curve: curve,
		Rng:   rand,
	}

	for i := range messagesBytes[1:] {
		idemixAttrs[i] = types.IdemixAttribute{
			Type: types.IdemixHiddenAttribute,
		}
	}

	rhIndex, eidIndex := 27, 26

	Nym, RNmy, err := userProto.MakeNym(sk, ipk)
	assert.NoError(t, err)

	////////////////////
	// base signature //
	////////////////////

	sig, _, err := signer.Sign(credBytes, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, types.Standard, nil)
	assert.NoError(t, err)

	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, 0, nil, 0, types.Basic, nil)
	assert.NoError(t, err)

	//////////////////////
	// eidNym signature //
	//////////////////////

	sig, m, err := signer.Sign(credBytes, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, types.EidNym, nil)
	assert.NoError(t, err)

	cb := bbs12381g2pub.NewCommitmentBuilder(2)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H0, m.EidNymAuditData.Rand)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H[eidIndex+1], bbs12381g2pub.FrFromOKM([]byte(`_:c14n0 <cbdccard:4_eid> "alice.remote" .`), curve))
	assert.True(t, cb.Build().Equals(m.EidNymAuditData.Nym))

	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, 0, nil, 0, types.ExpectEidNym, nil)
	assert.NoError(t, err)
}

func TestW3CCredSkElsewhere(t *testing.T) {
	curve := math.Curves[math.BLS12_381_BBS]

	rand, err := curve.Rand()
	assert.NoError(t, err)

	pkHex := `87fae47132975f345b38fafd53149f7a009b89dd94fdc54d5d051a29e185ed4870acc2453fbd2e307d1543dfb7fbfdb30cf0008df96c75e2e43975b7f92864b4bc6e3f2f1495748d80a36691f6feaeb8fe151c1bb35de9bff5ac21ff9e57aebe`
	sigBase64 := "tQ4rHLBIh7a9dk5MVoly8ccb80pGeoEqybhYnYZO8VmguaFDyuCN7rFdBPCVs1/SYUHlKfzccE4m7waZyoLEkBLFiK2g54Q2i+CdtYBgDdkUDsoULSBMcH1MwGHwdjfXpldFNFrHFx/IAvLVniyeMQ=="

	attributeNames := []string{
		"_:c14n0 <http://www.w3.",
		"_:c14n0 <https://w3id.o",
		"_:c14n0 <https://w3id.o",
		"<did:key:z6MknntgQWCT8Z",
		"<did:key:z6MknntgQWCT8Z",
		"<did:key:z6MknntgQWCT8Z",
		"<did:key:z6MknntgQWCT8Z",
		"<did:key:z6MknntgQWCT8Z",
		"<did:key:z6MknntgQWCT8Z",
		"<did:key:z6MknntgQWCT8Z",
		"<did:key:z6MknntgQWCT8Z",
		"<did:key:z6MknntgQWCT8Z",
		"<did:key:z6MknntgQWCT8Z",
		"<did:key:z6MknntgQWCT8Z",
		"<did:key:z6MknntgQWCT8Z",
		"<did:key:z6MknntgQWCT8Z",
		"<https://issuer.oidp.us",
		"<https://issuer.oidp.us",
		"<https://issuer.oidp.us",
		"<https://issuer.oidp.us",
		"<https://issuer.oidp.us",
		"<https://issuer.oidp.us",
		"<https://issuer.oidp.us",
		"_:c14n0 <cbdccard:1_usk",
		"_:c14n0 <cbdccard:2_ou>",
		"_:c14n0 <cbdccard:3_rol",
		"_:c14n0 <cbdccard:4_eid",
		"_:c14n0 <cbdccard:5_rh>",
	}

	messagesBytes := [][]byte{
		[]byte(`_:c14n0 <http://purl.org/dc/terms/created> "2023-11-03T11:12:17Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`),
		[]byte(`_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#BbsBlsSignature2020> .`),
		[]byte(`_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .`),
		[]byte(`_:c14n0 <https://w3id.org/security#verificationMethod> <did:key:zUC73gNPc1EnZmDDjYJzE8Bk89VRhuZPQYXFnSiSUZvX9N1i7N5VtMbJyowDR46rtARHLJYRVf7WMbGLb43s9tfTyKF9KFF22vBjXZRomcwtoQJmMNUSY7tfzyhLEy58dwUz3WD#zUC73gNPc1EnZmDDjYJzE8Bk89VRhuZPQYXFnSiSUZvX9N1i7N5VtMbJyowDR46rtARHLJYRVf7WMbGLb43s9tfTyKF9KFF22vBjXZRomcwtoQJmMNUSY7tfzyhLEy58dwUz3WD> .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <cbdccard:cbdcdata> _:c14n0 .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <http://schema.org/birthDate> "1990-11-22"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <http://schema.org/familyName> "Bowen" .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <http://schema.org/gender> "Male" .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <http://schema.org/givenName> "Jace" .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <cbdccard:CBDC> .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResident> .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <https://w3id.org/citizenship#birthCountry> "Bahamas" .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <https://w3id.org/citizenship#lprCategory> "C09" .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <https://w3id.org/citizenship#lprNumber> "223-45-198" .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <https://w3id.org/citizenship#residentSince> "2015-01-01"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`),
		[]byte(`<did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> <https://w3id.org/vdl#portraitMetadata> "{\"hash\":\"de701215430a0c4f940ffe830efd27f54cae0d9655d78dc3849272e7641c05eedd066588345caf9d4181d9f325e73a9950a967d6fe766a4a62e02876e73255ad\",\"key\":\"aab053a5e11e3360679ce1a42c7733063843854a1002c19186743d7432a2e467\",\"link\":\"https://dev.lcn-cluster-dev-qa-app-583c1d2c1a459ad4539801325cd4ba78-0000.us-south.containers.appdomain.cloud/api/public/v1/object/70a62792-eb95-4491-a77f-e53dde8034fb\"}"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON> .`),
		[]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <http://schema.org/name> "Permanent Resident Card" .`),
		[]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResidentCard> .`),
		[]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .`),
		[]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#credentialSubject> <did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e> .`),
		[]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#expirationDate> "2029-12-03T12:19:52Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`),
		[]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#issuanceDate> "2019-12-03T12:19:52Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`),
		[]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#issuer> <did:key:zUC73gNPc1EnZmDDjYJzE8Bk89VRhuZPQYXFnSiSUZvX9N1i7N5VtMbJyowDR46rtARHLJYRVf7WMbGLb43s9tfTyKF9KFF22vBjXZRomcwtoQJmMNUSY7tfzyhLEy58dwUz3WD> .`),
		[]byte(`_:c14n0 <cbdccard:1_usk> "chgA6VtGQeRd/0rf1P6fCFm8t7ZU1Q8eMPM/+E9gsw8=" .`),
		[]byte(`_:c14n0 <cbdccard:2_ou> "mytopos-mychannel-token-chaincode.example.com" .`),
		[]byte(`_:c14n0 <cbdccard:3_role> "2"^^<http://www.w3.org/2001/XMLSchema#integer> .`),
		[]byte(`_:c14n0 <cbdccard:4_eid> "alice.remote" .`),
		[]byte(`_:c14n0 <cbdccard:5_rh> "111" .`),
	}

	for _, idcs := range [][]int{
		{24, 27, 26},
		{0, 0, 1},
		{0, 1, 0},
		{3, 9, 7},
		{24, 0, 1},
		{24, 1, 0},
		{24, 25, 26},
		{26, 25, 24},
		{25, 26, 24},
		{25, 24, 26},
		{0, 1, len(messagesBytes) - 2},
		{0, len(messagesBytes) - 3, len(messagesBytes) - 2},
		{len(messagesBytes) - 2, len(messagesBytes) - 3, 0},
		{len(messagesBytes) - 2, 0, len(messagesBytes) - 3},
	} {
		skIndex := idcs[0]                    // this is an index into the `messagesBytes` array
		rhIndex, eidIndex := idcs[1], idcs[2] // these are indices into the `messagesBytes` *without* the usk attribute

		eidIndexInBases := eidIndex
		rhIndexInBases := rhIndex

		// increment the index to cater for the index for `sk`
		if eidIndexInBases >= skIndex {
			eidIndexInBases++
		}

		// increment the index to cater for the index for `sk`
		if rhIndexInBases >= skIndex {
			rhIndexInBases++
		}

		eidAttr := messagesBytes[eidIndexInBases]
		rhAttr := messagesBytes[rhIndexInBases]

		t.Run("run", func(t *testing.T) {
			pkBytes, err := hex.DecodeString(pkHex)
			assert.NoError(t, err)
			sigBytes, err := base64.StdEncoding.DecodeString(sigBase64)
			assert.NoError(t, err)

			bls := bbs12381g2pub.New(math.Curves[math.BLS12_381_BBS])

			err = bls.Verify(messagesBytes, sigBytes, pkBytes)
			assert.NoError(t, err)

			attributes := make([][]byte, len(attributeNames))
			j := 0
			for i, msg := range messagesBytes {
				if i == skIndex {
					continue
				}
				attributes[j] = bbs12381g2pub.FrFromOKM(msg, curve).Bytes()
				j++
			}

			sk := bbs12381g2pub.FrFromOKM(messagesBytes[skIndex], curve)

			cred := &aries.Credential{
				Cred:  sigBytes,
				Attrs: attributes,
				SkPos: int32(skIndex),
			}
			credBytes, err := proto.Marshal(cred)
			assert.NoError(t, err)

			credProto := &aries.Cred{
				Bls:   bbs12381g2pub.New(curve),
				Curve: curve,
			}

			issuerProto := &aries.Issuer{curve}

			ipk, err := issuerProto.NewPublicKeyFromBytes(pkBytes, attributeNames)
			assert.NoError(t, err)

			idemixAttrs := []types.IdemixAttribute{}
			for i, msg := range messagesBytes {
				if i == skIndex {
					continue
				}
				idemixAttrs = append(idemixAttrs, types.IdemixAttribute{
					Type:  types.IdemixBytesAttribute,
					Value: msg,
				})
			}

			err = credProto.Verify(sk, ipk, credBytes, idemixAttrs)
			assert.NoError(t, err)

			signer := &aries.Signer{
				Curve: curve,
				Rng:   rand,
			}

			userProto := &aries.User{
				Curve:              curve,
				Rng:                rand,
				UserSecretKeyIndex: skIndex,
			}

			for i := range idemixAttrs {
				idemixAttrs[i] = types.IdemixAttribute{
					Type: types.IdemixHiddenAttribute,
				}
			}

			Nym, RNmy, err := userProto.MakeNym(sk, ipk)
			assert.NoError(t, err)

			////////////////////
			// base signature //
			////////////////////

			sig, _, err := signer.Sign(credBytes, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, types.Standard, nil)
			assert.NoError(t, err)

			err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, skIndex, nil, 0, types.Basic, nil)
			assert.NoError(t, err)

			//////////////////////
			// eidNym signature //
			//////////////////////

			sig, m, err := signer.Sign(credBytes, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, types.EidNym, nil)
			assert.NoError(t, err)

			cb := bbs12381g2pub.NewCommitmentBuilder(2)
			cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H0, m.EidNymAuditData.Rand)
			cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H[eidIndexInBases], bbs12381g2pub.FrFromOKM(eidAttr, curve))
			assert.True(t, cb.Build().Equals(m.EidNymAuditData.Nym))

			err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, skIndex, nil, 0, types.ExpectEidNym, nil)
			assert.NoError(t, err)

			//////////////////////
			// eidNym signature // (nym supplied)
			//////////////////////

			rNym := curve.NewRandomZr(rand)

			cb = bbs12381g2pub.NewCommitmentBuilder(2)
			cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H0, rNym)
			cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H[eidIndexInBases], bbs12381g2pub.FrFromOKM(eidAttr, curve))
			nym := cb.Build()

			meta := &types.IdemixSignerMetadata{
				EidNym: nym.Bytes(),
				EidNymAuditData: &types.AttrNymAuditData{
					Nym:  nym,
					Rand: rNym,
					Attr: bbs12381g2pub.FrFromOKM(eidAttr, curve),
				},
			}

			sig, _, err = signer.Sign(credBytes, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, types.EidNym, meta)
			assert.NoError(t, err)

			err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, skIndex, nil, 0, types.ExpectEidNym, nil)
			assert.NoError(t, err)

			// supply correct metadata for verification
			err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs,
				rhIndex, eidIndex, skIndex, nil, 0, types.ExpectEidNym, meta)
			assert.NoError(t, err)

			// audit with AuditNymEid - it should succeed with the right nym and randomness
			err = signer.AuditNymEid(ipk, eidIndex, skIndex, sig, string(eidAttr), rNym, types.AuditExpectSignature)
			assert.NoError(t, err)

			/////////////////////
			// NymRh signature //
			/////////////////////

			sig, m, err = signer.Sign(credBytes, sk, Nym, RNmy, ipk, idemixAttrs, []byte("tome"), rhIndex, eidIndex, nil, types.EidNymRhNym, nil)
			assert.NoError(t, err)

			cb = bbs12381g2pub.NewCommitmentBuilder(2)
			cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H0, m.EidNymAuditData.Rand)
			cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H[eidIndexInBases], m.EidNymAuditData.Attr)
			assert.True(t, cb.Build().Equals(m.EidNymAuditData.Nym))

			cb = bbs12381g2pub.NewCommitmentBuilder(2)
			cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H0, m.RhNymAuditData.Rand)
			cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H[rhIndexInBases], m.RhNymAuditData.Attr)
			assert.True(t, cb.Build().Equals(m.RhNymAuditData.Nym))

			err = signer.Verify(ipk, sig, []byte("tome"), idemixAttrs, rhIndex, eidIndex, skIndex, nil, 0, types.ExpectEidNymRhNym, nil)
			assert.NoError(t, err)

			/////////////////////
			// NymRh signature // (nym supplied)
			/////////////////////

			rNym = curve.NewRandomZr(rand)

			cb = bbs12381g2pub.NewCommitmentBuilder(2)
			cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H0, rNym)
			cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H[rhIndexInBases], bbs12381g2pub.FrFromOKM(rhAttr, curve))
			nym = cb.Build()

			meta = &types.IdemixSignerMetadata{
				RhNym: nym.Bytes(),
				RhNymAuditData: &types.AttrNymAuditData{
					Nym:  nym,
					Rand: rNym,
					Attr: bbs12381g2pub.FrFromOKM(rhAttr, curve),
				},
			}

			sig, _, err = signer.Sign(credBytes, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, types.EidNymRhNym, meta)
			assert.NoError(t, err)

			err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, skIndex, nil, 0, types.ExpectEidNymRhNym, nil)
			assert.NoError(t, err)

			// supply correct metadata for verification
			err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, skIndex, nil, 0, types.ExpectEidNymRhNym, meta)
			assert.NoError(t, err)

			// audit with AuditNymEid - it should succeed with the right nym and randomness
			err = signer.AuditNymRh(ipk, rhIndex, skIndex, sig, string(rhAttr), rNym, types.AuditExpectSignature)
			assert.NoError(t, err)
		})
	}
}

func TestSigner(t *testing.T) {
	curve := math.Curves[math.BLS12_381_BBS]

	credProto := &aries.Cred{
		Bls:   bbs12381g2pub.New(curve),
		Curve: curve,
	}
	issuerProto := &aries.Issuer{curve}

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

	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, 0, nil, 0, types.Basic, nil)
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

	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, 0, nil, 0, types.ExpectEidNym, nil)
	assert.NoError(t, err)

	//////////////////////
	// eidNym signature // (nym supplied)
	//////////////////////

	rNym := curve.NewRandomZr(rand)

	cb = bbs12381g2pub.NewCommitmentBuilder(2)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H0, rNym)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H[eidIndex+1], bbs12381g2pub.FrFromOKM([]byte("nymeid"), curve))
	nym := cb.Build()

	meta := &types.IdemixSignerMetadata{
		EidNym: nym.Bytes(),
		EidNymAuditData: &types.AttrNymAuditData{
			Nym:  nym,
			Rand: rNym,
			Attr: bbs12381g2pub.FrFromOKM([]byte("nymeid"), curve),
		},
	}

	sig, _, err = signer.Sign(cred, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, types.EidNym, meta)
	assert.NoError(t, err)

	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, 0, nil, 0, types.ExpectEidNym, nil)
	assert.NoError(t, err)

	// supply correct metadata for verification
	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs,
		rhIndex, eidIndex, 0, nil, 0, types.ExpectEidNym, meta)
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
		rhIndex, eidIndex, 0, nil, 0, types.ExpectEidNym, meta)
	assert.EqualError(t, err, "signature invalid: nym eid validation failed, does not match regenerated nym eid")

	meta = &types.IdemixSignerMetadata{
		EidNym: curve.GenG1.Bytes(),
	}

	// supply wrong metadata for verification
	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs,
		rhIndex, eidIndex, 0, nil, 0, types.ExpectEidNym, meta)
	assert.EqualError(t, err, "signature invalid: nym eid validation failed, signature nym eid does not match metadata")

	meta = &types.IdemixSignerMetadata{
		EidNym: []byte("garbage"),
	}

	// supply wrong metadata for verification
	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs,
		rhIndex, eidIndex, 0, nil, 0, types.ExpectEidNym, meta)
	assert.EqualError(t, err, "signature invalid: nym eid validation failed, failed to unmarshal meta nym eid")

	meta = &types.IdemixSignerMetadata{
		EidNym: nym.Bytes(),
		EidNymAuditData: &types.AttrNymAuditData{
			Nym:  curve.GenG1.Mul(curve.NewRandomZr(rand)),
			Rand: rNym,
			Attr: bbs12381g2pub.FrFromOKM([]byte("nymeid"), curve),
		},
	}

	// supply wrong metadata for verification
	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs,
		rhIndex, eidIndex, 0, nil, 0, types.ExpectEidNym, meta)
	assert.EqualError(t, err, "signature invalid: nym eid validation failed, does not match metadata")

	// audit with AuditNymEid - it should succeed with the right nym and randomness
	err = signer.AuditNymEid(ipk, eidIndex, 0, sig, "nymeid", rNym, types.AuditExpectSignature)
	assert.NoError(t, err)

	// audit with AuditNymEid - it should fail with the wrong nym
	err = signer.AuditNymEid(ipk, eidIndex, 0, sig, "not so much the nymeid", rNym, types.AuditExpectSignature)
	assert.EqualError(t, err, "eid nym does not match")

	// audit with AuditNymEid - it should fail with the wrong randomness
	err = signer.AuditNymEid(ipk, eidIndex, 0, sig, "nymeid", curve.NewRandomZr(rand), types.AuditExpectSignature)
	assert.EqualError(t, err, "eid nym does not match")

	// audit with AuditNymEid - it should succeed with the right nym and randomness
	err = signer.AuditNymEid(ipk, eidIndex, 0, nym.Bytes(), "nymeid", rNym, types.AuditExpectEidNym)
	assert.NoError(t, err)

	// audit with AuditNymEid - it should fail with the wrong nym
	err = signer.AuditNymEid(ipk, eidIndex, 0, nym.Bytes(), "not so much the nymeid", rNym, types.AuditExpectEidNym)
	assert.EqualError(t, err, "eid nym does not match")

	// audit with AuditNymEid - it should fail with the wrong randomness
	err = signer.AuditNymEid(ipk, eidIndex, 0, nym.Bytes(), "nymeid", curve.NewRandomZr(rand), types.AuditExpectEidNym)
	assert.EqualError(t, err, "eid nym does not match")

	// audit with AuditNymEid - it should succeed with the right nym and randomness
	err = signer.AuditNymEid(ipk, eidIndex, 0, nym.Bytes(), "nymeid", rNym, types.AuditExpectEidNymRhNym)
	assert.NoError(t, err)

	// audit with AuditNymEid - it should fail with the wrong nym
	err = signer.AuditNymEid(ipk, eidIndex, 0, nym.Bytes(), "not so much the nymeid", rNym, types.AuditExpectEidNymRhNym)
	assert.EqualError(t, err, "eid nym does not match")

	// audit with AuditNymEid - it should fail with the wrong randomness
	err = signer.AuditNymEid(ipk, eidIndex, 0, nym.Bytes(), "nymeid", curve.NewRandomZr(rand), types.AuditExpectEidNymRhNym)
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
			Attr: bbs12381g2pub.FrFromOKM([]byte("nymeid"), curve),
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

	err = signer.Verify(ipk, sig, []byte("tome"), idemixAttrs, rhIndex, eidIndex, 0, nil, 0, types.ExpectEidNymRhNym, nil)
	assert.NoError(t, err)

	/////////////////////
	// NymRh signature // (nym supplied)
	/////////////////////

	rNym = curve.NewRandomZr(rand)

	cb = bbs12381g2pub.NewCommitmentBuilder(2)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H0, rNym)
	cb.Add(ipk.(*aries.IssuerPublicKey).PKwG.H[rhIndex+1], bbs12381g2pub.FrFromOKM([]byte("nymrh"), curve))
	nym = cb.Build()

	meta = &types.IdemixSignerMetadata{
		RhNym: nym.Bytes(),
		RhNymAuditData: &types.AttrNymAuditData{
			Nym:  nym,
			Rand: rNym,
			Attr: bbs12381g2pub.FrFromOKM([]byte("nymrh"), curve),
		},
	}

	sig, _, err = signer.Sign(cred, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, types.EidNymRhNym, meta)
	assert.NoError(t, err)

	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, 0, nil, 0, types.ExpectEidNymRhNym, nil)
	assert.NoError(t, err)

	// supply correct metadata for verification
	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, 0, nil, 0, types.ExpectEidNymRhNym, meta)
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
	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, 0, nil, 0, types.ExpectEidNymRhNym, meta)
	assert.EqualError(t, err, "signature invalid: nym rh validation failed, does not match regenerated nym rh")

	meta = &types.IdemixSignerMetadata{
		RhNym: curve.GenG1.Bytes(),
	}

	// supply wrong metadata for verification
	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, 0, nil, 0, types.ExpectEidNymRhNym, meta)
	assert.EqualError(t, err, "signature invalid: rh nym validation failed, signature rh nym does not match metadata")

	meta = &types.IdemixSignerMetadata{
		RhNym: []byte("garbage"),
	}

	// supply wrong metadata for verification
	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, 0, nil, 0, types.ExpectEidNymRhNym, meta)
	assert.EqualError(t, err, "signature invalid: rh nym validation failed, failed to unmarshal meta rh nym")

	meta = &types.IdemixSignerMetadata{
		RhNym: nym.Bytes(),
		RhNymAuditData: &types.AttrNymAuditData{
			Nym:  curve.GenG1.Mul(curve.NewRandomZr(rand)),
			Rand: rNym,
			Attr: bbs12381g2pub.FrFromOKM([]byte("nymrh"), curve),
		},
	}

	// supply wrong metadata for verification
	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, 0, nil, 0, types.ExpectEidNymRhNym, meta)
	assert.EqualError(t, err, "signature invalid: nym rh validation failed, does not match metadata")

	// audit with AuditNymEid - it should succeed with the right nym and randomness
	err = signer.AuditNymRh(ipk, rhIndex, 0, sig, "nymrh", rNym, types.AuditExpectSignature)
	assert.NoError(t, err)

	// audit with AuditNymEid - it should fail with the wrong nym
	err = signer.AuditNymRh(ipk, rhIndex, 0, sig, "not so much the nymrh", rNym, types.AuditExpectSignature)
	assert.EqualError(t, err, "rh nym does not match")

	// audit with AuditNymEid - it should fail with the wrong randomness
	err = signer.AuditNymRh(ipk, rhIndex, 0, sig, "nymrh", curve.NewRandomZr(rand), types.AuditExpectSignature)
	assert.EqualError(t, err, "rh nym does not match")

	// audit with AuditNymEid - it should succeed with the right nym and randomness
	err = signer.AuditNymRh(ipk, rhIndex, 0, nym.Bytes(), "nymrh", rNym, types.AuditExpectEidNymRhNym)
	assert.NoError(t, err)

	// audit with AuditNymEid - it should fail with the wrong nym
	err = signer.AuditNymRh(ipk, rhIndex, 0, nym.Bytes(), "not so much the nymrh", rNym, types.AuditExpectEidNymRhNym)
	assert.EqualError(t, err, "rh nym does not match")

	// audit with AuditNymEid - it should fail with the wrong randomness
	err = signer.AuditNymRh(ipk, rhIndex, 0, nym.Bytes(), "nymrh", curve.NewRandomZr(rand), types.AuditExpectEidNymRhNym)
	assert.EqualError(t, err, "rh nym does not match")

	// audit with AuditNymEid - it should fail with AuditExpectEidNym
	err = signer.AuditNymRh(ipk, rhIndex, 0, nym.Bytes(), "nymrh", rNym, types.AuditExpectEidNym)
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
			Attr: bbs12381g2pub.FrFromOKM([]byte("nymrh"), curve),
		},
	}

	_, _, err = signer.Sign(cred, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, types.EidNymRhNym, meta)
	assert.EqualError(t, err, "nym supplied in metadata cannot be recomputed")

	//////////////////////
	// eidNym signature // (eidNym missing but expected)
	//////////////////////

	sig, _, err = signer.Sign(cred, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, types.Standard, nil)
	assert.NoError(t, err)

	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, 0, nil, 0, types.ExpectEidNym, nil)
	assert.EqualError(t, err, "no EidNym provided but ExpectEidNym required")

	/////////////////////
	// rhNym signature // (rhNym missing but expected)
	/////////////////////

	sig, _, err = signer.Sign(cred, sk, Nym, RNmy, ipk, idemixAttrs, []byte("silliness"), rhIndex, eidIndex, nil, types.EidNym, nil)
	assert.NoError(t, err)

	err = signer.Verify(ipk, sig, []byte("silliness"), idemixAttrs, rhIndex, eidIndex, 0, nil, 0, types.ExpectEidNymRhNym, nil)
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
