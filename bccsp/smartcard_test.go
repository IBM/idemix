/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix_test

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	idemix "github.com/IBM/idemix/bccsp"
	"github.com/IBM/idemix/bccsp/handlers"
	"github.com/IBM/idemix/bccsp/schemes/aries"
	"github.com/IBM/idemix/bccsp/schemes/dlog/crypto/translator/amcl"
	"github.com/IBM/idemix/bccsp/types"
	"github.com/IBM/idemix/idemixmsp"
	math "github.com/IBM/mathlib"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/aries-bbs-go/bbs"
	"github.com/stretchr/testify/assert"
)

func getSmartcard(t *testing.T) (*aries.Smartcard, *math.Curve) {
	c := math.Curves[math.FP256BN_AMCL_MIRACL]

	rng, err := c.Rand()
	assert.NoError(t, err)

	k0, err := hex.DecodeString("4669650c993c43ef45742c3aa8aeb842")
	assert.NoError(t, err)
	k1, err := hex.DecodeString("358abd275e6a945d680d40474f5f16c7")
	assert.NoError(t, err)

	ciph0, err := aes.NewCipher(k0)
	assert.NoError(t, err)
	ciph1, err := aes.NewCipher(k1)
	assert.NoError(t, err)

	h0Bytes, err := hex.DecodeString("0441c48875b5045400ce6bb4ce5b9c733f6d539a89f1ec2c24e0e04f56932c52ffd918f0679996b017363c591df413e1ac0be63e919defd6edc0686d41b1fcd68d")
	assert.NoError(t, err)
	h0, err := c.NewG1FromBytes(h0Bytes)
	assert.NoError(t, err)

	h1Bytes, err := hex.DecodeString("041e304080e9afd0d04317d12b5cb058cd4f322a1cddb71e64a47528353d51f7a8324fce4698dff52cd8d4c7dd2c8c94c6fba8ce12493d182e4d849106dc5c46de")
	assert.NoError(t, err)
	h1, err := c.NewG1FromBytes(h1Bytes)
	assert.NoError(t, err)

	h2Bytes, err := hex.DecodeString("04196c48c6d0249de961b97433a577da537c341ad0ea0cde4dfa40ef6bab9b59f274a07a3665518401119957a52a32a18256d7215e4f1d0ce6c9e2646d939c07f9")
	assert.NoError(t, err)
	h2, err := c.NewG1FromBytes(h2Bytes)
	assert.NoError(t, err)

	eidBytes, err := hex.DecodeString("003522e297a5f7db7521e23d9f9b87378126acd80429cf4ec07344f06bd9f7d5")
	assert.NoError(t, err)
	eid := c.NewZrFromBytes(eidBytes)

	skBytes, err := hex.DecodeString("00f022e297a5f7db7521e23d9f9b87378182acd80429cf4ec07344f06bd9f7d5")
	assert.NoError(t, err)
	sk := c.NewZrFromBytes(skBytes)

	return &aries.Smartcard{
		H0:     h0,
		H1:     h1,
		H2:     h2,
		Uid_sk: sk,
		EID:    eid,
		PRF_K0: ciph0,
		PRF_K1: ciph1,
		Curve:  c,
		Rng:    rng,
	}, c
}

func readFile(t *testing.T, name string) []byte {
	bytes, err := os.ReadFile(name)
	assert.NoError(t, err)

	return bytes
}

func TestSmartcardHybrid(t *testing.T) {
	sc, curve := getSmartcard(t)
	translator := &amcl.Gurvy{C: curve}

	/*******************************************************************************/
	/****************************read out idemix config*****************************/
	/*******************************************************************************/

	issuer := &aries.Issuer{Curve: curve}

	_ipk, err := issuer.NewPublicKeyFromBytes(readFile(t, "testdata/idemix/msp/IssuerPublicKey"), []string{"", "", "", ""})
	assert.NoError(t, err)

	conf := &idemixmsp.IdemixMSPSignerConfig{}
	err = proto.Unmarshal(readFile(t, "testdata/idemix/user/SignerConfig"), conf)
	assert.NoError(t, err)

	/*******************************************************************************/
	/*****************instantiate an idemix bccsp and import ipk********************/
	/*******************************************************************************/

	CSP, err := idemix.NewAries(NewDummyKeyStore(), curve, translator, true)
	assert.NoError(t, err)

	IssuerPublicKey, err := CSP.KeyImport(readFile(t, "testdata/idemix/msp/IssuerPublicKey"), &types.IdemixIssuerPublicKeyImportOpts{Temporary: true, AttributeNames: []string{"", "", "", ""}})
	assert.NoError(t, err)

	/*******************************************************************************/
	/**************configure the smartcard to work with these creds*****************/
	/*******************************************************************************/

	ipk := _ipk.(*aries.IssuerPublicKey)
	sc.H0 = ipk.PKwG.H0
	sc.H1 = ipk.PKwG.H[0]
	sc.H2 = ipk.PKwG.H[3]
	sc.EID = bbs.FrFromOKM([]byte(conf.EnrollmentId), curve)
	sc.Uid_sk = curve.NewZrFromBytes(conf.Sk)

	/*******************************************************************************/
	/**************************NYM SIGNATURE****************************************/
	/*******************************************************************************/

	scIdmx := &aries.SmartcardIdemixBackend{Curve: curve}

	msg := []byte("msg")
	rNymEid, nymEid := sc.NymEid()

	/*****sign low-level*****/

	sig, nym, rNym, err := scIdmx.Sign(sc, ipk, msg)
	assert.NoError(t, err)

	/*****verify with csp*****/

	valid, err := CSP.Verify(handlers.NewNymPublicKey(nil, nil), sig, msg, &types.IdemixNymSignerOpts{
		IssuerPK:    IssuerPublicKey,
		IsSmartcard: true,
		NymEid:      nymEid,
	})
	assert.NoError(t, err)
	assert.True(t, valid)

	/*******************************************************************************/
	/**************************IDEMIX SIGNATURE*************************************/
	/*******************************************************************************/

	rhIndex, eidIndex := 3, 2

	idemixAttrs := []types.IdemixAttribute{
		{
			Type:  types.IdemixBytesAttribute,
			Value: []byte(conf.OrganizationalUnitIdentifier),
		},
		{
			Type:  types.IdemixIntAttribute,
			Value: int(conf.Role),
		},
		{
			Type: types.IdemixHiddenAttribute,
		},
		{
			Type: types.IdemixHiddenAttribute,
		},
	}

	meta := &types.IdemixSignerMetadata{
		EidNym: nymEid.Bytes(),
		EidNymAuditData: &types.AttrNymAuditData{
			Nym:  nymEid,
			Rand: rNymEid,
			Attr: bbs.FrFromOKM([]byte(conf.EnrollmentId), curve),
		},
	}

	signer := &aries.Signer{
		Curve: sc.Curve,
		Rng:   rand.Reader,
	}

	/*****sign low-level*****/

	sig, _, err = signer.Sign(conf.Cred, nil, nym, rNym, ipk, idemixAttrs, nil, rhIndex, eidIndex, nil, types.Smartcard, meta)
	assert.NoError(t, err)

	/*****verify with csp*****/

	valid, err = CSP.Verify(
		IssuerPublicKey,
		sig,
		nil,
		&types.IdemixSignerOpts{
			Attributes:       idemixAttrs,
			RhIndex:          3,
			EidIndex:         2,
			VerificationType: types.ExpectSmartcard,
			Metadata: &types.IdemixSignerMetadata{
				EidNym: nymEid.Bytes(),
			},
		},
	)
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestSmartcardCSP(t *testing.T) {
	sc, curve := getSmartcard(t)
	translator := &amcl.Gurvy{C: curve}

	/*******************************************************************************/
	/****************************read out idemix config*****************************/
	/*******************************************************************************/

	issuer := &aries.Issuer{Curve: curve}

	_ipk, err := issuer.NewPublicKeyFromBytes(readFile(t, "testdata/idemix/msp/IssuerPublicKey"), []string{"", "", "", ""})
	assert.NoError(t, err)

	conf := &idemixmsp.IdemixMSPSignerConfig{}
	err = proto.Unmarshal(readFile(t, "testdata/idemix/user/SignerConfig"), conf)
	assert.NoError(t, err)

	/*******************************************************************************/
	/*****************instantiate an idemix bccsp and import ipk********************/
	/*******************************************************************************/

	CSP, err := idemix.NewAries(NewDummyKeyStore(), curve, translator, true)
	assert.NoError(t, err)

	IssuerPublicKey, err := CSP.KeyImport(readFile(t, "testdata/idemix/msp/IssuerPublicKey"), &types.IdemixIssuerPublicKeyImportOpts{Temporary: true, AttributeNames: []string{"", "", "", ""}})
	assert.NoError(t, err)

	/*******************************************************************************/
	/**************configure the smartcard to work with these creds*****************/
	/*******************************************************************************/

	ipk := _ipk.(*aries.IssuerPublicKey)
	sc.H0 = ipk.PKwG.H0
	sc.H1 = ipk.PKwG.H[0]
	sc.H2 = ipk.PKwG.H[3]
	sc.EID = bbs.FrFromOKM([]byte(conf.EnrollmentId), curve)
	sc.Uid_sk = curve.NewZrFromBytes(conf.Sk)

	/*******************************************************************************/
	/**************************NYM SIGNATURE****************************************/
	/*******************************************************************************/

	msg := []byte("msg")
	rNymEid, nymEid := sc.NymEid()

	/*****sign*****/

	opts := &types.IdemixNymSignerOpts{
		IssuerPK:    IssuerPublicKey,
		IsSmartcard: true,
		Smartcard:   sc,
	}

	sig, err := CSP.Sign(handlers.NewUserSecretKey(nil, true), msg, opts)
	assert.NoError(t, err)

	/*****verify*****/

	valid, err := CSP.Verify(handlers.NewNymPublicKey(nil, nil), sig, msg, &types.IdemixNymSignerOpts{
		IssuerPK:    IssuerPublicKey,
		IsSmartcard: true,
		NymEid:      nymEid,
	})
	assert.NoError(t, err)
	assert.True(t, valid)

	/*******************************************************************************/
	/**************************IDEMIX SIGNATURE*************************************/
	/*******************************************************************************/

	/*****sign*****/

	nymsk, err := handlers.NewNymSecretKey(opts.RNym, opts.NymG1, translator, true)
	assert.NoError(t, err)

	signOpts := &types.IdemixSignerOpts{
		Credential: conf.Cred,
		Nym:        nymsk,
		IssuerPK:   IssuerPublicKey,
		Attributes: []types.IdemixAttribute{
			{
				Type:  types.IdemixBytesAttribute,
				Value: []byte(conf.OrganizationalUnitIdentifier),
			},
			{
				Type:  types.IdemixIntAttribute,
				Value: int(conf.Role),
			},
			{Type: types.IdemixHiddenAttribute},
			{Type: types.IdemixHiddenAttribute},
		},
		RhIndex:  3,
		EidIndex: 2,
		SigType:  types.Smartcard,
		Metadata: &types.IdemixSignerMetadata{
			EidNym: nymEid.Bytes(),
			EidNymAuditData: &types.AttrNymAuditData{
				Nym:  nymEid,
				Rand: rNymEid,
				Attr: bbs.FrFromOKM([]byte(conf.EnrollmentId), curve),
			},
		},
	}

	signature, err := CSP.Sign(
		handlers.NewUserSecretKey(nil, false),
		nil,
		signOpts,
	)
	assert.NoError(t, err)

	/*****verify*****/

	valid, err = CSP.Verify(
		IssuerPublicKey,
		signature,
		nil,
		&types.IdemixSignerOpts{
			Attributes: []types.IdemixAttribute{
				{
					Type:  types.IdemixBytesAttribute,
					Value: []byte(conf.OrganizationalUnitIdentifier),
				},
				{
					Type:  types.IdemixIntAttribute,
					Value: int(conf.Role),
				},
				{Type: types.IdemixHiddenAttribute},
				{Type: types.IdemixHiddenAttribute},
			},
			RhIndex:          3,
			EidIndex:         2,
			VerificationType: types.ExpectSmartcard,
			Metadata: &types.IdemixSignerMetadata{
				EidNym: nymEid.Bytes(),
			},
		},
	)
	assert.NoError(t, err)
	assert.True(t, valid)

	/*******************************************************************************/

	/*****sign*****/

	nymsk, err = handlers.NewNymSecretKey(opts.RNym, opts.NymG1, translator, true)
	assert.NoError(t, err)

	signOpts = &types.IdemixSignerOpts{
		Credential: conf.Cred,
		Nym:        nymsk,
		IssuerPK:   IssuerPublicKey,
		Attributes: []types.IdemixAttribute{
			{Type: types.IdemixHiddenAttribute},
			{Type: types.IdemixHiddenAttribute},
			{Type: types.IdemixHiddenAttribute},
			{Type: types.IdemixHiddenAttribute},
		},
		RhIndex:  3,
		EidIndex: 2,
		SigType:  types.Smartcard,
		Metadata: &types.IdemixSignerMetadata{
			EidNym: nymEid.Bytes(),
			EidNymAuditData: &types.AttrNymAuditData{
				Nym:  nymEid,
				Rand: rNymEid,
				Attr: bbs.FrFromOKM([]byte(conf.EnrollmentId), curve),
			},
		},
	}

	signature, err = CSP.Sign(
		handlers.NewUserSecretKey(nil, false),
		nil,
		signOpts,
	)
	assert.NoError(t, err)

	/*****verify*****/

	valid, err = CSP.Verify(
		IssuerPublicKey,
		signature,
		nil,
		&types.IdemixSignerOpts{
			Attributes: []types.IdemixAttribute{
				{Type: types.IdemixHiddenAttribute},
				{Type: types.IdemixHiddenAttribute},
				{Type: types.IdemixHiddenAttribute},
				{Type: types.IdemixHiddenAttribute},
			},
			RhIndex:          3,
			EidIndex:         2,
			VerificationType: types.ExpectSmartcard,
			Metadata: &types.IdemixSignerMetadata{
				EidNym: nymEid.Bytes(),
			},
		},
	)
	assert.NoError(t, err)
	assert.True(t, valid)

	/*******************************************************************************/
	/***********************low-level invocation************************************/
	/*******************************************************************************/

	rhIndex, eidIndex := 3, 2

	idemixAttrs := []types.IdemixAttribute{
		{
			Type: types.IdemixHiddenAttribute,
		},
		{
			Type:  types.IdemixIntAttribute,
			Value: int(conf.Role),
		},
		{
			Type: types.IdemixHiddenAttribute,
		},
		{
			Type: types.IdemixHiddenAttribute,
		},
	}

	meta := &types.IdemixSignerMetadata{
		EidNym: nymEid.Bytes(),
		EidNymAuditData: &types.AttrNymAuditData{
			Nym:  nymEid,
			Rand: rNymEid,
			Attr: bbs.FrFromOKM([]byte(conf.EnrollmentId), curve),
		},
	}

	rand, err := sc.Curve.Rand()
	assert.NoError(t, err)

	signer := &aries.Signer{
		Curve: sc.Curve,
		Rng:   rand,
	}

	/*****sign*****/

	sig, _, err = signer.Sign(conf.Cred, nil, opts.NymG1, opts.RNym, ipk, idemixAttrs, nil, rhIndex, eidIndex, nil, types.Smartcard, meta)
	assert.NoError(t, err)

	rng, err := curve.Rand()
	assert.NoError(t, err)

	/*****verify*****/

	verifier := &aries.Signer{
		Curve: curve,
		Rng:   rng,
	}
	err = verifier.Verify(ipk, sig, nil, []types.IdemixAttribute{
		{
			Type: types.IdemixHiddenAttribute,
		},
		{
			Type:  types.IdemixIntAttribute,
			Value: int(conf.Role),
		},
		{
			Type: types.IdemixHiddenAttribute,
		},
		{
			Type: types.IdemixHiddenAttribute,
		},
	}, 3, 2, 0, nil, -1, types.ExpectSmartcard, &types.IdemixSignerMetadata{EidNym: nymEid.Bytes()})
	assert.NoError(t, err)

	/*******************************************************************************/
	/*******************************************************************************/
}
