/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"testing"

	bccsp "github.com/IBM/idemix/bccsp/schemes"
	im "github.com/IBM/idemix/idemixmsp"
	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/assert"
)

func TestAudit(t *testing.T) {
	msp, err := NewIdemixMsp(MSPv1_3)
	assert.NoError(t, err)

	conf, err := GetIdemixMspConfig("testdata/idemix/MSP1OU1", "MSP1OU1")
	assert.NoError(t, err)

	err = msp.Setup(conf)
	assert.NoError(t, err)

	id, err := msp.GetDefaultSigningIdentity()
	assert.NoError(t, err)

	idemixSigner := id.(*IdemixSigningIdentity)

	config := &im.IdemixMSPConfig{}
	err = proto.Unmarshal(conf.Config, config)
	assert.NoError(t, err)

	idemixMsp := msp.(*Idemixmsp)
	csp := idemixMsp.csp

	msg := []byte("Lost forever, now and ever\nTo this magical sound that I hear")

	// STEP 1: Sign and Verify normally

	signature, err := csp.Sign(
		idemixSigner.UserKey,
		msg,
		&bccsp.IdemixSignerOpts{
			Credential: idemixSigner.Cred,
			Nym:        idemixSigner.NymKey,
			IssuerPK:   idemixMsp.ipk,
			Attributes: []bccsp.IdemixAttribute{
				{Type: bccsp.IdemixHiddenAttribute},
				{Type: bccsp.IdemixHiddenAttribute},
				{Type: bccsp.IdemixHiddenAttribute},
				{Type: bccsp.IdemixHiddenAttribute},
			},
			RhIndex:  AttributeIndexRevocationHandle,
			EidIndex: AttributeIndexEnrollmentId,
			Epoch:    0,
			CRI:      config.Signer.CredentialRevocationInformation,
		},
	)
	assert.NoError(t, err)

	valid, err := csp.Verify(
		idemixMsp.ipk,
		signature,
		msg,
		&bccsp.IdemixSignerOpts{
			RevocationPublicKey: idemixMsp.revocationPK,
			Attributes: []bccsp.IdemixAttribute{
				{Type: bccsp.IdemixHiddenAttribute},
				{Type: bccsp.IdemixHiddenAttribute},
				{Type: bccsp.IdemixHiddenAttribute},
				{Type: bccsp.IdemixHiddenAttribute},
			},
			RhIndex:          AttributeIndexRevocationHandle,
			EidIndex:         AttributeIndexEnrollmentId,
			Epoch:            0,
			VerificationType: bccsp.BestEffort,
		},
	)
	assert.NoError(t, err)
	assert.True(t, valid)

	// STEP 2: Sign by also generating a commitment to the EID (and Verify)

	sOpts := &bccsp.IdemixSignerOpts{
		SigType:    bccsp.EidNym,
		Credential: idemixSigner.Cred,
		Nym:        idemixSigner.NymKey,
		IssuerPK:   idemixMsp.ipk,
		Attributes: []bccsp.IdemixAttribute{
			{Type: bccsp.IdemixHiddenAttribute},
			{Type: bccsp.IdemixHiddenAttribute},
			{Type: bccsp.IdemixHiddenAttribute},
			{Type: bccsp.IdemixHiddenAttribute},
		},
		RhIndex:  AttributeIndexRevocationHandle,
		EidIndex: AttributeIndexEnrollmentId,
		Epoch:    0,
		CRI:      config.Signer.CredentialRevocationInformation,
	}

	signature, err = csp.Sign(
		idemixSigner.UserKey,
		msg,
		sOpts,
	)
	assert.NoError(t, err)

	valid, err = csp.Verify(
		idemixMsp.ipk,
		signature,
		msg,
		&bccsp.IdemixSignerOpts{
			RevocationPublicKey: idemixMsp.revocationPK,
			Attributes: []bccsp.IdemixAttribute{
				{Type: bccsp.IdemixHiddenAttribute},
				{Type: bccsp.IdemixHiddenAttribute},
				{Type: bccsp.IdemixHiddenAttribute},
				{Type: bccsp.IdemixHiddenAttribute},
			},
			RhIndex:          AttributeIndexRevocationHandle,
			EidIndex:         AttributeIndexEnrollmentId,
			Epoch:            0,
			VerificationType: bccsp.ExpectEidNym,
		},
	)
	assert.NoError(t, err)
	assert.True(t, valid)

	// STEP 3: audit of the nym eid
	valid, err = csp.Verify(
		idemixMsp.ipk,
		signature,
		msg,
		&bccsp.EidNymAuditOpts{
			EidIndex:     AttributeIndexEnrollmentId,
			EnrollmentID: config.Signer.EnrollmentId,
			RNymEid:      sOpts.Metadata.EidNymAuditData.Rand,
		},
	)
	assert.NoError(t, err)
	assert.True(t, valid)
}
