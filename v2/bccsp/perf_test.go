/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package idemix_test

import (
	"crypto/rand"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/IBM/idemix/bccsp/schemes/aries"
	bccsp "github.com/IBM/idemix/bccsp/types"
	imsp "github.com/IBM/idemix/v2"
	idemix "github.com/IBM/idemix/v2/bccsp"
	"github.com/IBM/idemix/v2/bccsp/schemes/dlog/crypto/translator/amcl"
	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/assert"
)

func setupAries(b *testing.B) (bccsp.BCCSP, bccsp.Key, bccsp.Key, bccsp.Key, []byte) {
	curve := math.Curves[math.BLS12_381_BBS]
	translator := &amcl.Gurvy{C: curve}

	CSP, err := idemix.NewAries(NewDummyKeyStore(), curve, translator, true)
	assert.NoError(b, err)

	AttributeNames := []string{imsp.AttributeNameOU, imsp.AttributeNameRole, imsp.AttributeNameEnrollmentId, imsp.AttributeNameRevocationHandle}
	IssuerKey, err := CSP.KeyGen(&bccsp.IdemixIssuerKeyGenOpts{Temporary: true, AttributeNames: AttributeNames})
	assert.NoError(b, err)
	IssuerPublicKey, err := IssuerKey.PublicKey()
	assert.NoError(b, err)

	UserKey, err := CSP.KeyGen(&bccsp.IdemixUserSecretKeyGenOpts{Temporary: true})
	assert.NoError(b, err)

	IssuerNonce := make([]byte, curve.ScalarByteSize)
	n, err := rand.Read(IssuerNonce)
	assert.NoError(b, err)
	assert.Equal(b, curve.ScalarByteSize, n)

	blindCredReqOpts := &bccsp.IdemixBlindCredentialRequestSignerOpts{IssuerPK: IssuerPublicKey, IssuerNonce: IssuerNonce}
	credRequest, err := CSP.Sign(
		UserKey,
		nil,
		blindCredReqOpts,
	)
	assert.NoError(b, err)

	credential, err := CSP.Sign(
		IssuerKey,
		credRequest,
		&bccsp.IdemixCredentialSignerOpts{
			Attributes: []bccsp.IdemixAttribute{
				{Type: bccsp.IdemixBytesAttribute, Value: []byte{0}},
				{Type: bccsp.IdemixBytesAttribute, Value: []byte{0, 1}},
				{Type: bccsp.IdemixIntAttribute, Value: 1},
				{Type: bccsp.IdemixBytesAttribute, Value: []byte{0, 1, 2}},
			},
		},
	)
	assert.NoError(b, err)

	cr := &aries.CredRequest{
		Curve: curve,
	}

	credential, err = cr.Unblind(credential, blindCredReqOpts.Blinding)
	assert.NoError(b, err)

	valid, err := CSP.Verify(
		IssuerPublicKey,
		credRequest,
		nil,
		&bccsp.IdemixBlindCredentialRequestSignerOpts{IssuerNonce: IssuerNonce},
	)
	assert.NoError(b, err)
	assert.True(b, valid)

	valid, err = CSP.Verify(
		UserKey,
		credential,
		nil,
		&bccsp.IdemixCredentialSignerOpts{
			IssuerPK: IssuerPublicKey,
			Attributes: []bccsp.IdemixAttribute{
				{Type: bccsp.IdemixBytesAttribute, Value: []byte{0}},
				{Type: bccsp.IdemixBytesAttribute, Value: []byte{0, 1}},
				{Type: bccsp.IdemixIntAttribute, Value: 1},
				{Type: bccsp.IdemixBytesAttribute, Value: []byte{0, 1, 2}},
			},
		},
	)
	assert.NoError(b, err)
	assert.True(b, valid)

	NymKey, err := CSP.KeyDeriv(UserKey, &bccsp.IdemixNymKeyDerivationOpts{Temporary: true, IssuerPK: IssuerPublicKey})
	assert.NoError(b, err)

	return CSP, IssuerPublicKey, UserKey, NymKey, credential
}

func setupLegacy(b *testing.B) (bccsp.BCCSP, bccsp.Key, bccsp.Key, bccsp.Key, []byte) {
	curve := math.Curves[math.BLS12_381_BBS]
	translator := &amcl.Gurvy{C: curve}

	CSP, err := idemix.New(NewDummyKeyStore(), curve, translator, true)
	assert.NoError(b, err)

	AttributeNames := []string{imsp.AttributeNameOU, imsp.AttributeNameRole, imsp.AttributeNameEnrollmentId, imsp.AttributeNameRevocationHandle}
	IssuerKey, err := CSP.KeyGen(&bccsp.IdemixIssuerKeyGenOpts{Temporary: true, AttributeNames: AttributeNames})
	assert.NoError(b, err)
	IssuerPublicKey, err := IssuerKey.PublicKey()
	assert.NoError(b, err)

	UserKey, err := CSP.KeyGen(&bccsp.IdemixUserSecretKeyGenOpts{Temporary: true})
	assert.NoError(b, err)

	IssuerNonce := make([]byte, curve.ScalarByteSize)
	n, err := rand.Read(IssuerNonce)
	assert.NoError(b, err)
	assert.Equal(b, curve.ScalarByteSize, n)

	// Credential Request for User
	credRequest, err := CSP.Sign(
		UserKey,
		nil,
		&bccsp.IdemixCredentialRequestSignerOpts{IssuerPK: IssuerPublicKey, IssuerNonce: IssuerNonce},
	)
	assert.NoError(b, err)

	// Credential
	credential, err := CSP.Sign(
		IssuerKey,
		credRequest,
		&bccsp.IdemixCredentialSignerOpts{
			Attributes: []bccsp.IdemixAttribute{
				{Type: bccsp.IdemixBytesAttribute, Value: []byte{0}},
				{Type: bccsp.IdemixBytesAttribute, Value: []byte{0, 1}},
				{Type: bccsp.IdemixIntAttribute, Value: 1},
				{Type: bccsp.IdemixBytesAttribute, Value: []byte{0, 1, 2}},
			},
		},
	)
	assert.NoError(b, err)

	valid, err := CSP.Verify(
		IssuerPublicKey,
		credRequest,
		nil,
		&bccsp.IdemixCredentialRequestSignerOpts{IssuerNonce: IssuerNonce},
	)
	assert.NoError(b, err)
	assert.True(b, valid)

	valid, err = CSP.Verify(
		UserKey,
		credential,
		nil,
		&bccsp.IdemixCredentialSignerOpts{
			IssuerPK: IssuerPublicKey,
			Attributes: []bccsp.IdemixAttribute{
				{Type: bccsp.IdemixBytesAttribute, Value: []byte{0}},
				{Type: bccsp.IdemixBytesAttribute, Value: []byte{0, 1}},
				{Type: bccsp.IdemixIntAttribute, Value: 1},
				{Type: bccsp.IdemixBytesAttribute, Value: []byte{0, 1, 2}},
			},
		},
	)
	assert.NoError(b, err)
	assert.True(b, valid)

	NymKey, err := CSP.KeyDeriv(UserKey, &bccsp.IdemixNymKeyDerivationOpts{Temporary: true, IssuerPK: IssuerPublicKey})
	assert.NoError(b, err)

	return CSP, IssuerPublicKey, UserKey, NymKey, credential
}

func stackNameFromSetupFnName(fname string) string {
	if strings.Contains(fname, "Aries") {
		return "aries"
	}

	if strings.Contains(fname, "Legacy") {
		return "legacy"
	}

	panic("programming error")
}

func Benchmark_SignVerify(b *testing.B) {

	setups := []func(b *testing.B) (bccsp.BCCSP, bccsp.Key, bccsp.Key, bccsp.Key, []byte){
		setupLegacy,
		setupAries,
	}

	for _, setupFn := range setups {

		CSP, IssuerPublicKey, UserKey, NymKey, credential := setupFn(b)

		b.ResetTimer()

		b.Run(fmt.Sprintf("sign-%s", stackNameFromSetupFnName(runtime.FuncForPC(reflect.ValueOf(setupFn).Pointer()).Name())), func(b *testing.B) {
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					signOpts := &bccsp.IdemixSignerOpts{
						Credential: credential,
						Nym:        NymKey,
						IssuerPK:   IssuerPublicKey,
						Attributes: []bccsp.IdemixAttribute{
							{Type: bccsp.IdemixHiddenAttribute},
							{Type: bccsp.IdemixHiddenAttribute},
							{Type: bccsp.IdemixHiddenAttribute},
							{Type: bccsp.IdemixHiddenAttribute},
						},
						RhIndex:  3,
						EidIndex: 2,
						Epoch:    0,
						SigType:  bccsp.EidNymRhNym,
					}

					signature, err := CSP.Sign(
						UserKey,
						nil,
						signOpts,
					)
					assert.NoError(b, err)

					_ = signature
				}
			})
		})

		RevocationKey, err := CSP.KeyGen(&bccsp.IdemixRevocationKeyGenOpts{Temporary: true})
		assert.NoError(b, err)

		cri, err := CSP.Sign(
			RevocationKey,
			nil,
			&bccsp.IdemixCRISignerOpts{},
		)
		assert.NoError(b, err)

		signOpts := &bccsp.IdemixSignerOpts{
			Credential: credential,
			Nym:        NymKey,
			IssuerPK:   IssuerPublicKey,
			Attributes: []bccsp.IdemixAttribute{
				{Type: bccsp.IdemixHiddenAttribute},
				{Type: bccsp.IdemixHiddenAttribute},
				{Type: bccsp.IdemixHiddenAttribute},
				{Type: bccsp.IdemixHiddenAttribute},
			},
			RhIndex:  3,
			EidIndex: 2,
			Epoch:    0,
			SigType:  bccsp.EidNymRhNym,
			CRI:      cri,
		}

		signature, err := CSP.Sign(
			UserKey,
			nil,
			signOpts,
		)
		assert.NoError(b, err)

		b.ResetTimer()

		b.Run(fmt.Sprintf("verify-%s", stackNameFromSetupFnName(runtime.FuncForPC(reflect.ValueOf(setupFn).Pointer()).Name())), func(b *testing.B) {
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					valid, err := CSP.Verify(
						IssuerPublicKey,
						signature,
						nil,
						&bccsp.IdemixSignerOpts{
							Attributes: []bccsp.IdemixAttribute{
								{Type: bccsp.IdemixHiddenAttribute},
								{Type: bccsp.IdemixHiddenAttribute},
								{Type: bccsp.IdemixHiddenAttribute},
								{Type: bccsp.IdemixHiddenAttribute},
							},
							RhIndex:          3,
							EidIndex:         2,
							Epoch:            0,
							VerificationType: bccsp.ExpectEidNymRhNym,
							Metadata:         signOpts.Metadata,
						},
					)
					assert.NoError(b, err)
					assert.True(b, valid)
				}
			})
		})
	}
}
