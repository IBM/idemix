/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package idemix_test

import (
	"testing"

	idemix "github.com/IBM/idemix/bccsp"
	"github.com/IBM/idemix/bccsp/schemes/dlog/crypto/translator/amcl"
	bccsp "github.com/IBM/idemix/bccsp/types"
	math "github.com/IBM/mathlib"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
)

func TestPlain(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Plain Suite")
}

func TestRevocationKeyExportImport(t *testing.T) {
	curve := math.Curves[math.FP256BN_AMCL]
	translator := &amcl.Fp256bn{C: curve}

	var err error
	CSP, err := idemix.New(NewDummyKeyStore(), curve, translator, true)
	assert.NoError(t, err)

	RevocationPrivateKey, err := CSP.KeyGen(&bccsp.IdemixRevocationKeyGenOpts{Temporary: true})
	assert.NoError(t, err)

	RevocationPublicKey, err := RevocationPrivateKey.PublicKey()
	assert.NoError(t, err)

	RevocationPublicKeyBytes, err := RevocationPublicKey.Bytes()
	assert.NoError(t, err)

	_, err = CSP.KeyImport(RevocationPublicKeyBytes, &bccsp.IdemixRevocationPublicKeyImportOpts{Temporary: true})
	assert.NoError(t, err)
}
