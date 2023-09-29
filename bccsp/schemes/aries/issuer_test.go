/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries_test

import (
	"testing"

	"github.com/IBM/idemix/bccsp/schemes/aries"
	"github.com/stretchr/testify/assert"
)

func TestIssuer(t *testing.T) {
	issuer := &aries.Issuer{}

	attrs := []string{
		"attr1",
		"attr2",
		"attr3",
		"attr4",
	}

	isk, err := issuer.NewKey(attrs)
	assert.NoError(t, err)
	assert.NotNil(t, isk)

	iskBytes, err := isk.Bytes()
	assert.NoError(t, err)
	assert.NotNil(t, iskBytes)

	isk1, err := issuer.NewKeyFromBytes(iskBytes, attrs)
	assert.NoError(t, err)
	assert.NotNil(t, isk1)
	assert.Equal(t, isk, isk1)

	ipk := isk.Public()
	assert.NotNil(t, ipk)

	ipkBytes, err := ipk.Bytes()
	assert.NoError(t, err)
	assert.NotNil(t, ipkBytes)

	ipk1, err := issuer.NewPublicKeyFromBytes(ipkBytes, attrs)
	assert.NoError(t, err)
	assert.NotNil(t, ipk1)
	assert.True(t, ipk.(*aries.IssuerPublicKey).PK.PointG2.Equals(ipk1.(*aries.IssuerPublicKey).PK.PointG2))
	assert.Equal(t, ipk.(*aries.IssuerPublicKey).N, ipk1.(*aries.IssuerPublicKey).N)

	_, err = issuer.NewKeyFromBytes([]byte("resistance is futile"), attrs)
	assert.EqualError(t, err, "UnmarshalPrivateKey failed [invalid size of private key]")

	_, err = issuer.NewPublicKeyFromBytes([]byte("resresistance is futile"), attrs)
	assert.EqualError(t, err, "UnmarshalPublicKey failed [invalid size of public key]")
}
