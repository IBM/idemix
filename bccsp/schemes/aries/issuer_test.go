/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries_test

import (
	"testing"

	"github.com/IBM/idemix/bccsp/schemes/aries"
	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIssuer(t *testing.T) {
	issuer := &aries.Issuer{Curve: math.Curves[math.BLS12_381_BBS]}

	attrs := []string{
		"attr1",
		"attr2",
		"attr3",
		"attr4",
	}

	isk, err := issuer.NewKey(attrs)
	require.NoError(t, err)
	require.NotNil(t, isk)

	ipk := isk.Public()
	require.NotNil(t, ipk)

	t.Run("secret_key_roundtrip", func(t *testing.T) {
		iskBytes, err := isk.Bytes()
		require.NoError(t, err)
		require.NotNil(t, iskBytes)

		isk1, err := issuer.NewKeyFromBytes(iskBytes, attrs)
		require.NoError(t, err)
		assert.NotNil(t, isk1)
		assert.Equal(t, isk, isk1)
	})

	t.Run("public_key_roundtrip", func(t *testing.T) {
		ipkBytes, err := ipk.Bytes()
		require.NoError(t, err)
		require.NotNil(t, ipkBytes)

		ipk1, err := issuer.NewPublicKeyFromBytes(ipkBytes, attrs)
		require.NoError(t, err)
		assert.NotNil(t, ipk1)
		assert.True(t, ipk.(*aries.IssuerPublicKey).PK.PointG2.Equals(ipk1.(*aries.IssuerPublicKey).PK.PointG2))
		assert.Equal(t, ipk.(*aries.IssuerPublicKey).N, ipk1.(*aries.IssuerPublicKey).N)
	})

	t.Run("invalid_secret_key_bytes", func(t *testing.T) {
		_, err := issuer.NewKeyFromBytes([]byte("resistance is futile"), attrs)
		assert.EqualError(t, err, "UnmarshalPrivateKey failed [invalid size of private key]")
	})

	t.Run("invalid_public_key_bytes", func(t *testing.T) {
		_, err := issuer.NewPublicKeyFromBytes([]byte("resresistance is futile"), attrs)
		assert.EqualError(t, err, "UnmarshalPublicKey failed [invalid size of public key]")
	})
}
