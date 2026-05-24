/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs_test

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"

	ml "github.com/IBM/mathlib"
	"github.com/btcsuite/btcutil/base58"
	"github.com/IBM/idemix/bbs"
	"github.com/stretchr/testify/require"
)

func TestGenerateKeyPair(t *testing.T) {
	h := sha256.New

	seed := make([]byte, 32)

	for i, curve := range ml.Curves {
		t.Run(fmt.Sprintf("with curve %s", ml.CurveIDToString(ml.CurveID(i))), func(t *testing.T) {
			bl := bbs.NewBBSLib(curve)
			pubKey, privKey, err := bl.GenerateKeyPair(h, seed)
			require.NoError(t, err)
			require.NotNil(t, pubKey)
			require.NotNil(t, privKey)

			// use random seed
			pubKey, privKey, err = bl.GenerateKeyPair(h, nil)
			require.NoError(t, err)
			require.NotNil(t, pubKey)
			require.NotNil(t, privKey)

			// invalid size of seed
			pubKey, privKey, err = bl.GenerateKeyPair(h, make([]byte, 31))
			require.Error(t, err)
			require.EqualError(t, err, "invalid size of seed")
			require.Nil(t, pubKey)
			require.Nil(t, privKey)
		})
	}
}

func TestPrivateKey_Marshal(t *testing.T) {
	for i, curve := range ml.Curves {
		t.Run(fmt.Sprintf("with curve %s", ml.CurveIDToString(ml.CurveID(i))), func(t *testing.T) {

			_, privKey, err := generateKeyPairRandom(curve)
			require.NoError(t, err)

			privKeyBytes, err := privKey.Marshal()
			require.NoError(t, err)
			require.NotNil(t, privKeyBytes)

			bl := bbs.NewBBSLib(curve)
			privKeyUnmarshalled, err := bl.UnmarshalPrivateKey(privKeyBytes)
			require.NoError(t, err)
			require.NotNil(t, privKeyUnmarshalled)
			require.Equal(t, privKey, privKeyUnmarshalled)
		})
	}
}

func TestPrivateKey_PublicKey(t *testing.T) {
	for i, curve := range ml.Curves {
		t.Run(fmt.Sprintf("with curve %s", ml.CurveIDToString(ml.CurveID(i))), func(t *testing.T) {

			pubKey, privKey, err := generateKeyPairRandom(curve)
			require.NoError(t, err)

			require.Equal(t, pubKey, privKey.PublicKey())
		})
	}
}

func TestPublicKey_Marshal(t *testing.T) {
	for i, curve := range ml.Curves {
		t.Run(fmt.Sprintf("with curve %s", ml.CurveIDToString(ml.CurveID(i))), func(t *testing.T) {
			pubKey, _, err := generateKeyPairRandom(curve)
			require.NoError(t, err)

			pubKeyBytes, err := pubKey.Marshal()
			require.NoError(t, err)
			require.NotNil(t, pubKeyBytes)

			bl := bbs.NewBBSLib(curve)
			pubKeyUnmarshalled, err := bl.UnmarshalPublicKey(pubKeyBytes)
			require.NoError(t, err)
			require.NotNil(t, pubKeyUnmarshalled)
			require.True(t, pubKey.PointG2.Equals(pubKeyUnmarshalled.PointG2))
		})
	}
}

func TestParseMattrKeys(t *testing.T) {
	privKeyB58 := "5D6Pa8dSwApdnfg7EZR8WnGfvLDCZPZGsZ5Y1ELL9VDj"
	privKeyBytes := base58.Decode(privKeyB58)

	pubKeyB58 := "oqpWYKaZD9M1Kbe94BVXpr8WTdFBNZyKv48cziTiQUeuhm7sBhCABMyYG4kcMrseC68YTFFgyhiNeBKjzdKk9MiRWuLv5H4FFujQsQK2KTAtzU8qTBiZqBHMmnLF4PL7Ytu" //nolint:lll
	pubKeyBytes := base58.Decode(pubKeyB58)

	messagesBytes := [][]byte{[]byte("message1"), []byte("message2")}
	signatureBytes, err := bbs.New(ml.Curves[ml.BLS12_381_BBS]).Sign(messagesBytes, privKeyBytes)
	require.NoError(t, err)

	err = bbs.New(ml.Curves[ml.BLS12_381_BBS]).Verify(messagesBytes, signatureBytes, pubKeyBytes)
	require.NoError(t, err)
}

func generateKeyPairRandom(curve *ml.Curve) (*bbs.PublicKey, *bbs.PrivateKey, error) {
	seed := make([]byte, 32)

	_, err := rand.Read(seed)
	if err != nil {
		panic(err)
	}

	bbs := bbs.NewBBSLib(curve)

	return bbs.GenerateKeyPair(sha256.New, seed)
}
