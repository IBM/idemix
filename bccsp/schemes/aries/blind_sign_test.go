/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries_test

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/IBM/idemix/bccsp/schemes/aries"
	math "github.com/IBM/mathlib"
	ml "github.com/IBM/mathlib"
	"github.com/hyperledger/aries-bbs-go/bbs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateKeyPairRandom(curve *math.Curve) (*bbs.PublicKey, *bbs.PrivateKey, error) {
	seed := make([]byte, 32)

	_, err := rand.Read(seed)
	if err != nil {
		panic(err)
	}

	return bbs.NewBBSLib(curve).GenerateKeyPair(sha256.New, seed)
}

func TestBlindSignMessages(t *testing.T) {
	curve := math.Curves[math.BLS12_381_BBS]

	pubKey, privKey, err := generateKeyPairRandom(curve)
	require.NoError(t, err)

	pubKeyBytes, err := pubKey.Marshal()
	require.NoError(t, err)

	blindMsgCount := 2

	messagesBytes := [][]byte{
		[]byte("message1"),
		[]byte("message2"),
		[]byte("message3"),
		[]byte("message4"),
	}

	blindedMessagesBytes := [][]byte{
		[]byte("message1"),
		nil,
		nil,
		[]byte("message4"),
	}

	msgToSign := []*bbs.SignatureMessage{
		{
			FR:  bbs.FrFromOKM([]byte("message2"), curve),
			Idx: 1,
		},
		{
			FR:  bbs.FrFromOKM([]byte("message3"), curve),
			Idx: 2,
		},
	}

	blindedMessagesBitmap := []bool{
		true,
		false,
		false,
		true,
	}

	bm, err := aries.BlindMessages(blindedMessagesBytes, pubKey, blindMsgCount, []byte("nonce578"), curve)
	assert.NoError(t, err)

	S := bm.S

	bmBytes := bm.Bytes()
	bm, err = aries.ParseBlindedMessages(bmBytes, curve)
	assert.NoError(t, err)

	err = aries.VerifyBlinding(blindedMessagesBitmap, bm.C, bm.PoK, pubKey, []byte("nonce578"), curve)
	assert.NoError(t, err)

	bls := bbs.New(curve)

	privKeyBytes, err := privKey.Marshal()
	require.NoError(t, err)

	signatureBytes, err := aries.BlindSign(msgToSign, 4, bm.C, privKeyBytes, curve)
	require.NoError(t, err)
	require.NoError(t, err)
	require.NotEmpty(t, signatureBytes)
	require.Len(t, signatureBytes, 112)

	signatureBytes, err = aries.UnblindSign(signatureBytes, S, curve)
	require.NoError(t, err)
	require.NoError(t, err)
	require.NotEmpty(t, signatureBytes)
	require.Len(t, signatureBytes, 112)

	require.NoError(t, bls.Verify(messagesBytes, signatureBytes, pubKeyBytes))
}

func TestBlindSignZr(t *testing.T) {
	curve := math.Curves[math.BLS12_381_BBS]

	pubKey, privKey, err := generateKeyPairRandom(curve)
	require.NoError(t, err)

	blindMsgCount := 1

	rnd, err := ml.Curves[ml.BLS12_381_BBS].Rand()
	require.NoError(t, err)
	zr := ml.Curves[ml.BLS12_381_BBS].NewRandomZr(rnd)

	blindedMessagesZr := []*ml.Zr{
		zr,
		nil,
	}

	msgToSign := []*bbs.SignatureMessage{
		{
			FR:  bbs.FrFromOKM([]byte("message2"), curve),
			Idx: 1,
		},
	}

	blindedMessagesBitmap := []bool{
		true,
		false,
	}

	bm, err := aries.BlindMessagesZr(blindedMessagesZr, pubKey, blindMsgCount, []byte("nonce23423"), curve)
	assert.NoError(t, err)

	err = aries.VerifyBlinding(blindedMessagesBitmap, bm.C, bm.PoK, pubKey, []byte("nonce23423"), curve)
	assert.NoError(t, err)

	privKeyBytes, err := privKey.Marshal()
	require.NoError(t, err)

	signatureBytes, err := aries.BlindSign(msgToSign, 2, bm.C, privKeyBytes, curve)
	require.NoError(t, err)
	require.NoError(t, err)
	require.NotEmpty(t, signatureBytes)
	require.Len(t, signatureBytes, 112)

	signatureBytes, err = aries.UnblindSign(signatureBytes, bm.S, curve)
	require.NoError(t, err)
	require.NoError(t, err)
	require.NotEmpty(t, signatureBytes)
	require.Len(t, signatureBytes, 112)

	signature, err := bbs.NewBBSLib(curve).ParseSignature(signatureBytes)
	require.NoError(t, err)

	messagesCount := 2

	publicKeyWithGenerators, err := pubKey.ToPublicKeyWithGenerators(messagesCount)
	require.NoError(t, err)

	messagesZr := []*bbs.SignatureMessage{
		{FR: zr, Idx: 0},
		msgToSign[0],
	}

	err = signature.Verify(messagesZr, publicKeyWithGenerators)
	require.NoError(t, err)
}
