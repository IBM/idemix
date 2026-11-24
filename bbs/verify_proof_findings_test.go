/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs_test

import (
	"testing"

	"github.com/IBM/idemix/bbs"
	ml "github.com/IBM/mathlib"
	"github.com/stretchr/testify/require"
)

// TestFindingVerifyProofIgnoresExtraRevealedMessages: VerifyProofFr only rejects
// len(payload.Revealed) > len(messages) and maps payload.Revealed[i] -> messages[i]
// positionally. A proof that reveals only message 0 is accepted when the verifier
// supplies two "revealed" messages: the second one is never checked.
func TestFindingVerifyProofIgnoresExtraRevealedMessages(t *testing.T) {
	curve := ml.Curves[ml.BLS12_381_BBS]

	pubKey, privKey, err := generateKeyPairRandom(curve)
	require.NoError(t, err)
	pubKeyBytes, err := pubKey.Marshal()
	require.NoError(t, err)
	privKeyBytes, err := privKey.Marshal()
	require.NoError(t, err)

	bls := bbs.New(curve)
	messages := [][]byte{[]byte("m0"), []byte("m1"), []byte("m2")}
	sig, err := bls.Sign(messages, privKeyBytes)
	require.NoError(t, err)

	nonce := []byte("nonce")
	proof, err := bls.DeriveProof(messages, sig, nonce, pubKeyBytes, []int{0})
	require.NoError(t, err)
	require.NoError(t, bls.VerifyProof(messages[:1], proof, nonce, pubKeyBytes))

	err = bls.VerifyProof([][]byte{[]byte("m0"), []byte("never-signed")}, proof, nonce, pubKeyBytes)
	require.Error(t, err, "verifier supplied 2 revealed messages but the proof reveals only 1")
}
