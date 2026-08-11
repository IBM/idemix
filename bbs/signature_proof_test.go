/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs_test

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/IBM/idemix/bbs"
	ml "github.com/IBM/mathlib"
	"github.com/stretchr/testify/require"
)

// TestBBSLib_ParseSignatureProof_MalformedLength regression-tests F4: ParseSignatureProof
// used to slice sigProofBytes using an attacker-controlled length prefix without checking
// it against the buffer's actual length, which could panic with an out-of-range slice.
func TestBBSLib_ParseSignatureProof_MalformedLength(t *testing.T) {
	curve := ml.Curves[ml.BLS12_381_BBS]

	pubKey, privKey, err := generateKeyPairRandom(curve)
	require.NoError(t, err)

	messagesBytes := [][]byte{[]byte("message1"), []byte("message2")}
	bls := bbs.New(curve)

	privKeyBytes, err := privKey.Marshal()
	require.NoError(t, err)

	sigBytes, err := bls.Sign(messagesBytes, privKeyBytes)
	require.NoError(t, err)

	pubKeyBytes, err := pubKey.Marshal()
	require.NoError(t, err)

	nonce := []byte("nonce")
	proofBytes, err := bls.DeriveProof(messagesBytes, sigBytes, nonce, pubKeyBytes, []int{0})
	require.NoError(t, err)

	payload, err := bbs.ParsePoKPayload(proofBytes)
	require.NoError(t, err)

	sigProofBytes := proofBytes[payload.LenInBytes():]

	bl := bbs.NewBBSLib(curve)

	t.Run("truncated right after the three G1 points, no room for the length prefix", func(t *testing.T) {
		truncLen := curve.CompressedG1ByteSize * 3

		// make+copy (not append) so cap == len, exercising the same bounds check a
		// real proto.Unmarshal-produced buffer would hit.
		truncated := make([]byte, truncLen)
		copy(truncated, sigProofBytes[:truncLen])

		proof, err := bl.ParseSignatureProof(truncated)
		require.Error(t, err)
		require.EqualError(t, err, "invalid size of signature proof")
		require.Nil(t, proof)
	})

	t.Run("huge proof1BytesLen claims more bytes than are present", func(t *testing.T) {
		offset := curve.CompressedG1ByteSize * 3

		tampered := make([]byte, offset+4)
		copy(tampered, sigProofBytes[:offset+4])
		binary.BigEndian.PutUint32(tampered[offset:offset+4], 0xFFFFFFFF)

		proof, err := bl.ParseSignatureProof(tampered)
		require.Error(t, err)
		require.EqualError(t, err, "invalid size of signature proof")
		require.Nil(t, proof)
	})
}

// TestPoKOfSignatureProof_GetBytesForChallenge_MoreRevealedThanMessages regression-tests F5:
// GetBytesForChallenge used to compute hiddenCount without clamping it to zero, so a
// revealedMessages map larger than pubKey.MessagesCount produced a negative length passed to
// make([]byte, ...), which panics.
func TestPoKOfSignatureProof_GetBytesForChallenge_MoreRevealedThanMessages(t *testing.T) {
	curve := ml.Curves[ml.BLS12_381_BBS]

	pubKey, privKey, err := generateKeyPairRandom(curve)
	require.NoError(t, err)

	messagesBytes := [][]byte{[]byte("message1"), []byte("message2")}
	bls := bbs.New(curve)

	privKeyBytes, err := privKey.Marshal()
	require.NoError(t, err)

	sigBytes, err := bls.Sign(messagesBytes, privKeyBytes)
	require.NoError(t, err)

	pubKeyBytes, err := pubKey.Marshal()
	require.NoError(t, err)

	nonce := []byte("nonce")
	proofBytes, err := bls.DeriveProof(messagesBytes, sigBytes, nonce, pubKeyBytes, []int{0})
	require.NoError(t, err)

	payload, err := bbs.ParsePoKPayload(proofBytes)
	require.NoError(t, err)

	bl := bbs.NewBBSLib(curve)

	proof, err := bl.ParseSignatureProof(proofBytes[payload.LenInBytes():])
	require.NoError(t, err)

	pubKeyWithGenerators, err := pubKey.ToPublicKeyWithGenerators(len(messagesBytes))
	require.NoError(t, err)

	// More revealed entries than pubKeyWithGenerators.MessagesCount (2), so
	// MessagesCount - len(revealedMessages) is negative before clamping.
	revealedMessages := map[int]*bbs.SignatureMessage{
		0: {FR: curve.NewZrFromInt(1)},
		1: {FR: curve.NewZrFromInt(2)},
		2: {FR: curve.NewZrFromInt(3)},
		3: {FR: curve.NewZrFromInt(4)},
	}

	var challengeBytes []byte
	require.NotPanics(t, func() {
		challengeBytes = proof.GetBytesForChallenge(revealedMessages, pubKeyWithGenerators)
	})
	require.NotEmpty(t, challengeBytes)
}

// TestProofG1_Verify_ResponsesBasesLengthMismatch regression-tests F6: ProofG1.Verify used to
// build the challenge contribution by zipping bases with pg1.Responses without checking they
// have the same length first, which could panic on the mismatched index inside
// getChallengeContribution/sumOfG1Products.
func TestProofG1_Verify_ResponsesBasesLengthMismatch(t *testing.T) {
	curve := ml.Curves[ml.BLS12_381_BBS]

	commitment := curve.GenG1.Copy()
	responses := []*ml.Zr{curve.NewZrFromInt(1), curve.NewZrFromInt(2)}
	proofG1 := bbs.NewProofG1(commitment, responses)

	bases := []*ml.G1{curve.GenG1}

	err := proofG1.Verify(bases, commitment, curve.NewZrFromInt(1))
	require.Error(t, err)
	require.EqualError(t, err, "invalid proof: responses length does not match bases length")
}

// TestBBSG2Pub_VerifyProof_MessagesCountExceedsMax regression-tests F7: VerifyProofFr used to
// derive generators for an attacker-controlled MessagesCount with no upper bound, allowing a
// proof to force excessive hash-to-curve work during verification (DoS). MessagesCount is
// rejected once it exceeds bbs.MaxMessagesCount, before any generator derivation happens.
func TestBBSG2Pub_VerifyProof_MessagesCountExceedsMax(t *testing.T) {
	curve := ml.Curves[ml.BLS12_381_BBS]

	pubKey, _, err := generateKeyPairRandom(curve)
	require.NoError(t, err)

	pubKeyBytes, err := pubKey.Marshal()
	require.NoError(t, err)

	hugeCount := bbs.MaxMessagesCount + 1

	payload := bbs.NewPoKPayload(hugeCount, []int{0})
	payloadBytes, err := payload.ToBytes()
	require.NoError(t, err)

	// Payload header claiming hugeCount messages; the rest of the bytes are irrelevant
	// because VerifyProofFr must reject the count before parsing further.
	proof := make([]byte, len(payloadBytes)+100)
	copy(proof, payloadBytes)

	nonce := []byte("nonce")
	bls := bbs.New(curve)

	err = bls.VerifyProof([][]byte{[]byte("message1")}, proof, nonce, pubKeyBytes)
	require.Error(t, err)
	require.EqualError(t, err, fmt.Sprintf("invalid message count in proof: %d", hugeCount))
}
