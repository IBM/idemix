/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs_test

import (
	"math/big"
	"testing"

	"github.com/IBM/idemix/bbs"
	ml "github.com/IBM/mathlib"
	"github.com/stretchr/testify/require"
)

// plusOrder returns b+q encoded on len(b) bytes; for BLS12-381 q < 2^255 so
// it always fits. Before the fix the reducing decoder mapped it to the same
// scalar as b.
func plusOrder(t *testing.T, curve *ml.Curve, b []byte) []byte {
	t.Helper()
	v := new(big.Int).Add(new(big.Int).SetBytes(b), curve.GroupOrder.BigInt())
	require.LessOrEqual(t, len(v.Bytes()), len(b))
	m := v.FillBytes(make([]byte, len(b)))
	require.True(t, curve.NewZrFromBytes(m).Equals(curve.NewZrFromBytes(b)))

	return m
}

// FINDING-F7 (scalar malleability): ParseSignature, ParseProofG1 and
// UnmarshalPrivateKey decoded scalars with the reducing NewZrFromBytes, so a
// signature with E (or S) replaced by E+q, or a proof with a response replaced
// by response+q, still verified. Non-canonical scalars must now be rejected.
func TestFindingBBSScalarMalleability(t *testing.T) {
	curve := ml.Curves[ml.BLS12_381_BBS]

	pubKey, privKey, err := generateKeyPairRandom(curve)
	require.NoError(t, err)
	pubKeyBytes, err := pubKey.Marshal()
	require.NoError(t, err)
	privKeyBytes, err := privKey.Marshal()
	require.NoError(t, err)

	lib := bbs.New(curve)
	messages := [][]byte{[]byte("m0"), []byte("m1"), []byte("m2")}
	sig, err := lib.Sign(messages, privKeyBytes)
	require.NoError(t, err)
	require.NoError(t, lib.Verify(messages, sig, pubKeyBytes))

	const frSize = 32
	g1 := curve.CompressedG1ByteSize

	t.Run("signature E+q", func(t *testing.T) {
		m := append([]byte(nil), sig...)
		copy(m[g1:g1+frSize], plusOrder(t, curve, sig[g1:g1+frSize]))
		require.Error(t, lib.Verify(messages, m, pubKeyBytes))
	})

	t.Run("signature S+q", func(t *testing.T) {
		m := append([]byte(nil), sig...)
		copy(m[g1+frSize:], plusOrder(t, curve, sig[g1+frSize:]))
		require.Error(t, lib.Verify(messages, m, pubKeyBytes))
	})

	t.Run("proof response+q", func(t *testing.T) {
		nonce := []byte("nonce")
		proof, err := lib.DeriveProof(messages, sig, nonce, pubKeyBytes, []int{0})
		require.NoError(t, err)
		require.NoError(t, lib.VerifyProof(messages[:1], proof, nonce, pubKeyBytes))

		// the last frSize bytes are the last response of the second sub-proof
		m := append([]byte(nil), proof...)
		copy(m[len(m)-frSize:], plusOrder(t, curve, proof[len(proof)-frSize:]))
		require.Error(t, lib.VerifyProof(messages[:1], m, nonce, pubKeyBytes))
	})

	t.Run("private key+q", func(t *testing.T) {
		_, err := bbs.NewBBSLib(curve).UnmarshalPrivateKey(plusOrder(t, curve, privKeyBytes))
		require.Error(t, err)
	})
}
