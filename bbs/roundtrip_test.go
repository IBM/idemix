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

	"github.com/IBM/idemix/bbs"
	ml "github.com/IBM/mathlib"
	"github.com/stretchr/testify/require"
)

func TestDeriveVerifyRoundTrip(t *testing.T) {
	for _, curveID := range []ml.CurveID{
		ml.FP256BN_AMCL,
		ml.BN254,
		ml.FP256BN_AMCL_MIRACL,
		ml.BLS12_381,
		ml.BLS12_377_GURVY,
		ml.BLS12_381_GURVY,
		ml.BLS12_381_BBS,
		ml.BLS12_381_BBS_GURVY,
	} {
		curve := ml.Curves[curveID]
		t.Run(ml.CurveIDToString(curveID), func(t *testing.T) {
			for _, n := range []int{1, 5, 10, 20} {
				revealed := benchRevealedIndexes(n)
				t.Run(fmt.Sprintf("msgs=%d/revealed=%d", n, len(revealed)), func(t *testing.T) {
					seed := make([]byte, 32)
					_, _ = rand.Read(seed)
					lib := bbs.NewBBSLib(curve)
					pub, priv, err := lib.GenerateKeyPair(sha256.New, seed)
					require.NoError(t, err)

					privKeyBytes, _ := priv.Marshal()
					pubKeyBytes, _ := pub.Marshal()
					msgs := benchMessages(n)
					scheme := bbs.New(curve)
					nonce := []byte("benchmark-nonce")

					sigBytes, err := scheme.Sign(msgs, privKeyBytes)
					require.NoError(t, err)

					require.NoError(t, scheme.Verify(msgs, sigBytes, pubKeyBytes))

					proofBytes, err := scheme.DeriveProof(msgs, sigBytes, nonce, pubKeyBytes, revealed)
					require.NoError(t, err)

					revealedMsgs := make([][]byte, len(revealed))
					for i, idx := range revealed {
						revealedMsgs[i] = msgs[idx]
					}

					err = scheme.VerifyProof(revealedMsgs, proofBytes, nonce, pubKeyBytes)
					require.NoError(t, err)
				})
			}
		})
	}
}
