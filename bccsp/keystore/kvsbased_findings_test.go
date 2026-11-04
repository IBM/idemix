/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keystore

import (
	"encoding/hex"
	"testing"

	"github.com/IBM/idemix/bccsp/handlers"
	"github.com/IBM/idemix/bccsp/keystore/kvs"
	"github.com/IBM/idemix/bccsp/schemes/dlog/crypto/translator/amcl"
	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/require"
)

// FINDING-KS-1: KVSStore.GetKey(ski) returns whatever entry is stored under hex(ski) without
// checking that the decoded key actually has that SKI (nym: SKI of the public part; user: SKI
// of Sk) or that Sk has the curve's scalar length. A tampered/colliding KVS entry is returned
// as the key "for" an unrelated SKI.
func TestFindingKVSStoreGetKeyDoesNotCheckSKI(t *testing.T) {
	curve := math.Curves[math.BLS12_381_BBS]
	translator := &amcl.Gurvy{C: curve}
	k, err := kvs.NewFileBased(t.TempDir())
	require.NoError(t, err)
	ks, err := NewKVSStore(k, curve, translator)
	require.NoError(t, err)

	rnd, err := curve.Rand()
	require.NoError(t, err)

	t.Run("nym key stored under another SKI", func(t *testing.T) {
		nymA, err := handlers.NewNymSecretKey(curve.NewRandomZr(rnd), curve.GenG1.Mul(curve.NewRandomZr(rnd)), translator, true)
		require.NoError(t, err)
		nymB, err := handlers.NewNymSecretKey(curve.NewRandomZr(rnd), curve.GenG1.Mul(curve.NewRandomZr(rnd)), translator, true)
		require.NoError(t, err)
		pkB, err := nymB.PublicKey()
		require.NoError(t, err)
		require.NoError(t, ks.StoreKey(nymA))

		// copy A's entry under B's identifier
		pkA, err := nymA.PublicKey()
		require.NoError(t, err)
		e := &entry{}
		require.NoError(t, k.Get(hex.EncodeToString(pkA.SKI()), e))
		require.NoError(t, k.Put(hex.EncodeToString(pkB.SKI()), e))

		_, err = ks.GetKey(pkB.SKI())
		require.Error(t, err, "GetKey must reject an entry whose key does not match the requested SKI")
	})

	t.Run("user key with wrong scalar length", func(t *testing.T) {
		require.NoError(t, k.Put("abcdef", &entry{UserSecretKey: &UserSecretKey{Sk: make([]byte, 100)}}))
		_, err := ks.GetKey([]byte{0xab, 0xcd, 0xef})
		require.Error(t, err, "GetKey must reject a secret key of the wrong length")
	})
}
