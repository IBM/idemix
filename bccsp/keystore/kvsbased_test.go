/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keystore

import (
	"testing"

	"github.com/IBM/idemix/bccsp/handlers"
	"github.com/IBM/idemix/bccsp/keystore/kvs"
	"github.com/IBM/idemix/bccsp/schemes/dlog/crypto/translator/amcl"
	bccsp "github.com/IBM/idemix/bccsp/types"
	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileBased(t *testing.T) {
	curve := math.Curves[math.FP256BN_AMCL]
	translator := &amcl.Fp256bn{C: curve}
	rnd, err := curve.Rand()
	require.NoError(t, err)

	dir := t.TempDir()

	kvs, err := kvs.NewFileBased(dir)
	require.NoError(t, err)

	keystore := &KVSStore{
		KVS:        kvs,
		Translator: translator,
		Curve:      curve,
	}

	nsk, err := handlers.NewNymSecretKey(curve.NewRandomZr(rnd), curve.GenG1.Mul(curve.NewRandomZr(rnd)), translator, true)
	require.NoError(t, err)
	keys := []bccsp.Key{
		handlers.NewUserSecretKey(curve.NewRandomZr(rnd), true),
		nsk,
	}
	pk, err := nsk.PublicKey()
	require.NoError(t, err)
	skis := [][]byte{
		keys[0].SKI(),
		pk.SKI(),
	}

	for i, key := range keys {
		err = keystore.StoreKey(key)
		require.NoError(t, err)

		keyBack, err := keystore.GetKey(skis[i])
		require.NoError(t, err)

		b1, err := key.Bytes()
		require.NoError(t, err)
		b2, err := keyBack.Bytes()
		require.NoError(t, err)
		assert.Equal(t, b1, b2)

		pk1, err := key.PublicKey()
		if err != nil && err.Error() == "cannot call this method on a symmetric key" {
			// skip if it's a symmetric key
			continue
		}
		pk2, err := keyBack.PublicKey()
		require.NoError(t, err)

		b1, err = pk1.Bytes()
		require.NoError(t, err)
		b2, err = pk2.Bytes()
		require.NoError(t, err)
		assert.Equal(t, b1, b2)
	}
}

func TestKVSStoreRejectsMismatchedTranslator(t *testing.T) {
	bn := math.Curves[math.BN254]
	bls := math.Curves[math.BLS12_381_BBS]

	k, err := kvs.NewFileBased(t.TempDir())
	require.NoError(t, err)

	_, err = NewKVSStore(k, bls, &amcl.Gurvy{C: bn})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid curve/translator pair")

	ks, err := NewKVSStore(k, bls, &amcl.Gurvy{C: bls})
	require.NoError(t, err)

	rnd, err := bls.Rand()
	require.NoError(t, err)
	usk := handlers.NewUserSecretKey(bls.NewRandomZr(rnd), true)
	require.NoError(t, ks.StoreKey(usk))
	_, err = ks.GetKey(usk.SKI())
	require.NoError(t, err)

	// a store built as a struct literal with a mismatched pair fails on use
	bad := &KVSStore{KVS: k, Curve: bls, Translator: &amcl.Gurvy{C: bn}}
	_, err = bad.GetKey(usk.SKI())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid curve/translator pair")
	require.Error(t, bad.StoreKey(usk))
}

func TestKVSStoreGetKeyCorruptedNym(t *testing.T) {
	curve := math.Curves[math.BLS12_381_BBS]
	translator := &amcl.Gurvy{C: curve}

	k, err := kvs.NewFileBased(t.TempDir())
	require.NoError(t, err)
	ks, err := NewKVSStore(k, curve, translator)
	require.NoError(t, err)

	// a nym entry with no public key used to panic in the Gurvy translator
	require.NoError(t, k.Put("abcd", &entry{NymSecretKey: &NymSecretKey{Sk: []byte{1}}}))
	assert.NotPanics(t, func() {
		_, err = ks.GetKey([]byte{0xab, 0xcd})
	})
	require.Error(t, err)

	// truncated coordinates
	require.NoError(t, k.Put("abce", &entry{NymSecretKey: &NymSecretKey{Sk: []byte{1}, Pk: &amcl.ECP{X: []byte{1}, Y: []byte{2}}}}))
	_, err = ks.GetKey([]byte{0xab, 0xce})
	require.Error(t, err)
}
