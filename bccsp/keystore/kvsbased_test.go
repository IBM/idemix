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
