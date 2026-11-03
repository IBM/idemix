/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keystore

import (
	"bytes"
	"testing"

	"github.com/IBM/idemix/bccsp/keystore/kvs"
	"github.com/IBM/idemix/bccsp/schemes/dlog/crypto/translator/amcl"
	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/require"
)

// FINDING-F7 (scalar malleability): KVSStore.GetKey decoded stored secret keys
// with the reducing NewZrFromBytes; an out-of-range Sk of the right length was
// silently reduced. Stored scalars must now be canonical.
func TestFindingKVSStoreGetKeyNonCanonicalScalar(t *testing.T) {
	curve := math.Curves[math.BLS12_381_BBS]
	translator := &amcl.Gurvy{C: curve}
	k, err := kvs.NewFileBased(t.TempDir())
	require.NoError(t, err)
	ks, err := NewKVSStore(k, curve, translator)
	require.NoError(t, err)

	tooBig := bytes.Repeat([]byte{0xff}, curve.ScalarByteSize)
	require.NoError(t, k.Put("abcdef", &entry{UserSecretKey: &UserSecretKey{Sk: tooBig}}))
	_, err = ks.GetKey([]byte{0xab, 0xcd, 0xef})
	require.ErrorContains(t, err, "invalid scalar encoding")

	require.NoError(t, k.Put("abcd01", &entry{NymSecretKey: &NymSecretKey{Sk: tooBig, Pk: translator.G1ToProto(curve.GenG1)}}))
	_, err = ks.GetKey([]byte{0xab, 0xcd, 0x01})
	require.ErrorContains(t, err, "invalid scalar encoding")
}
