/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bridge_test

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/IBM/idemix/bccsp/schemes/dlog/bridge"
	idemix "github.com/IBM/idemix/bccsp/schemes/dlog/crypto"
	"github.com/IBM/idemix/bccsp/schemes/dlog/crypto/translator/amcl"
	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/require"
)

// FINDING-F7 (scalar malleability): User.NewKeyFromBytes reduced any
// ScalarByteSize input modulo the group order, so sk and sk+q imported as the
// same key. Only canonical encodings are now accepted.
func TestFindingUserNewKeyFromBytesNonCanonical(t *testing.T) {
	curve := math.Curves[math.BLS12_381_GURVY]
	user := &bridge.User{Idemix: &idemix.Idemix{Curve: curve}, Translator: &amcl.Gurvy{C: curve}}

	sk, err := user.NewKey()
	require.NoError(t, err)
	imported, err := user.NewKeyFromBytes(sk.Bytes())
	require.NoError(t, err)
	require.True(t, imported.Equals(sk))

	v := new(big.Int).Add(sk.BigInt(), curve.GroupOrder.BigInt())
	require.LessOrEqual(t, len(v.Bytes()), curve.ScalarByteSize)
	_, err = user.NewKeyFromBytes(v.FillBytes(make([]byte, curve.ScalarByteSize)))
	require.Error(t, err)

	_, err = user.NewKeyFromBytes(bytes.Repeat([]byte{0xff}, curve.ScalarByteSize))
	require.Error(t, err)
}
