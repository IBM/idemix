/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries_test

import (
	"math/big"
	"testing"

	"github.com/IBM/idemix/bbs"
	"github.com/IBM/idemix/bccsp/schemes/aries"
	"github.com/IBM/idemix/bccsp/types"
	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// plusOrderTail replaces the trailing scalar of b with scalar+q (same length).
// On BLS12-381 q < 2^255, so the result always fits; before the canonical
// decoding fix it decoded to the same scalar.
func plusOrderTail(t *testing.T, curve *math.Curve, b []byte) []byte {
	t.Helper()
	n := curve.ScalarByteSize
	tail := b[len(b)-n:]
	v := new(big.Int).Add(new(big.Int).SetBytes(tail), curve.GroupOrder.BigInt())
	require.LessOrEqual(t, len(v.Bytes()), n)
	m := append([]byte(nil), b...)
	v.FillBytes(m[len(m)-n:])
	require.True(t, curve.NewZrFromBytes(m[len(m)-n:]).Equals(curve.NewZrFromBytes(tail)))

	return m
}

var malleabilityAttrs = []types.IdemixAttribute{
	{Type: types.IdemixBytesAttribute, Value: []byte("ou")},
	{Type: types.IdemixHiddenAttribute},
	{Type: types.IdemixHiddenAttribute},
	{Type: types.IdemixHiddenAttribute},
}

// FINDING-F7 (scalar malleability): the BBS+ proof responses carried in an
// Aries signature (main proof and nym proofs) were decoded with the reducing
// NewZrFromBytes, so response+q produced a distinct but still valid signature.
func TestFindingSignerVerifyScalarMalleability(t *testing.T) {
	env := newFindingsEnv(t)
	signer := &aries.Signer{Curve: env.curve, Rng: env.rng}
	msg := []byte("msg")

	raw, _, err := signer.Sign(env.cred, env.sk, env.nym, env.rNym, env.ipk, malleabilityAttrs, msg, 3, 2, nil, types.EidNymRhNym, nil)
	require.NoError(t, err)
	verify := func(sig []byte) error {
		return signer.Verify(env.ipk, sig, msg, env.nym, malleabilityAttrs, 3, 2, 0, nil, 0, types.ExpectEidNymRhNym, nil)
	}
	require.NoError(t, verify(raw))

	honest := &aries.Signature{}
	require.NoError(t, proto.Unmarshal(raw, honest))

	fields := map[string]func(*aries.Signature) *[]byte{
		"MainSignature": func(s *aries.Signature) *[]byte { return &s.MainSignature },
		"NymProof":      func(s *aries.Signature) *[]byte { return &s.NymProof },
		"NymEidProof":   func(s *aries.Signature) *[]byte { return &s.NymEidProof },
		"NymRhProof":    func(s *aries.Signature) *[]byte { return &s.NymRhProof },
	}
	for field, get := range fields {
		sig := proto.Clone(honest).(*aries.Signature)
		*get(sig) = plusOrderTail(t, env.curve, *get(honest))
		b, err := proto.Marshal(sig)
		require.NoError(t, err)
		require.Error(t, verify(b), "%s response+q must be rejected", field)
	}
}

// FINDING-F7: same for the Aries pseudonym signature.
func TestFindingNymSignerVerifyScalarMalleability(t *testing.T) {
	env := newFindingsEnv(t)
	signer := &aries.NymSigner{Curve: env.curve, Rng: env.rng}
	msg := []byte("msg")

	raw, err := signer.Sign(env.sk, env.nym, env.rNym, env.ipk, msg)
	require.NoError(t, err)
	require.NoError(t, signer.Verify(env.ipk, env.nym, raw, msg, 0))

	sig := &aries.NymSignature{}
	require.NoError(t, proto.Unmarshal(raw, sig))
	sig.MainSignature = plusOrderTail(t, env.curve, sig.MainSignature)
	b, err := proto.Marshal(sig)
	require.NoError(t, err)
	require.Error(t, signer.Verify(env.ipk, env.nym, b, msg, 0))
}

// FINDING-F7: credential attribute values and the user secret key must be
// canonical scalars.
func TestFindingCredentialAndKeyScalarMalleability(t *testing.T) {
	env := newFindingsEnv(t)

	honest := &aries.Credential{}
	require.NoError(t, proto.Unmarshal(env.cred, honest))
	cred := proto.Clone(honest).(*aries.Credential)
	cred.Attrs[1] = plusOrderTail(t, env.curve, cred.Attrs[1])
	credBytes, err := proto.Marshal(cred)
	require.NoError(t, err)

	credAttrs := []types.IdemixAttribute{
		{Type: types.IdemixBytesAttribute, Value: []byte("ou")},
		{Type: types.IdemixIntAttribute, Value: findingsRole},
		{Type: types.IdemixBytesAttribute, Value: []byte("eid")},
		{Type: types.IdemixBytesAttribute, Value: []byte("rh")},
	}
	credProto := &aries.Cred{BBS: bbs.New(env.curve), Curve: env.curve}
	require.NoError(t, credProto.Verify(env.sk, env.ipk, env.cred, credAttrs))
	require.Error(t, credProto.Verify(env.sk, env.ipk, credBytes, credAttrs))

	signer := &aries.Signer{Curve: env.curve, Rng: env.rng}
	_, _, err = signer.Sign(credBytes, env.sk, env.nym, env.rNym, env.ipk, malleabilityAttrs, []byte("msg"), 3, 2, nil, types.Standard, nil)
	require.Error(t, err)

	user := &aries.User{Curve: env.curve, Rng: env.rng}
	sk, err := user.NewKeyFromBytes(env.sk.Bytes())
	require.NoError(t, err)
	require.True(t, sk.Equals(env.sk))
	_, err = user.NewKeyFromBytes(plusOrderTail(t, env.curve, env.sk.Bytes()))
	require.Error(t, err)
}

// FINDING-F7: Smartcard.NymVerify must reject response scalars that are not
// smaller than the group order. On FP256BN the order is close to 2^256, so a
// same-length +q re-encoding of an honest response is not constructible in a
// test; out-of-range values in the fixed-size slots are checked instead.
func TestFindingSmartcardNymVerifyNonCanonicalScalars(t *testing.T) {
	sc, curve := getSmartcard(t)
	_, nymEid := sc.NymEid()
	msg := []byte("msg")

	pi, err := sc.NymSign(msg)
	require.NoError(t, err)
	require.NoError(t, sc.NymVerify(pi, nymEid, msg))

	n := curve.ScalarByteSize
	xOff := 16 + 2*curve.G1ByteSize
	for _, off := range []int{xOff, xOff + n} {
		for _, bad := range [][]byte{
			curve.GroupOrder.BigInt().FillBytes(make([]byte, n)),
			bytesOf(0xff, n),
		} {
			m := append([]byte(nil), pi...)
			copy(m[off:off+n], bad)
			err := sc.NymVerify(m, nymEid, msg)
			require.ErrorContains(t, err, "invalid scalar encoding")
		}
	}
}

func bytesOf(v byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = v
	}

	return b
}
