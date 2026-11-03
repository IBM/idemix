/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries_test

import (
	"testing"

	"github.com/IBM/idemix/bbs"
	"github.com/IBM/idemix/bccsp/schemes/aries"
	"github.com/IBM/idemix/bccsp/types"
	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// findingsEnv is an issued credential (OU="ou", Role=1, eid, rh) plus a user nym.
type findingsEnv struct {
	curve *math.Curve
	ipk   types.IssuerPublicKey
	cred  []byte
	sk    *math.Zr
	nym   *math.G1
	rNym  *math.Zr
	rng   interface{ Read([]byte) (int, error) }
}

const (
	findingsRole      = 1 // role actually certified by the issuer
	findingsForgeRole = 2 // role claimed by the attacker
)

func newFindingsEnv(t *testing.T) *findingsEnv {
	t.Helper()

	curve := math.Curves[math.BLS12_381_BBS]
	issuer := &aries.Issuer{Curve: curve}

	isk, err := issuer.NewKey([]string{"ou", "role", "eid", "rh"})
	require.NoError(t, err)
	ipk := isk.Public()

	rng, err := curve.Rand()
	require.NoError(t, err)

	user := &aries.User{Curve: curve, Rng: rng}
	sk, err := user.NewKey()
	require.NoError(t, err)

	cr := &aries.CredRequest{Curve: curve}
	credReq, blinding, err := cr.Blind(sk, ipk, []byte("nonce"))
	require.NoError(t, err)

	credAttrs := []types.IdemixAttribute{
		{Type: types.IdemixBytesAttribute, Value: []byte("ou")},
		{Type: types.IdemixIntAttribute, Value: findingsRole},
		{Type: types.IdemixBytesAttribute, Value: []byte("eid")},
		{Type: types.IdemixBytesAttribute, Value: []byte("rh")},
	}

	credProto := &aries.Cred{BBS: bbs.New(curve), Curve: curve}
	cred, err := credProto.Sign(isk, credReq, credAttrs)
	require.NoError(t, err)
	cred, err = cr.Unblind(cred, blinding)
	require.NoError(t, err)
	require.NoError(t, credProto.Verify(sk, ipk, cred, credAttrs))

	nym, rNym, err := user.MakeNym(sk, ipk)
	require.NoError(t, err)

	return &findingsEnv{curve: curve, ipk: ipk, cred: cred, sk: sk, nym: nym, rNym: rNym, rng: rng}
}

// mspVerifierAttrs mirrors msp/idemixmsp.go verifyProof: OU and Role disclosed, eid and rh hidden.
func mspVerifierAttrs(role int) []types.IdemixAttribute {
	return []types.IdemixAttribute{
		{Type: types.IdemixBytesAttribute, Value: []byte("ou")},
		{Type: types.IdemixIntAttribute, Value: role},
		{Type: types.IdemixHiddenAttribute},
		{Type: types.IdemixHiddenAttribute},
	}
}

// signHidingRole produces an honest signature that discloses only the OU and hides the role.
func (env *findingsEnv) signHidingRole(t *testing.T, msg []byte) []byte {
	t.Helper()

	signer := &aries.Signer{Curve: env.curve, Rng: env.rng}
	attrs := []types.IdemixAttribute{
		{Type: types.IdemixBytesAttribute, Value: []byte("ou")},
		{Type: types.IdemixHiddenAttribute},
		{Type: types.IdemixHiddenAttribute},
		{Type: types.IdemixHiddenAttribute},
	}

	sig, _, err := signer.Sign(env.cred, env.sk, env.nym, env.rNym, env.ipk, attrs, msg, 3, 2, nil, types.Standard, nil)
	require.NoError(t, err)

	// sanity: honest verification of what was actually disclosed succeeds
	require.NoError(t, signer.Verify(env.ipk, sig, msg, env.nym, attrs, 3, 2, 0, nil, 0, types.ExpectStandard, nil))

	return sig
}

// TestFindingSignerVerifyAcceptsUndisclosedAttribute: Signer.Verify only checks
// len(payload.Revealed) <= len(messages) and then maps payload.Revealed[i] -> messages[i]
// positionally. A proof that hides the role is therefore accepted by a verifier that
// expects the role to be disclosed with ANY value: the expected role is never checked.
func TestFindingSignerVerifyAcceptsUndisclosedAttribute(t *testing.T) {
	env := newFindingsEnv(t)
	msg := []byte("msg")
	sig := env.signHidingRole(t, msg)

	signer := &aries.Signer{Curve: env.curve}
	t.Run("role_hidden", func(t *testing.T) {
		// types.Basic and rh/eid = 3/2 are exactly what msp/idemixmsp.go verifyProof uses.
		err := signer.Verify(env.ipk, sig, msg, env.nym, mspVerifierAttrs(findingsForgeRole), 3, 2, 0, nil, 0, types.Basic, nil)
		require.Error(t, err, "signature that does not disclose the role must not verify against an expected role %d (certified role is %d)", findingsForgeRole, findingsRole)
	})

	t.Run("ou_and_role_hidden", func(t *testing.T) {
		// hiding OU as well: zero revealed attributes, verifier expects OU "other" and role 2
		allHidden := []types.IdemixAttribute{
			{Type: types.IdemixHiddenAttribute}, {Type: types.IdemixHiddenAttribute},
			{Type: types.IdemixHiddenAttribute}, {Type: types.IdemixHiddenAttribute},
		}
		s2 := &aries.Signer{Curve: env.curve, Rng: env.rng}
		sig2, _, err := s2.Sign(env.cred, env.sk, env.nym, env.rNym, env.ipk, allHidden, msg, 3, 2, nil, types.Standard, nil)
		require.NoError(t, err)
		forged := mspVerifierAttrs(findingsForgeRole)
		forged[0].Value = []byte("other-ou")
		err = signer.Verify(env.ipk, sig2, msg, env.nym, forged, 3, 2, 0, nil, 0, types.Basic, nil)
		require.Error(t, err, "signature disclosing nothing must not verify against expected OU/role")
	})
}

// TestFindingSignerVerifyAcceptsOutOfRangeRevealedIndex: even with an equal number of
// revealed indices, the payload may reveal an index that has no generator (>= len(H)).
// The extra message is consumed by revealedMessages but never checked in VC2, so the
// role is again unbound. The payload bytes are not part of the Fiat-Shamir challenge.
func TestFindingSignerVerifyAcceptsOutOfRangeRevealedIndex(t *testing.T) {
	env := newFindingsEnv(t)
	msg := []byte("msg")
	sigBytes := env.signHidingRole(t, msg)

	sig := &aries.Signature{}
	require.NoError(t, proto.Unmarshal(sigBytes, sig))

	payload, err := bbs.ParsePoKPayload(sig.MainSignature)
	require.NoError(t, err)
	require.Equal(t, []int{1}, payload.Revealed)

	// reveal {1 (ou), 9 (no such generator)} instead of {1}
	newPayload, err := bbs.NewPoKPayload(10, []int{1, 9}).ToBytes()
	require.NoError(t, err)
	sig.MainSignature = append(newPayload, sig.MainSignature[payload.LenInBytes():]...)
	tampered, err := proto.Marshal(sig)
	require.NoError(t, err)

	signer := &aries.Signer{Curve: env.curve}
	err = signer.Verify(env.ipk, tampered, msg, env.nym, mspVerifierAttrs(findingsForgeRole), 3, 2, 0, nil, 0, types.ExpectStandard, nil)
	require.Error(t, err, "revealed index 9 is outside the issuer key and must be rejected")
}

// TestFindingNymSignerVerifySkIndexOutOfRange: NymSigner.Verify indexes ipk.PKwG.H[skIndex]
// without a bounds check and has no recover.
func TestFindingNymSignerVerifySkIndexOutOfRange(t *testing.T) {
	env := newFindingsEnv(t)
	msg := []byte("msg")

	ns := &aries.NymSigner{Curve: env.curve, Rng: env.rng}
	sig, err := ns.Sign(env.sk, env.nym, env.rNym, env.ipk, msg)
	require.NoError(t, err)
	require.NoError(t, ns.Verify(env.ipk, env.nym, sig, msg, 0))

	for _, idx := range []int{-1, 5, 1 << 20} {
		require.NotPanics(t, func() {
			err = ns.Verify(env.ipk, env.nym, sig, msg, idx)
		}, "skIndex %d", idx)
		require.Error(t, err, "skIndex %d", idx)
	}
}

// TestFindingSmartcardNymVerifyShortProof: Smartcard.NymVerify slices proofBytes at fixed
// offsets without checking its length. The proof is the attacker-supplied signature in
// NymVerifier.Verify (IsSmartcard), and there is no recover on that path.
func TestFindingSmartcardNymVerifyShortProof(t *testing.T) {
	sc, curve := getSmartcard(t)
	_, nymEid := sc.NymEid()

	full := 16 + 2*curve.G1ByteSize + 2*curve.ScalarByteSize
	for _, l := range []int{0, 15, 16, 16 + curve.G1ByteSize, full - 1} {
		proof := make([]byte, l)
		var err error
		require.NotPanics(t, func() {
			err = sc.NymVerify(proof, nymEid, []byte("msg"))
		}, "proof length %d", l)
		require.Error(t, err, "proof length %d", l)
	}
}

// TestFindingSmartcardNymVerifyTrailingBytes: Smartcard.NymVerify used to only enforce a
// lower bound on the proof length and ignore any trailing bytes, making the proof
// encoding malleable. Only the APDU status word 0x9000 may follow the proof.
func TestFindingSmartcardNymVerifyTrailingBytes(t *testing.T) {
	sc, _ := getSmartcard(t)
	_, nymEid := sc.NymEid()
	msg := []byte("msg")

	pi, err := sc.NymSign(msg)
	require.NoError(t, err)
	require.NoError(t, sc.NymVerify(pi, nymEid, msg))
	require.NoError(t, sc.NymVerify(append(append([]byte{}, pi...), 0x90, 0x00), nymEid, msg))

	for _, trailer := range [][]byte{
		{0x00},
		{0x6a, 0x82},
		{0x90, 0x00, 0x00},
		{0x90, 0x00, 0x90, 0x00},
		make([]byte, 32),
	} {
		err := sc.NymVerify(append(append([]byte{}, pi...), trailer...), nymEid, msg)
		require.Error(t, err, "trailer %x", trailer)
	}
}

// TestFindingSmartcardBackendVerifyMalformedInput: SmartcardIdemixBackend.Verify performs
// an unchecked type assertion on the issuer public key and hardcodes PKwG.H[3].
func TestFindingSmartcardBackendVerifyMalformedInput(t *testing.T) {
	curve := math.Curves[math.BLS12_381_BBS]
	backend := &aries.SmartcardIdemixBackend{Curve: curve}

	t.Run("wrong_ipk_type", func(t *testing.T) {
		var err error
		require.NotPanics(t, func() {
			err = backend.Verify(&fakeIPK{}, curve.GenG1, make([]byte, 256), []byte("msg"))
		})
		require.Error(t, err)
	})

	t.Run("ipk_with_fewer_than_4_generators", func(t *testing.T) {
		issuer := &aries.Issuer{Curve: curve}
		isk, err := issuer.NewKey([]string{"a"}) // H has 2 entries
		require.NoError(t, err)

		require.NotPanics(t, func() {
			err = backend.Verify(isk.Public(), curve.GenG1, make([]byte, 256), []byte("msg"))
		})
		require.Error(t, err)
	})
}

// TestFindingIssuerBasesNegativeIndex: Issuer.Bases only checks the upper bound of the
// indices. Negative values either panic (H[-1]) or silently alias another generator
// (RhIndex/EidIndex = -1 select H[0], the user secret key base).
func TestFindingIssuerBasesNegativeIndex(t *testing.T) {
	curve := math.Curves[math.BLS12_381_BBS]
	issuer := &aries.Issuer{Curve: curve}

	isk, err := issuer.NewKey([]string{"ou", "role", "eid", "rh"})
	require.NoError(t, err)
	ipk := isk.Public()

	cases := []struct {
		name             string
		rh, eid, skIndex int
	}{
		{"sk_negative", 3, 2, -1},
		{"rh_minus_two", -2, 2, 0},
		{"eid_minus_one_aliases_sk_base", 3, -1, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var err error
			require.NotPanics(t, func() {
				_, err = issuer.Bases(ipk, types.Dlog, c.rh, c.eid, c.skIndex)
			})
			require.Error(t, err)
		})
	}
}
