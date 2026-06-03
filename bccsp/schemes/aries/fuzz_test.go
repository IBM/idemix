/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/IBM/idemix/bbs"
	"github.com/IBM/idemix/bccsp/schemes/aries"
	"github.com/IBM/idemix/bccsp/types"
	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/require"
)

// fuzzEnv holds pre-computed valid objects used to seed fuzz corpora.
type fuzzEnv struct {
	curve  *math.Curve
	issuer *aries.Issuer
	ipk    types.IssuerPublicKey
	isk    types.IssuerSecretKey
	sk     *math.Zr
	nym    *math.G1
	rNym   *math.Zr
}

func newFuzzEnv(tb testing.TB) *fuzzEnv {
	tb.Helper()
	curve := math.Curves[math.BLS12_381_BBS]

	issuer := &aries.Issuer{Curve: curve}
	isk, err := issuer.NewKey([]string{"attr1", "attr2", "eid", "rh"})
	require.NoError(tb, err)
	ipk := isk.Public()

	rng, err := curve.Rand()
	require.NoError(tb, err)

	user := &aries.User{Curve: curve, Rng: rng}
	sk, err := user.NewKey()
	require.NoError(tb, err)

	nym, rNym, err := user.MakeNym(sk, ipk)
	require.NoError(tb, err)

	return &fuzzEnv{
		curve:  curve,
		issuer: issuer,
		ipk:    ipk,
		isk:    isk,
		sk:     sk,
		nym:    nym,
		rNym:   rNym,
	}
}

// FuzzParseBlindedMessages feeds random bytes into ParseBlindedMessages
// which decompresses two G1 points and parses a proof — all trust-boundary operations.
func FuzzParseBlindedMessages(f *testing.F) {
	env := newFuzzEnv(f)

	// Seed with a valid blinded message blob.
	rng, err := env.curve.Rand()
	require.NoError(f, err)

	cr := &aries.CredRequest{Curve: env.curve}
	credReq, _, err := cr.Blind(env.sk, env.ipk, []byte("nonce"))
	require.NoError(f, err)

	f.Add(credReq)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic; errors are acceptable.
		_, _ = aries.ParseBlindedMessages(data, env.curve)
		_ = rng // keep reference to avoid GC
	})
}

// FuzzIssuerNewPublicKeyFromBytes feeds random bytes into the issuer public key
// deserialization path which performs G2 point decompression.
func FuzzIssuerNewPublicKeyFromBytes(f *testing.F) {
	env := newFuzzEnv(f)

	// Seed with valid serialized IPK bytes.
	pkBytes, err := env.ipk.Bytes()
	require.NoError(f, err)

	f.Add(pkBytes)

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = env.issuer.NewPublicKeyFromBytes(data, []string{"attr1", "attr2", "eid", "rh"})
	})
}

// FuzzCredVerify feeds random credential bytes into Cred.Verify which does
// proto unmarshal followed by BBS+ signature parsing.
func FuzzCredVerify(f *testing.F) {
	env := newFuzzEnv(f)

	rng, err := env.curve.Rand()
	require.NoError(f, err)

	// Create a valid credential for seeding.
	cr := &aries.CredRequest{Curve: env.curve}
	credReq, blinding, err := cr.Blind(env.sk, env.ipk, []byte("nonce"))
	require.NoError(f, err)

	credProto := &aries.Cred{BBS: bbs.New(env.curve), Curve: env.curve}
	idemixAttrs := []types.IdemixAttribute{
		{Type: types.IdemixBytesAttribute, Value: []byte("msg1")},
		{Type: types.IdemixIntAttribute, Value: 34},
		{Type: types.IdemixBytesAttribute, Value: []byte("nymeid")},
		{Type: types.IdemixBytesAttribute, Value: []byte("nymrh")},
	}

	cred, err := credProto.Sign(env.isk, credReq, idemixAttrs)
	require.NoError(f, err)
	cred, err = cr.Unblind(cred, blinding)
	require.NoError(f, err)

	f.Add(cred)

	f.Fuzz(func(t *testing.T, data []byte) {
		c := &aries.Cred{BBS: bbs.New(env.curve), Curve: env.curve}
		_ = c.Verify(env.sk, env.ipk, data, idemixAttrs)
		_ = rng // keep reference to avoid GC
	})
}

// FuzzNymSignerVerify feeds random bytes into NymSigner.Verify which
// does proto unmarshal and proof parsing.
func FuzzNymSignerVerify(f *testing.F) {
	env := newFuzzEnv(f)

	rng, err := env.curve.Rand()
	require.NoError(f, err)

	// Create a valid nym signature for seeding.
	nymSigner := &aries.NymSigner{Curve: env.curve, Rng: rng, UserSecretKeyIndex: 0}
	digest := []byte("test message")
	sigBytes, err := nymSigner.Sign(env.sk, env.nym, env.rNym, env.ipk, digest)
	require.NoError(f, err)

	f.Add(sigBytes)

	f.Fuzz(func(t *testing.T, data []byte) {
		ns := &aries.NymSigner{Curve: env.curve, Rng: rng, UserSecretKeyIndex: 0}
		_ = ns.Verify(env.ipk, env.nym, data, digest, 0)
	})
}

// FuzzSignerVerify feeds random signature bytes into Signer.Verify which
// does proto unmarshal, PoK payload parsing, and signature proof parsing.
func FuzzSignerVerify(f *testing.F) {
	env := newFuzzEnv(f)

	rng, err := env.curve.Rand()
	require.NoError(f, err)

	// Create valid credential and signature for seeding.
	cr := &aries.CredRequest{Curve: env.curve}
	credReq, blinding, err := cr.Blind(env.sk, env.ipk, []byte("nonce"))
	require.NoError(f, err)

	credProto := &aries.Cred{BBS: bbs.New(env.curve), Curve: env.curve}
	idemixAttrs := []types.IdemixAttribute{
		{Type: types.IdemixBytesAttribute, Value: []byte("msg1")},
		{Type: types.IdemixIntAttribute, Value: 34},
		{Type: types.IdemixBytesAttribute, Value: []byte("nymeid")},
		{Type: types.IdemixBytesAttribute, Value: []byte("nymrh")},
	}

	cred, err := credProto.Sign(env.isk, credReq, idemixAttrs)
	require.NoError(f, err)
	cred, err = cr.Unblind(cred, blinding)
	require.NoError(f, err)

	signer := &aries.Signer{Curve: env.curve, Rng: rng}
	sigAttrs := []types.IdemixAttribute{
		{Type: types.IdemixBytesAttribute, Value: []byte("msg1")},
		{Type: types.IdemixIntAttribute, Value: 34},
		{Type: types.IdemixHiddenAttribute},
		{Type: types.IdemixHiddenAttribute},
	}

	sig, _, err := signer.Sign(cred, env.sk, env.nym, env.rNym, env.ipk, sigAttrs,
		[]byte("signer-msg"), 3, 2, nil, types.Standard, nil)
	require.NoError(f, err)

	f.Add(sig)

	f.Fuzz(func(t *testing.T, data []byte) {
		s := &aries.Signer{Curve: env.curve, Rng: rng}
		_ = s.Verify(env.ipk, data, []byte("signer-msg"), sigAttrs, 3, 2, 0, nil, 0, types.BestEffort, nil)
	})
}

// FuzzRevocationVerify feeds random CRI bytes into RevocationAuthority.Verify
// which does proto unmarshal and ASN.1 signature parsing.
func FuzzRevocationVerify(f *testing.F) {
	env := newFuzzEnv(f)

	// Create a valid CRI for seeding.
	revKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(f, err)

	rng, err := env.curve.Rand()
	require.NoError(f, err)

	ra := &aries.RevocationAuthority{Curve: env.curve, Rng: rng}
	criBytes, err := ra.Sign(revKey, [][]byte{}, 0, types.AlgNoRevocation)
	require.NoError(f, err)

	f.Add(criBytes)

	f.Fuzz(func(t *testing.T, data []byte) {
		r := &aries.RevocationAuthority{Curve: env.curve, Rng: rng}
		_ = r.Verify(&revKey.PublicKey, data, 0, types.AlgNoRevocation)
	})
}
