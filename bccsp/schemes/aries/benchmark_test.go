/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries_test

import (
	"io"
	"testing"

	"github.com/IBM/idemix/bbs"
	"github.com/IBM/idemix/bccsp/schemes/aries"
	"github.com/IBM/idemix/bccsp/types"
	math "github.com/IBM/mathlib"
)

// benchEnv holds all pre-computed objects needed by benchmarks.
type benchEnv struct {
	curve  *math.Curve
	rand   io.Reader
	issuer *aries.Issuer
	isk    types.IssuerSecretKey
	ipk    types.IssuerPublicKey
	user   *aries.User
	sk     *math.Zr
	nym    *math.G1
	rNym   *math.Zr
	cred   []byte
	cr     *aries.CredRequest
	signer *aries.Signer
	attrs  []types.IdemixAttribute
}

func newBenchEnv(b *testing.B) *benchEnv {
	b.Helper()
	curve := math.Curves[math.BLS12_381_BBS]

	r, err := curve.Rand()
	if err != nil {
		b.Fatal(err)
	}

	issuer := &aries.Issuer{Curve: curve}
	isk, err := issuer.NewKey([]string{"attr1", "attr2", "eid", "rh"})
	if err != nil {
		b.Fatal(err)
	}
	ipk := isk.Public()

	user := &aries.User{Curve: curve, Rng: r}
	sk, err := user.NewKey()
	if err != nil {
		b.Fatal(err)
	}

	nym, rNym, err := user.MakeNym(sk, ipk)
	if err != nil {
		b.Fatal(err)
	}

	cr := &aries.CredRequest{Curve: curve}
	credReq, blinding, err := cr.Blind(sk, ipk, []byte("nonce"))
	if err != nil {
		b.Fatal(err)
	}

	credProto := &aries.Cred{BBS: bbs.New(curve), Curve: curve}
	idemixAttrs := []types.IdemixAttribute{
		{Type: types.IdemixBytesAttribute, Value: []byte("msg1")},
		{Type: types.IdemixIntAttribute, Value: 34},
		{Type: types.IdemixBytesAttribute, Value: []byte("nymeid")},
		{Type: types.IdemixBytesAttribute, Value: []byte("nymrh")},
	}

	cred, err := credProto.Sign(isk, credReq, idemixAttrs)
	if err != nil {
		b.Fatal(err)
	}
	cred, err = cr.Unblind(cred, blinding)
	if err != nil {
		b.Fatal(err)
	}

	sigAttrs := []types.IdemixAttribute{
		{Type: types.IdemixBytesAttribute, Value: []byte("msg1")},
		{Type: types.IdemixIntAttribute, Value: 34},
		{Type: types.IdemixHiddenAttribute},
		{Type: types.IdemixHiddenAttribute},
	}

	return &benchEnv{
		curve:  curve,
		rand:   r,
		issuer: issuer,
		isk:    isk,
		ipk:    ipk,
		user:   user,
		sk:     sk,
		nym:    nym,
		rNym:   rNym,
		cred:   cred,
		cr:     cr,
		signer: &aries.Signer{Curve: curve, Rng: r},
		attrs:  sigAttrs,
	}
}

// ─── Issuer Key Generation ───────────────────────────────────────────

func BenchmarkIssuerNewKey(b *testing.B) {
	curve := math.Curves[math.BLS12_381_BBS]
	issuer := &aries.Issuer{Curve: curve}
	attrs := []string{"attr1", "attr2", "eid", "rh"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := issuer.NewKey(attrs)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIssuerNewKeyFromBytes(b *testing.B) {
	env := newBenchEnv(b)
	skBytes, err := env.isk.Bytes()
	if err != nil {
		b.Fatal(err)
	}
	attrNames := []string{"attr1", "attr2", "eid", "rh"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := env.issuer.NewKeyFromBytes(skBytes, attrNames)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIssuerNewPublicKeyFromBytes(b *testing.B) {
	env := newBenchEnv(b)
	pkBytes, err := env.ipk.Bytes()
	if err != nil {
		b.Fatal(err)
	}
	attrNames := []string{"attr1", "attr2", "eid", "rh"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := env.issuer.NewPublicKeyFromBytes(pkBytes, attrNames)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// ─── User Nym Creation ───────────────────────────────────────────────

func BenchmarkUserMakeNym(b *testing.B) {
	env := newBenchEnv(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := env.user.MakeNym(env.sk, env.ipk)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// ─── Credential Request ──────────────────────────────────────────────

func BenchmarkCredRequestBlind(b *testing.B) {
	env := newBenchEnv(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := env.cr.Blind(env.sk, env.ipk, []byte("nonce"))
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCredRequestBlindVerify(b *testing.B) {
	env := newBenchEnv(b)
	credReq, _, err := env.cr.Blind(env.sk, env.ipk, []byte("nonce"))
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := env.cr.BlindVerify(credReq, env.ipk, []byte("nonce"))
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCredRequestUnblind(b *testing.B) {
	env := newBenchEnv(b)
	credReq, blinding, err := env.cr.Blind(env.sk, env.ipk, []byte("nonce"))
	if err != nil {
		b.Fatal(err)
	}

	credProto := &aries.Cred{BBS: bbs.New(env.curve), Curve: env.curve}
	allAttrs := []types.IdemixAttribute{
		{Type: types.IdemixBytesAttribute, Value: []byte("msg1")},
		{Type: types.IdemixIntAttribute, Value: 34},
		{Type: types.IdemixBytesAttribute, Value: []byte("nymeid")},
		{Type: types.IdemixBytesAttribute, Value: []byte("nymrh")},
	}
	blindedCred, err := credProto.Sign(env.isk, credReq, allAttrs)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := env.cr.Unblind(blindedCred, blinding)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// ─── Credential Sign / Verify ────────────────────────────────────────

func BenchmarkCredSign(b *testing.B) {
	env := newBenchEnv(b)
	credReq, _, err := env.cr.Blind(env.sk, env.ipk, []byte("nonce"))
	if err != nil {
		b.Fatal(err)
	}

	credProto := &aries.Cred{BBS: bbs.New(env.curve), Curve: env.curve}
	allAttrs := []types.IdemixAttribute{
		{Type: types.IdemixBytesAttribute, Value: []byte("msg1")},
		{Type: types.IdemixIntAttribute, Value: 34},
		{Type: types.IdemixBytesAttribute, Value: []byte("nymeid")},
		{Type: types.IdemixBytesAttribute, Value: []byte("nymrh")},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := credProto.Sign(env.isk, credReq, allAttrs)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCredVerify(b *testing.B) {
	env := newBenchEnv(b)
	credProto := &aries.Cred{BBS: bbs.New(env.curve), Curve: env.curve}
	allAttrs := []types.IdemixAttribute{
		{Type: types.IdemixBytesAttribute, Value: []byte("msg1")},
		{Type: types.IdemixIntAttribute, Value: 34},
		{Type: types.IdemixBytesAttribute, Value: []byte("nymeid")},
		{Type: types.IdemixBytesAttribute, Value: []byte("nymrh")},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := credProto.Verify(env.sk, env.ipk, env.cred, allAttrs)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// ─── Signer Sign / Verify ────────────────────────────────────────────

func BenchmarkSignerSign(b *testing.B) {
	env := newBenchEnv(b)
	rhIndex, eidIndex := 3, 2

	cases := []struct {
		name    string
		sigType types.SignatureType
	}{
		{"Standard", types.Standard},
		{"EidNym", types.EidNym},
		{"EidNymRhNym", types.EidNymRhNym},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _, err := env.signer.Sign(env.cred, env.sk, env.nym, env.rNym, env.ipk, env.attrs, []byte("msg"), rhIndex, eidIndex, nil, tc.sigType, nil)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkSignerVerify(b *testing.B) {
	env := newBenchEnv(b)
	rhIndex, eidIndex := 3, 2

	cases := []struct {
		name    string
		sigType types.SignatureType
		verType types.VerificationType
	}{
		{"Basic", types.Standard, types.Basic},
		{"ExpectEidNym", types.EidNym, types.ExpectEidNym},
		{"ExpectEidNymRhNym", types.EidNymRhNym, types.ExpectEidNymRhNym},
	}

	for _, tc := range cases {
		sig, _, err := env.signer.Sign(env.cred, env.sk, env.nym, env.rNym, env.ipk, env.attrs, []byte("msg"), rhIndex, eidIndex, nil, tc.sigType, nil)
		if err != nil {
			b.Fatal(err)
		}

		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				err := env.signer.Verify(env.ipk, sig, []byte("msg"), env.attrs, rhIndex, eidIndex, 0, nil, 0, tc.verType, nil)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// ─── Nym Signer ──────────────────────────────────────────────────────

func BenchmarkNymSignerSign(b *testing.B) {
	env := newBenchEnv(b)
	ipk := env.ipk.(*aries.IssuerPublicKey)

	nymSigner := &aries.NymSigner{
		Curve:              env.curve,
		Rng:                env.rand,
		UserSecretKeyIndex: 0,
	}

	sk := env.curve.NewRandomZr(env.rand)
	rNym := env.curve.NewRandomZr(env.rand)

	cb := bbs.NewCommitmentBuilder(2)
	cb.Add(ipk.PKwG.H0, rNym)
	cb.Add(ipk.PKwG.H[0], sk)
	nym := cb.Build()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := nymSigner.Sign(sk, nym, rNym, env.ipk, []byte("msg"))
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNymSignerVerify(b *testing.B) {
	env := newBenchEnv(b)
	ipk := env.ipk.(*aries.IssuerPublicKey)

	nymSigner := &aries.NymSigner{
		Curve:              env.curve,
		Rng:                env.rand,
		UserSecretKeyIndex: 0,
	}

	sk := env.curve.NewRandomZr(env.rand)
	rNym := env.curve.NewRandomZr(env.rand)

	cb := bbs.NewCommitmentBuilder(2)
	cb.Add(ipk.PKwG.H0, rNym)
	cb.Add(ipk.PKwG.H[0], sk)
	nym := cb.Build()

	sig, err := nymSigner.Sign(sk, nym, rNym, env.ipk, []byte("msg"))
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := nymSigner.Verify(env.ipk, nym, sig, []byte("msg"), 0)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// ─── Revocation ──────────────────────────────────────────────────────

func BenchmarkRevocationSign(b *testing.B) {
	curve := math.Curves[math.BLS12_381_BBS]
	r, err := curve.Rand()
	if err != nil {
		b.Fatal(err)
	}

	rev := &aries.RevocationAuthority{Curve: curve, Rng: r}
	key, err := rev.NewKey()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := rev.Sign(key, nil, 0, types.AlgNoRevocation)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRevocationVerify(b *testing.B) {
	curve := math.Curves[math.BLS12_381_BBS]
	r, err := curve.Rand()
	if err != nil {
		b.Fatal(err)
	}

	rev := &aries.RevocationAuthority{Curve: curve, Rng: r}
	key, err := rev.NewKey()
	if err != nil {
		b.Fatal(err)
	}

	cri, err := rev.Sign(key, nil, 0, types.AlgNoRevocation)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := rev.Verify(&key.PublicKey, cri, 0, types.AlgNoRevocation)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// ─── Audit ───────────────────────────────────────────────────────────

func BenchmarkAuditNymEid(b *testing.B) {
	env := newBenchEnv(b)
	rhIndex, eidIndex := 3, 2

	sig, m, err := env.signer.Sign(env.cred, env.sk, env.nym, env.rNym, env.ipk, env.attrs, []byte("msg"), rhIndex, eidIndex, nil, types.EidNymRhNym, nil)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := env.signer.AuditNymEid(env.ipk, eidIndex, 0, sig, "nymeid", m.EidNymAuditData.Rand, types.AuditExpectSignature)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAuditNymRh(b *testing.B) {
	env := newBenchEnv(b)
	rhIndex, eidIndex := 3, 2

	sig, m, err := env.signer.Sign(env.cred, env.sk, env.nym, env.rNym, env.ipk, env.attrs, []byte("msg"), rhIndex, eidIndex, nil, types.EidNymRhNym, nil)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := env.signer.AuditNymRh(env.ipk, rhIndex, 0, sig, "nymrh", m.RhNymAuditData.Rand, types.AuditExpectSignature)
		if err != nil {
			b.Fatal(err)
		}
	}
}
