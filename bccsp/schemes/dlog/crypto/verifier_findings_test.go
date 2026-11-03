/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"crypto/ecdsa"
	"testing"

	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	opts "github.com/IBM/idemix/bccsp/types"
)

// findingFx is an honest issuer key, credential, nym and CRI used as the
// starting point for the malformed inputs below.
type findingFx struct {
	curve *math.Curve
	tr    Translator
	idmx  *Idemix
	key   *IssuerKey
	sk    *math.Zr
	cred  *Credential
	cri   *CredentialRevocationInformation
	rk    *ecdsa.PrivateKey
	nym   *math.G1
	rnym  *math.Zr
	attrs []*math.Zr
}

const (
	fxRhIndex  = 3
	fxEidIndex = 2
)

var fxMsg = []byte("msg")

func newFindingFx(t *testing.T, e testEnv) *findingFx {
	t.Helper()
	idmx := &Idemix{Curve: e.curve, Translator: e.tr}
	rng, err := e.curve.Rand()
	require.NoError(t, err)
	key, err := idmx.NewIssuerKey([]string{"OU", "Role", "EID", "RH"}, rng, e.tr)
	require.NoError(t, err)
	sk := e.curve.NewRandomZr(rng)
	nonce := e.curve.NewRandomZr(rng)
	m, err := idmx.NewCredRequest(sk, nonce.Bytes(), key.Ipk, rng, e.tr)
	require.NoError(t, err)
	attrs := []*math.Zr{e.curve.NewZrFromInt(1), e.curve.NewZrFromInt(2), e.curve.NewZrFromInt(3), e.curve.NewZrFromInt(4)}
	cred, err := idmx.NewCredential(key, m, attrs, rng, e.tr)
	require.NoError(t, err)
	rk, err := idmx.GenerateLongTermRevocationKey()
	require.NoError(t, err)
	cri, err := idmx.CreateCRI(rk, nil, 0, ALG_NO_REVOCATION, rng, e.tr)
	require.NoError(t, err)
	nym, rnym, err := idmx.MakeNym(sk, key.Ipk, rng, e.tr)
	require.NoError(t, err)

	return &findingFx{e.curve, e.tr, idmx, key, sk, cred, cri, rk, nym, rnym, attrs}
}

func (f *findingFx) sign(t *testing.T, disc []byte, st opts.SignatureType) *Signature {
	t.Helper()
	rng, err := f.curve.Rand()
	require.NoError(t, err)
	sig, _, err := f.idmx.NewSignature(f.cred, f.sk, f.nym, f.rnym, f.key.Ipk, disc, fxMsg, fxRhIndex, fxEidIndex, f.cri, rng, f.tr, st, nil)
	require.NoError(t, err)

	return sig
}

func (f *findingFx) values(disc []byte) []*math.Zr {
	vals := make([]*math.Zr, len(disc))
	for i := range disc {
		if disc[i] != 0 {
			vals[i] = f.attrs[i]
		}
	}

	return vals
}

// ver calls Signature.Ver directly (no bridge-level recover) and fails the
// test if it panics.
func (f *findingFx) ver(t *testing.T, sig *Signature, disc []byte, vals []*math.Zr, eidIndex int, vt opts.VerificationType) error {
	t.Helper()
	var err error
	require.NotPanics(t, func() {
		err = sig.Ver(disc, f.key.Ipk, fxMsg, f.nym, vals, fxRhIndex, eidIndex, &f.rk.PublicKey, 0, f.curve, f.tr, vt, nil)
	})

	return err
}

var allHidden = []byte{0, 0, 0, 0}

// FINDING-DLOG-1: Signature.Ver dereferences sig.NonRevocationProof without a
// nil check (signature.go:842, again at :1028 and :1055). A signature whose
// non_revocation_proof field is simply omitted makes the verifier panic.
func TestFindingSignatureVerNilNonRevocationProof(t *testing.T) {
	for _, e := range envs {
		f := newFindingFx(t, e)
		sig := f.sign(t, allHidden, opts.Standard)
		require.NoError(t, f.ver(t, sig, allHidden, f.values(allHidden), fxEidIndex, opts.Basic))

		sig.NonRevocationProof = nil
		require.Error(t, f.ver(t, sig, allHidden, f.values(allHidden), fxEidIndex, opts.Basic))
	}
}

// FINDING-DLOG-2: with VerificationType BestEffort, a signature carrying an
// RhNym but no EidNym sets verifyRHNym, which forces verifyEIDNym, and then
// sig.EidNym.ProofSEid is dereferenced on a nil EidNym (signature.go:996).
func TestFindingSignatureVerBestEffortRhNymWithoutEidNym(t *testing.T) {
	for _, e := range envs {
		f := newFindingFx(t, e)
		sig := f.sign(t, allHidden, opts.Standard)
		sig.RhNym = &RHNym{Nym: sig.Nym, ProofSRh: []byte{1}}
		require.Error(t, f.ver(t, sig, allHidden, f.values(allHidden), fxEidIndex, opts.BestEffort))
	}
}

// FINDING-DLOG-3: Signature.Ver bounds-checks rhIndex but never eidIndex; when
// the eid nym is verified, ipk.HAttrs[eidIndex] is indexed directly
// (signature.go:991), so an out-of-range eidIndex panics instead of erroring.
func TestFindingSignatureVerEidIndexOutOfRange(t *testing.T) {
	for _, e := range envs {
		f := newFindingFx(t, e)
		sig := f.sign(t, allHidden, opts.EidNym)
		require.NoError(t, f.ver(t, sig, allHidden, f.values(allHidden), fxEidIndex, opts.ExpectEidNym))
		for _, idx := range []int{-1, 4, 9} {
			require.Error(t, f.ver(t, sig, allHidden, f.values(allHidden), idx, opts.ExpectEidNym), "eidIndex %d", idx)
		}
	}
}

// FINDING-DLOG-4: Signature.Ver does not check len(attributeValues) nor that
// disclosed entries are non-nil; HAttrs[index].Mul(attributeValues[index])
// (signature.go:979) panics on a short slice or a nil value.
func TestFindingSignatureVerMalformedAttributeValues(t *testing.T) {
	disc := []byte{1, 0, 0, 0}
	for _, e := range envs {
		f := newFindingFx(t, e)
		sig := f.sign(t, disc, opts.Standard)
		require.NoError(t, f.ver(t, sig, disc, f.values(disc), fxEidIndex, opts.Basic))

		require.Error(t, f.ver(t, sig, disc, nil, fxEidIndex, opts.Basic))
		require.Error(t, f.ver(t, sig, disc, make([]*math.Zr, len(disc)), fxEidIndex, opts.Basic))
	}
}

// FINDING-DLOG-5: Signature.Ver treats any VerificationType it does not know
// (including ExpectSmartcard / ExpectSmartcardNoNyms, which the dlog scheme
// does not implement, and out-of-range values) as Basic and accepts
// (signature.go:845-869). A caller asking for a property the scheme cannot
// verify gets a silent accept instead of an error.
func TestFindingSignatureVerUnsupportedVerificationTypeAccepted(t *testing.T) {
	for _, e := range envs {
		f := newFindingFx(t, e)
		sig := f.sign(t, allHidden, opts.Standard)
		for _, vt := range []opts.VerificationType{opts.ExpectSmartcard, opts.ExpectSmartcardNoNyms, opts.VerificationType(99)} {
			require.Error(t, f.ver(t, sig, allHidden, f.values(allHidden), fxEidIndex, vt), "verification type %d", vt)
		}
	}
}

// FINDING-DLOG-6: CredRequest.Check sizes its proof buffer for an IssuerNonce
// of exactly ScalarByteSize bytes and then copies ipk.Hash after the nonce
// (credrequest.go:111-118). A credential request whose issuer_nonce is longer
// makes copy(proofData[index:], ...) slice out of range and panic. The bridge
// only checks the nonce length after Check returns.
func TestFindingCredRequestCheckLongNonce(t *testing.T) {
	for _, e := range envs {
		f := newFindingFx(t, e)
		rng, err := f.curve.Rand()
		require.NoError(t, err)
		m, err := f.idmx.NewCredRequest(f.sk, f.curve.NewRandomZr(rng).Bytes(), f.key.Ipk, rng, f.tr)
		require.NoError(t, err)
		require.NoError(t, m.Check(f.key.Ipk, f.curve, f.tr))

		m.IssuerNonce = make([]byte, 4*f.curve.G1ByteSize)
		require.NotPanics(t, func() { err = m.Check(f.key.Ipk, f.curve, f.tr) })
		require.Error(t, err)
	}
}

// FINDING-DLOG-7: Credential.Ver never checks len(cred.Attrs) against the
// issuer key; a credential with more attributes than ipk.HAttrs indexes
// HAttrs out of range (credential.go:222/:230) and, for a nil extra entry,
// ipk.AttributeNames (credential.go:193).
func TestFindingCredentialVerExtraAttributes(t *testing.T) {
	for _, e := range envs {
		f := newFindingFx(t, e)
		require.NoError(t, f.cred.Ver(f.sk, f.key.Ipk, f.curve, f.tr))

		for _, extra := range [][][]byte{{{1}, {2}}, {{1}}, {nil}} {
			c := proto.Clone(f.cred).(*Credential)
			c.Attrs = append(c.Attrs, extra...)
			var err error
			require.NotPanics(t, func() { err = c.Ver(f.sk, f.key.Ipk, f.curve, f.tr) })
			require.Error(t, err)
		}
	}
}

// FINDING-DLOG-8: makeNymFromBytes slices raw without a length check
// (util.go:64-67); a short serialized nym key panics.
func TestFindingMakeNymFromBytesShortInput(t *testing.T) {
	for _, e := range envs {
		f := newFindingFx(t, e)
		for _, raw := range [][]byte{nil, {1, 2}, make([]byte, f.curve.ScalarByteSize+1)} {
			var err error
			require.NotPanics(t, func() { _, _, err = f.idmx.MakeNymFromBytes(raw) })
			require.Error(t, err)
		}
	}
}

// FINDING-DLOG-9: the audit functions only check the upper bound of the
// attribute index (`len(ipk.HAttrs) <= idx`), so a negative index panics
// (signature.go:746/:791, nymeid.go:39, nymrh.go:39).
func TestFindingAuditNegativeIndex(t *testing.T) {
	for _, e := range envs {
		f := newFindingFx(t, e)
		sig := f.sign(t, allHidden, opts.EidNymRhNym)
		r := f.curve.NewZrFromInt(1)
		raw := f.nym.Bytes()
		for name, audit := range map[string]func() error{
			"Signature.AuditNymEid": func() error { return sig.AuditNymEid(f.key.Ipk, f.attrs[2], -1, r, f.curve, f.tr) },
			"Signature.AuditNymRh":  func() error { return sig.AuditNymRh(f.key.Ipk, f.attrs[3], -1, r, f.curve, f.tr) },
			"NymEID.AuditNymEid":    func() error { return NymEID(raw).AuditNymEid(f.key.Ipk, f.attrs[2], -1, r, f.curve, f.tr) },
			"NymRH.AuditNymRh":      func() error { return NymRH(raw).AuditNymRh(f.key.Ipk, f.attrs[3], -1, r, f.curve, f.tr) },
		} {
			var err error
			require.NotPanics(t, func() { err = audit() }, name)
			require.Error(t, err, name)
		}
	}
}

// FINDING-DLOG-10: IssuerPublicKey.Check does not reject identity elements.
// On the gurvy curves (BN254, BLS12-*) the translator decodes the identity
// without error, so Check accepts (a) W = BarG2 = identity, i.e. issuer
// secret key 0, with a valid proof of knowledge of 0 (anyone can then compute
// A = B^{1/e} and forge credentials for any attributes), and (b) HSk/HRand/
// HAttrs[i] = identity, which removes the binding of the credential to the
// user secret key / randomness / attribute i (issuerkey.go:177-188).
func TestFindingIssuerPublicKeyCheckAcceptsIdentityElements(t *testing.T) {
	for _, e := range envs {
		f := newFindingFx(t, e)
		c := f.curve
		require.NoError(t, proto.Clone(f.key.Ipk).(*IssuerPublicKey).Check(c, f.tr))

		// (a) isk = 0 with a valid ZK proof
		rng, err := c.Rand()
		require.NoError(t, err)
		ipk := proto.Clone(f.key.Ipk).(*IssuerPublicKey)
		BarG1, err := f.tr.G1FromProto(ipk.BarG1)
		require.NoError(t, err)
		ipk.W = f.tr.G2ToProto(c.NewG2())
		ipk.BarG2 = f.tr.G1ToProto(c.NewG1())
		r := c.NewRandomZr(rng)
		pd := make([]byte, 3*c.G1ByteSize+3*c.G2ByteSize)
		i := appendBytesG2(pd, 0, c.GenG2.Mul(r))
		i = appendBytesG1(pd, i, BarG1.Mul(r))
		i = appendBytesG2(pd, i, c.GenG2)
		i = appendBytesG1(pd, i, BarG1)
		i = appendBytesG2(pd, i, c.NewG2())
		appendBytesG1(pd, i, c.NewG1())
		ipk.ProofC = c.HashToZr(pd).Bytes()
		ipk.ProofS = r.Bytes()
		require.Error(t, ipk.Check(c, f.tr), "issuer key with W = identity (isk = 0) must be rejected")

		// (b) identity generators
		for name, set := range map[string]func(*IssuerPublicKey){
			"HSk":       func(k *IssuerPublicKey) { k.HSk = f.tr.G1ToProto(c.NewG1()) },
			"HRand":     func(k *IssuerPublicKey) { k.HRand = f.tr.G1ToProto(c.NewG1()) },
			"HAttrs[0]": func(k *IssuerPublicKey) { k.HAttrs[0] = f.tr.G1ToProto(c.NewG1()) },
		} {
			k := proto.Clone(f.key.Ipk).(*IssuerPublicKey)
			set(k)
			require.Error(t, k.Check(c, f.tr), "issuer key with %s = identity must be rejected", name)
		}
	}
}

// FINDING-DLOG-11: verifyEpochPK ignores the `rest` returned by asn1.Unmarshal
// (revocation_authority.go:128), so an epoch PK signature with arbitrary
// trailing bytes is accepted: the signature encoding is malleable.
func TestFindingVerifyEpochPKAcceptsTrailingBytes(t *testing.T) {
	for _, e := range envs {
		f := newFindingFx(t, e)
		require.NoError(t, f.idmx.VerifyEpochPK(&f.rk.PublicKey, f.cri.EpochPk, f.cri.EpochPkSig, 0, ALG_NO_REVOCATION))
		mauled := append(append([]byte{}, f.cri.EpochPkSig...), 0xde, 0xad)
		require.Error(t, f.idmx.VerifyEpochPK(&f.rk.PublicKey, f.cri.EpochPk, mauled, 0, ALG_NO_REVOCATION))
	}
}
