/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	"testing"

	"github.com/IBM/idemix/bbs"
	"github.com/IBM/idemix/bccsp/types"
	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

const (
	nymIdxEidIndex = 2
	nymIdxRhIndex  = 3
)

// nymIdxEnv is an issued credential (attr1, 34, eid, rh) with sk at position 0.
type nymIdxEnv struct {
	curve  *math.Curve
	ipk    *IssuerPublicKey
	cred   []byte
	sk     *math.Zr
	nym    *math.G1
	rNym   *math.Zr
	signer *Signer
	attrs  []types.IdemixAttribute
	msg    []byte
}

func newNymIdxEnv(t *testing.T) *nymIdxEnv {
	t.Helper()

	curve := math.Curves[math.BLS12_381_BBS]
	rng, err := curve.Rand()
	require.NoError(t, err)

	isk, err := (&Issuer{Curve: curve}).NewKey([]string{"attr1", "attr2", "eid", "rh"})
	require.NoError(t, err)
	ipk := isk.Public()

	user := &User{Curve: curve, Rng: rng}
	sk, err := user.NewKey()
	require.NoError(t, err)

	cr := &CredRequest{Curve: curve}
	credReq, blinding, err := cr.Blind(sk, ipk, []byte("nonce"))
	require.NoError(t, err)

	credAttrs := []types.IdemixAttribute{
		{Type: types.IdemixBytesAttribute, Value: []byte("attr1")},
		{Type: types.IdemixIntAttribute, Value: 34},
		{Type: types.IdemixBytesAttribute, Value: []byte("eid")},
		{Type: types.IdemixBytesAttribute, Value: []byte("rh")},
	}

	credProto := &Cred{BBS: bbs.New(curve), Curve: curve}
	cred, err := credProto.Sign(isk, credReq, credAttrs)
	require.NoError(t, err)
	cred, err = cr.Unblind(cred, blinding)
	require.NoError(t, err)
	require.NoError(t, credProto.Verify(sk, ipk, cred, credAttrs))

	nym, rNym, err := user.MakeNym(sk, ipk)
	require.NoError(t, err)

	return &nymIdxEnv{
		curve:  curve,
		ipk:    ipk.(*IssuerPublicKey),
		cred:   cred,
		sk:     sk,
		nym:    nym,
		rNym:   rNym,
		signer: &Signer{Curve: curve, Rng: rng},
		attrs: []types.IdemixAttribute{
			{Type: types.IdemixBytesAttribute, Value: []byte("attr1")},
			{Type: types.IdemixIntAttribute, Value: 34},
			{Type: types.IdemixHiddenAttribute},
			{Type: types.IdemixHiddenAttribute},
		},
		msg: []byte("msg"),
	}
}

func (env *nymIdxEnv) sign(t *testing.T, sigType types.SignatureType) []byte {
	t.Helper()

	sig, _, err := env.signer.Sign(env.cred, env.sk, env.nym, env.rNym, env.ipk, env.attrs, env.msg, nymIdxRhIndex, nymIdxEidIndex, nil, sigType, nil)
	require.NoError(t, err)

	return sig
}

func (env *nymIdxEnv) verify(sig []byte, verType types.VerificationType) error {
	return env.signer.Verify(env.ipk, sig, env.msg, env.nym, env.attrs, nymIdxRhIndex, nymIdxEidIndex, 0, nil, 0, verType, nil)
}

func rewrite(t *testing.T, sigBytes []byte, mutate func(sig *Signature)) []byte {
	t.Helper()

	sig := &Signature{}
	require.NoError(t, proto.Unmarshal(sigBytes, sig))
	mutate(sig)
	out, err := proto.Marshal(sig)
	require.NoError(t, err)

	return out
}

// forgeEidNymOverRh produces an EidNym signature whose nym eid commits, under the eid base,
// to the value of the rh attribute, i.e. NymEid = H0^r * H_eid^rh. The nym eid proof is tied
// to the main proof through the VC2 response of the hidden rh attribute: sig.NymEidIdx is set
// to the VC2 position of rh instead of that of eid. Everything else is honest.
func (env *nymIdxEnv) forgeEidNymOverRh(t *testing.T) []byte {
	t.Helper()

	s := env.signer
	ipk := env.ipk

	credential := &Credential{}
	require.NoError(t, proto.Unmarshal(env.cred, credential))
	skPos := int(credential.SkPos)
	require.Equal(t, 0, skPos)

	pokSignature, messagesFr, err := s.getPoKOfSignature(credential, env.attrs, env.sk, ipk.PKwG, types.EidNym, env.nym, env.rNym)
	require.NoError(t, err)

	commitNym := s.getCommitNym(ipk, pokSignature, types.EidNym, skPos, revealedAttributesIndex(env.attrs, skPos))

	eidInBases, rhInBases := nymIdxEidIndex+1, nymIdxRhIndex+1 // sk is at position 0
	rh := messagesFr[rhInBases].FR

	rhVC2, err := s.indexOfAttributeInCommitment(pokSignature.PokVC2, rhInBases, ipk.PKwG)
	require.NoError(t, err)

	R := env.curve.NewRandomZr(s.Rng)
	cb := bbs.NewCommitmentBuilder(2)
	cb.Add(ipk.PKwG.H0, R)
	cb.Add(ipk.PKwG.H[eidInBases], rh)

	commit := bbs.NewBBSLib(env.curve).NewProverCommittingG1()
	commit.Commit(ipk.PKwG.H0)
	commit.Commit(ipk.PKwG.H[eidInBases])
	commit.BlindingFactors[AttributeIndexInNym] = pokSignature.PokVC2.BlindingFactors[rhVC2]

	nymEid := &attributeCommitment{index: rhVC2, proof: commit.Finish(), comm: cb.Build(), r: R}

	challenge, nonce := s.getChallengeHash(pokSignature, env.nym, commitNym, nymEid, nil, env.msg, types.EidNym)

	proof := pokSignature.GenerateProof(challenge)
	proofNym := commitNym.GenerateProof(challenge, []*math.Zr{env.rNym, env.sk})
	proofNymEid := nymEid.proof.GenerateProof(challenge, []*math.Zr{R, rh})

	sig, err := s.packageProof(env.attrs, skPos, env.nym, proof, proofNym, nymEid, proofNymEid, nil, nil, &CredentialRevocationInformation{}, nonce)
	require.NoError(t, err)

	return sig
}

// TestFindingNymEidIdxMustReferToEidAttribute: sig.NymEidIdx / sig.NymRhIdx are carried by
// the (attacker controlled) signature and select the VC2 response the nym eid / nym rh proof
// is tied to. Signer.Verify only bounds-checked them, so they could point at the response of
// another hidden attribute, binding the nym eid (resp. rh) to a value other than the eid (rh).
func TestFindingNymEidIdxMustReferToEidAttribute(t *testing.T) {
	env := newNymIdxEnv(t)

	eidNym := env.sign(t, types.EidNym)
	require.NoError(t, env.verify(eidNym, types.ExpectEidNym))

	eidNymRhNym := env.sign(t, types.EidNymRhNym)
	require.NoError(t, env.verify(eidNymRhNym, types.ExpectEidNymRhNym))

	honest := &Signature{}
	require.NoError(t, proto.Unmarshal(eidNymRhNym, honest))
	eidIdx, rhIdx := honest.NymEidIdx, honest.NymRhIdx
	require.NotEqual(t, eidIdx, rhIdx)
	skIdx := int32(IndexOffsetVC2Attributes) // sk is the first hidden message

	t.Run("eid_nym_rewritten_to_rh", func(t *testing.T) {
		err := env.verify(rewrite(t, eidNym, func(sig *Signature) { sig.NymEidIdx = rhIdx }), types.ExpectEidNym)
		require.ErrorContains(t, err, "does not refer to the eid attribute")
	})

	t.Run("eid_nym_rewritten_to_sk", func(t *testing.T) {
		err := env.verify(rewrite(t, eidNym, func(sig *Signature) { sig.NymEidIdx = skIdx }), types.ExpectEidNym)
		require.ErrorContains(t, err, "does not refer to the eid attribute")
	})

	t.Run("eid_nym_rh_nym_eid_rewritten", func(t *testing.T) {
		err := env.verify(rewrite(t, eidNymRhNym, func(sig *Signature) { sig.NymEidIdx = rhIdx }), types.ExpectEidNymRhNym)
		require.ErrorContains(t, err, "does not refer to the eid attribute")
	})

	t.Run("eid_nym_rh_nym_rh_rewritten", func(t *testing.T) {
		err := env.verify(rewrite(t, eidNymRhNym, func(sig *Signature) { sig.NymRhIdx = eidIdx }), types.ExpectEidNymRhNym)
		require.ErrorContains(t, err, "does not refer to the rh attribute")

		err = env.verify(rewrite(t, eidNymRhNym, func(sig *Signature) { sig.NymRhIdx = skIdx }), types.ExpectEidNymRhNym)
		require.ErrorContains(t, err, "does not refer to the rh attribute")
	})

	t.Run("eid_nym_rh_nym_swapped", func(t *testing.T) {
		err := env.verify(rewrite(t, eidNymRhNym, func(sig *Signature) { sig.NymEidIdx, sig.NymRhIdx = rhIdx, eidIdx }), types.ExpectEidNymRhNym)
		require.ErrorContains(t, err, "does not refer to the eid attribute")
	})

	// Full attack: a nym eid that commits to the rh value under the eid base, with a
	// consistent proof tied to the rh VC2 response. All the proofs are valid: only the
	// index binding rejects it.
	t.Run("eid_nym_over_rh_forgery", func(t *testing.T) {
		forged := env.forgeEidNymOverRh(t)

		sig := &Signature{}
		require.NoError(t, proto.Unmarshal(forged, sig))
		require.Equal(t, rhIdx, sig.NymEidIdx)

		err := env.verify(forged, types.ExpectEidNym)
		require.ErrorContains(t, err, "does not refer to the eid attribute")

		err = env.verify(forged, types.BestEffort)
		require.ErrorContains(t, err, "does not refer to the eid attribute")
	})

	// The verifier discloses the eid (or rh) while expecting its nym: the expected VC2
	// index would then be the one of the next hidden attribute, so the request is rejected.
	t.Run("disclosed_attribute_with_nym", func(t *testing.T) {
		eidDisclosed := append([]types.IdemixAttribute(nil), env.attrs...)
		eidDisclosed[nymIdxEidIndex] = types.IdemixAttribute{Type: types.IdemixBytesAttribute, Value: []byte("eid")}
		disclosedEnv := *env
		disclosedEnv.attrs = eidDisclosed
		forged := disclosedEnv.forgeEidNymOverRh(t)
		for _, vt := range []types.VerificationType{types.ExpectEidNym, types.BestEffort} {
			err := env.signer.Verify(env.ipk, forged, env.msg, env.nym, eidDisclosed, nymIdxRhIndex, nymIdxEidIndex, 0, nil, 0, vt, nil)
			require.ErrorContains(t, err, "enrollment ID must be hidden")
		}

		rhDisclosed := append([]types.IdemixAttribute(nil), env.attrs...)
		rhDisclosed[nymIdxRhIndex] = types.IdemixAttribute{Type: types.IdemixBytesAttribute, Value: []byte("rh")}
		err := env.signer.Verify(env.ipk, eidNymRhNym, env.msg, env.nym, rhDisclosed, nymIdxRhIndex, nymIdxEidIndex, 0, nil, 0, types.ExpectEidNymRhNym, nil)
		require.ErrorContains(t, err, "revocation handle must be hidden")
	})
}

// A CRI for a non-zero epoch (fabric-ca starts at epoch 1) verifies when no
// epoch is configured (0) or the configured epoch matches, and fails otherwise.
func TestSignerVerifyNonZeroEpoch(t *testing.T) {
	env := newNymIdxEnv(t)
	rev := &RevocationAuthority{Curve: env.curve, Rng: env.signer.Rng}
	rk, err := rev.NewKey()
	require.NoError(t, err)
	cri, err := rev.Sign(rk, nil, 1, types.AlgNoRevocation)
	require.NoError(t, err)

	sig, _, err := env.signer.Sign(env.cred, env.sk, env.nym, env.rNym, env.ipk, env.attrs, env.msg, nymIdxRhIndex, nymIdxEidIndex, cri, types.Standard, nil)
	require.NoError(t, err)

	ver := func(sig []byte, epoch int) error {
		return env.signer.Verify(env.ipk, sig, env.msg, env.nym, env.attrs, nymIdxRhIndex, nymIdxEidIndex, 0, &rk.PublicKey, epoch, types.Basic, nil)
	}
	require.NoError(t, ver(sig, 0), "no configured epoch")
	require.NoError(t, ver(sig, 1), "matching epoch")
	require.ErrorContains(t, ver(sig, 2), "does not match the expected epoch")
	require.Error(t, ver(rewrite(t, sig, func(s *Signature) { s.Epoch = 2 }), 0), "epoch not signed by the revocation authority")
}
