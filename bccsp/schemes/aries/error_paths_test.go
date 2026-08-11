/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries_test

import (
	"crypto/rand"
	"testing"

	"github.com/IBM/idemix/bbs"
	"github.com/IBM/idemix/bccsp/schemes/aries"
	"github.com/IBM/idemix/bccsp/types"
	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// fakeIPK implements types.IssuerPublicKey but is NOT *aries.IssuerPublicKey.
// Used to trigger type-assertion error paths.
type fakeIPK struct{}

func (f *fakeIPK) Bytes() ([]byte, error) { return nil, nil }
func (f *fakeIPK) Hash() []byte           { return nil }

// setup creates a valid issuer key pair and user secret key for reuse across tests.
func setup(t *testing.T) (*aries.IssuerSecretKey, types.IssuerPublicKey, *math.Zr, *math.Curve) {
	t.Helper()

	curve := math.Curves[math.BLS12_381_BBS]
	issuer := &aries.Issuer{Curve: curve}

	isk, err := issuer.NewKey([]string{"attr1", "attr2", "attr3", "attr4"})
	require.NoError(t, err)

	ipk := isk.Public()

	rng, err := curve.Rand()
	require.NoError(t, err)

	user := &aries.User{Curve: curve, Rng: rng}
	sk, err := user.NewKey()
	require.NoError(t, err)

	return isk.(*aries.IssuerSecretKey), ipk, sk, curve
}

func TestErrorPaths_CredRequest_Blind(t *testing.T) {
	_, _, sk, curve := setup(t)

	cr := &aries.CredRequest{Curve: curve}

	t.Run("wrong_key_type", func(t *testing.T) {
		_, _, err := cr.Blind(sk, &fakeIPK{}, []byte("nonce"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid issuer public key")
	})
}

func TestErrorPaths_CredRequest_BlindVerify(t *testing.T) {
	_, ipk, sk, curve := setup(t)

	cr := &aries.CredRequest{Curve: curve}

	// Generate a valid credential request for some tests
	validCredReq, _, err := cr.Blind(sk, ipk, []byte("nonce"))
	require.NoError(t, err)

	t.Run("wrong_key_type", func(t *testing.T) {
		err := cr.BlindVerify(validCredReq, &fakeIPK{}, []byte("nonce"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid issuer public key")
	})

	t.Run("garbage_cred_request_bytes", func(t *testing.T) {
		err := cr.BlindVerify([]byte("garbage"), ipk, []byte("nonce"))
		require.Error(t, err)
	})

	t.Run("empty_cred_request_bytes", func(t *testing.T) {
		err := cr.BlindVerify([]byte{}, ipk, []byte("nonce"))
		require.Error(t, err)
	})

	t.Run("wrong_nonce", func(t *testing.T) {
		err := cr.BlindVerify(validCredReq, ipk, []byte("wrong-nonce"))
		require.Error(t, err)
	})
}

func TestErrorPaths_CredRequest_Unblind(t *testing.T) {
	_, _, _, curve := setup(t)

	cr := &aries.CredRequest{Curve: curve}

	t.Run("malformed_signature_bytes", func(t *testing.T) {
		// Not a valid protobuf
		_, err := cr.Unblind([]byte("not-a-protobuf"), curve.NewRandomZr(rand.Reader).Bytes())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "proto.Unmarshal failed")
	})

	t.Run("empty_signature_bytes", func(t *testing.T) {
		// Empty bytes will unmarshal to an empty Credential proto (valid proto, but Cred field is nil)
		_, err := cr.Unblind([]byte{}, curve.NewRandomZr(rand.Reader).Bytes())
		// Either returns error from UnblindSign or succeeds with empty credential
		// The important thing is it does NOT panic
		_ = err
	})
}

func TestErrorPaths_Signer_Sign(t *testing.T) {
	_, ipk, sk, curve := setup(t)

	rng, err := curve.Rand()
	require.NoError(t, err)

	signer := &aries.Signer{Curve: curve, Rng: rng}

	attributes := []types.IdemixAttribute{
		{Type: types.IdemixHiddenAttribute},
		{Type: types.IdemixHiddenAttribute},
		{Type: types.IdemixHiddenAttribute},
		{Type: types.IdemixHiddenAttribute},
	}

	Nym := curve.GenG1.Mul(curve.NewRandomZr(rng))
	RNym := curve.NewRandomZr(rng)

	t.Run("wrong_key_type", func(t *testing.T) {
		_, _, err := signer.Sign(
			[]byte("cred"), sk, Nym, RNym, &fakeIPK{},
			attributes, []byte("msg"), 2, 1, []byte("cri"),
			types.Standard, nil,
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid issuer public key")
	})

	t.Run("malformed_cri_bytes", func(t *testing.T) {
		_, _, err := signer.Sign(
			[]byte("cred"), sk, Nym, RNym, ipk,
			attributes, []byte("msg"), 2, 1, []byte("not-a-protobuf"),
			types.Standard, nil,
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed unmarshalling credential revocation information")
	})

	t.Run("unsupported_revocation_alg_in_cri", func(t *testing.T) {
		// Craft a CRI proto where RevocationAlg (field 4, varint) = 5.
		// Proto wire format: field_number=4, wire_type=0 → tag = (4<<3)|0 = 0x20, value = 0x05
		criWithBadAlg := []byte{0x20, 0x05}

		_, _, err = signer.Sign(
			[]byte("cred"), sk, Nym, RNym, ipk,
			attributes, []byte("msg"), 2, 1, criWithBadAlg,
			types.Standard, nil,
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported revocation algorithm")
	})

	t.Run("malformed_credential_bytes", func(t *testing.T) {
		// Valid CRI but bad credential bytes
		rev := &aries.RevocationAuthority{Rng: rng, Curve: curve}
		revKey, err := rev.NewKey()
		require.NoError(t, err)

		cri, err := rev.Sign(revKey, nil, 0, types.AlgNoRevocation)
		require.NoError(t, err)

		_, _, err = signer.Sign(
			[]byte("not-a-credential"), sk, Nym, RNym, ipk,
			attributes, []byte("msg"), 2, 1, cri,
			types.Standard, nil,
		)
		require.Error(t, err)
	})
}

func TestErrorPaths_Signer_Verify(t *testing.T) {
	_, ipk, _, curve := setup(t)

	rng, err := curve.Rand()
	require.NoError(t, err)

	signer := &aries.Signer{Curve: curve, Rng: rng}

	attributes := []types.IdemixAttribute{
		{Type: types.IdemixHiddenAttribute},
		{Type: types.IdemixHiddenAttribute},
		{Type: types.IdemixHiddenAttribute},
		{Type: types.IdemixHiddenAttribute},
	}

	t.Run("wrong_key_type", func(t *testing.T) {
		err := signer.Verify(
			&fakeIPK{}, []byte("sig"), []byte("msg"), nil,
			attributes, 2, 1, 0, nil, 0,
			types.ExpectStandard, nil,
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid issuer public key")
	})

	t.Run("garbage_signature_bytes", func(t *testing.T) {
		err := signer.Verify(
			ipk, []byte("garbage"), []byte("msg"), nil,
			attributes, 2, 1, 0, nil, 0,
			types.ExpectStandard, nil,
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "proto.Unmarshal error")
	})

	t.Run("empty_signature_bytes", func(t *testing.T) {
		err := signer.Verify(
			ipk, []byte{}, []byte("msg"), nil,
			attributes, 2, 1, 0, nil, 0,
			types.ExpectStandard, nil,
		)
		// Empty bytes unmarshal to empty Signature proto with nil NonRevocationProof
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no non-revocation proof")
	})
}

func TestErrorPaths_AuditNymEid(t *testing.T) {
	_, _, _, curve := setup(t)

	rng, err := curve.Rand()
	require.NoError(t, err)

	signer := &aries.Signer{Curve: curve, Rng: rng}

	t.Run("wrong_key_type", func(t *testing.T) {
		err := signer.AuditNymEid(
			&fakeIPK{}, 1, 0, []byte("sig"), "eid",
			curve.NewRandomZr(rng), types.AuditExpectSignature,
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid issuer public key")
	})

	t.Run("garbage_signature_AuditExpectSignature", func(t *testing.T) {
		_, ipk, _, _ := setup(t)
		err := signer.AuditNymEid(
			ipk, 1, 0, []byte("garbage"), "eid",
			curve.NewRandomZr(rng), types.AuditExpectSignature,
		)
		require.Error(t, err)
	})

	t.Run("garbage_signature_AuditExpectEidNym", func(t *testing.T) {
		_, ipk, _, _ := setup(t)
		err := signer.AuditNymEid(
			ipk, 1, 0, []byte("garbage"), "eid",
			curve.NewRandomZr(rng), types.AuditExpectEidNym,
		)
		require.Error(t, err)
	})

	t.Run("invalid_audit_type", func(t *testing.T) {
		_, ipk, _, _ := setup(t)
		err := signer.AuditNymEid(
			ipk, 1, 0, []byte("sig"), "eid",
			curve.NewRandomZr(rng), types.AuditVerificationType(99),
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid audit type")
	})
}

func TestErrorPaths_AuditNymRh(t *testing.T) {
	_, _, _, curve := setup(t)

	rng, err := curve.Rand()
	require.NoError(t, err)

	signer := &aries.Signer{Curve: curve, Rng: rng}

	t.Run("wrong_key_type", func(t *testing.T) {
		err := signer.AuditNymRh(
			&fakeIPK{}, 2, 0, []byte("sig"), "rh",
			curve.NewRandomZr(rng), types.AuditExpectSignature,
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid issuer public key")
	})

	t.Run("garbage_signature_AuditExpectSignature", func(t *testing.T) {
		_, ipk, _, _ := setup(t)
		err := signer.AuditNymRh(
			ipk, 2, 0, []byte("garbage"), "rh",
			curve.NewRandomZr(rng), types.AuditExpectSignature,
		)
		require.Error(t, err)
	})

	t.Run("garbage_signature_AuditExpectEidNymRhNym", func(t *testing.T) {
		_, ipk, _, _ := setup(t)
		err := signer.AuditNymRh(
			ipk, 2, 0, []byte("garbage"), "rh",
			curve.NewRandomZr(rng), types.AuditExpectEidNymRhNym,
		)
		require.Error(t, err)
	})

	t.Run("invalid_audit_type", func(t *testing.T) {
		_, ipk, _, _ := setup(t)
		err := signer.AuditNymRh(
			ipk, 2, 0, []byte("sig"), "rh",
			curve.NewRandomZr(rng), types.AuditVerificationType(99),
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid audit type")
	})
}

func TestErrorPaths_RevocationAuthority_Sign(t *testing.T) {
	curve := math.Curves[math.BLS12_381_BBS]
	rng, err := curve.Rand()
	require.NoError(t, err)

	rev := &aries.RevocationAuthority{Rng: rng, Curve: curve}

	t.Run("nil_key", func(t *testing.T) {
		_, err := rev.Sign(nil, nil, 0, types.AlgNoRevocation)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nil input")
	})

	t.Run("unsupported_algorithm", func(t *testing.T) {
		key, err := rev.NewKey()
		require.NoError(t, err)

		_, err = rev.Sign(key, nil, 0, types.RevocationAlgorithm(99))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not supported")
	})
}

func TestErrorPaths_RevocationAuthority_Verify(t *testing.T) {
	curve := math.Curves[math.BLS12_381_BBS]
	rng, err := curve.Rand()
	require.NoError(t, err)

	rev := &aries.RevocationAuthority{Rng: rng, Curve: curve}

	t.Run("nil_public_key", func(t *testing.T) {
		err := rev.Verify(nil, []byte("cri"), 0, types.AlgNoRevocation)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nil input")
	})

	t.Run("garbage_cri_bytes", func(t *testing.T) {
		key, err := rev.NewKey()
		require.NoError(t, err)

		err = rev.Verify(&key.PublicKey, []byte("garbage"), 0, types.AlgNoRevocation)
		require.Error(t, err)
	})

	t.Run("corrupted_epoch_signature", func(t *testing.T) {
		key, err := rev.NewKey()
		require.NoError(t, err)

		cri, err := rev.Sign(key, nil, 0, types.AlgNoRevocation)
		require.NoError(t, err)

		// Flip some bytes in the CRI to corrupt the ECDSA signature
		corrupted := make([]byte, len(cri))
		copy(corrupted, cri)
		corrupted[len(corrupted)-5] ^= 0xFF

		err = rev.Verify(&key.PublicKey, corrupted, 0, types.AlgNoRevocation)
		require.Error(t, err)
	})
}

func TestErrorPaths_ParseBlindedMessages(t *testing.T) {
	curve := math.Curves[math.BLS12_381_BBS]

	t.Run("too_short_bytes", func(t *testing.T) {
		_, err := aries.ParseBlindedMessages([]byte{0x01, 0x02, 0x03}, curve)
		require.Error(t, err)
	})

	t.Run("garbage_bytes_full_length", func(t *testing.T) {
		// Provide bytes that are the right length for two G1 points but contain garbage
		garbage := make([]byte, curve.CompressedG1ByteSize*2+100)
		for i := range garbage {
			garbage[i] = 0xAB
		}
		_, err := aries.ParseBlindedMessages(garbage, curve)
		require.Error(t, err)
	})

	t.Run("empty_bytes", func(t *testing.T) {
		_, err := aries.ParseBlindedMessages([]byte{}, curve)
		require.Error(t, err)
	})
}

func TestErrorPaths_Issuer_NewKeyFromBytes(t *testing.T) {
	curve := math.Curves[math.BLS12_381_BBS]
	issuer := &aries.Issuer{Curve: curve}

	t.Run("garbage_bytes", func(t *testing.T) {
		_, err := issuer.NewKeyFromBytes([]byte("garbage"), []string{"a", "b"})
		require.Error(t, err)
	})

	t.Run("empty_bytes", func(t *testing.T) {
		_, err := issuer.NewKeyFromBytes([]byte{}, []string{"a", "b"})
		require.Error(t, err)
	})
}

func TestErrorPaths_Issuer_NewPublicKeyFromBytes(t *testing.T) {
	curve := math.Curves[math.BLS12_381_BBS]
	issuer := &aries.Issuer{Curve: curve}

	t.Run("garbage_bytes", func(t *testing.T) {
		_, err := issuer.NewPublicKeyFromBytes([]byte("garbage"), []string{"a", "b"})
		require.Error(t, err)
	})

	t.Run("empty_bytes", func(t *testing.T) {
		_, err := issuer.NewPublicKeyFromBytes([]byte{}, []string{"a", "b"})
		require.Error(t, err)
	})
}

func TestErrorPaths_Issuer_Bases(t *testing.T) {
	curve := math.Curves[math.BLS12_381_BBS]
	issuer := &aries.Issuer{Curve: curve}

	isk, err := issuer.NewKey([]string{"attr1", "attr2", "attr3", "attr4"})
	require.NoError(t, err)
	ipk := isk.Public()

	t.Run("wrong_key_type", func(t *testing.T) {
		_, err := issuer.Bases(&fakeIPK{}, types.Dlog, 2, 1, 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid issuer public key")
	})

	t.Run("invalid_ipk_type", func(t *testing.T) {
		_, err := issuer.Bases(ipk, types.CommitmentBasesRequest(99), 2, 1, 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid ipk type")
	})

	t.Run("duplicate_indices", func(t *testing.T) {
		_, err := issuer.Bases(ipk, types.Dlog, 1, 1, 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid indices")
	})

	t.Run("index_out_of_range", func(t *testing.T) {
		_, err := issuer.Bases(ipk, types.Dlog, 99, 1, 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid indices")
	})
}

func TestErrorPaths_User_NewKeyFromBytes(t *testing.T) {
	curve := math.Curves[math.BLS12_381_BBS]
	rng, err := curve.Rand()
	require.NoError(t, err)

	user := &aries.User{Curve: curve, Rng: rng}

	t.Run("empty_bytes", func(t *testing.T) {
		_, err := user.NewKeyFromBytes([]byte{})
		require.Error(t, err)
	})

	t.Run("wrong_length_bytes", func(t *testing.T) {
		_, err := user.NewKeyFromBytes([]byte{0x01, 0x02, 0x03})
		require.Error(t, err)
	})
}

func TestErrorPaths_User_NewPublicNymFromBytes(t *testing.T) {
	curve := math.Curves[math.BLS12_381_BBS]
	rng, err := curve.Rand()
	require.NoError(t, err)

	user := &aries.User{Curve: curve, Rng: rng}

	t.Run("garbage_bytes", func(t *testing.T) {
		_, err := user.NewPublicNymFromBytes([]byte("garbage"))
		require.Error(t, err)
	})
}

// eidNymRhNymEnv holds a fully valid credential + EidNymRhNym signature, plus everything
// needed to re-verify it. Used by the F1/F2 regression tests below, which tamper with the
// unmarshalled *aries.Signature before re-marshalling and re-verifying.
type eidNymRhNymEnv struct {
	curve    *math.Curve
	ipk      types.IssuerPublicKey
	sigBytes []byte
	nym      *math.G1
	attrs    []types.IdemixAttribute
	msg      []byte
	rhIndex  int
	eidIndex int
	skIndex  int
}

// buildEidNymRhNymSignature signs a full EidNymRhNym signature end-to-end so that both
// NymEidIdx and NymRhIdx are populated (packageProof only sets them when the corresponding
// commitment is non-nil, which requires sigType EidNym/EidNymRhNym).
func buildEidNymRhNymSignature(t *testing.T) *eidNymRhNymEnv {
	t.Helper()

	curve := math.Curves[math.BLS12_381_BBS]
	issuer := &aries.Issuer{Curve: curve}

	attrNames := []string{"attr1", "attr2", "eid", "rh"}
	rhIndex, eidIndex, skIndex := 3, 2, 0

	isk, err := issuer.NewKey(attrNames)
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

	err = cr.BlindVerify(credReq, ipk, []byte("nonce"))
	require.NoError(t, err)

	credAttrs := []types.IdemixAttribute{
		{Type: types.IdemixBytesAttribute, Value: []byte("msg1")},
		{Type: types.IdemixIntAttribute, Value: 34},
		{Type: types.IdemixBytesAttribute, Value: []byte("nymeid")},
		{Type: types.IdemixBytesAttribute, Value: []byte("nymrh")},
	}

	credProto := &aries.Cred{BBS: bbs.New(curve), Curve: curve}

	cred, err := credProto.Sign(isk, credReq, credAttrs)
	require.NoError(t, err)

	cred, err = cr.Unblind(cred, blinding)
	require.NoError(t, err)

	err = credProto.Verify(sk, ipk, cred, credAttrs)
	require.NoError(t, err)

	Nym, RNym, err := user.MakeNym(sk, ipk)
	require.NoError(t, err)

	signer := &aries.Signer{Curve: curve, Rng: rng}

	sigAttrs := []types.IdemixAttribute{
		{Type: types.IdemixBytesAttribute, Value: []byte("msg1")},
		{Type: types.IdemixIntAttribute, Value: 34},
		{Type: types.IdemixHiddenAttribute},
		{Type: types.IdemixHiddenAttribute},
	}

	msg := []byte("silliness")

	sigBytes, _, err := signer.Sign(
		cred, sk, Nym, RNym, ipk, sigAttrs, msg, rhIndex, eidIndex, nil, types.EidNymRhNym, nil,
	)
	require.NoError(t, err)

	err = signer.Verify(ipk, sigBytes, msg, Nym, sigAttrs, rhIndex, eidIndex, skIndex, nil, 0, types.ExpectEidNymRhNym, nil)
	require.NoError(t, err)

	return &eidNymRhNymEnv{
		curve:    curve,
		ipk:      ipk,
		sigBytes: sigBytes,
		nym:      Nym,
		attrs:    sigAttrs,
		msg:      msg,
		rhIndex:  rhIndex,
		eidIndex: eidIndex,
		skIndex:  skIndex,
	}
}

// verify unmarshals env.sigBytes, applies mutate to the proto, re-marshals, and verifies.
func (env *eidNymRhNymEnv) verifyMutated(t *testing.T, mutate func(sig *aries.Signature)) error {
	t.Helper()

	sig := &aries.Signature{}
	err := proto.Unmarshal(env.sigBytes, sig)
	require.NoError(t, err)

	mutate(sig)

	tamperedBytes, err := proto.Marshal(sig)
	require.NoError(t, err)

	signer := &aries.Signer{Curve: env.curve}

	return signer.Verify(
		env.ipk, tamperedBytes, env.msg, env.nym, env.attrs,
		env.rhIndex, env.eidIndex, env.skIndex, nil, 0,
		types.ExpectEidNymRhNym, nil,
	)
}

// TestErrorPaths_Signer_Verify_NymEidIdxOutOfRange regression-tests F1: Signer.Verify used
// sig.NymEidIdx to index directly into signatureProof.ProofVC2.Responses without checking it
// against the slice bounds first, which could panic on an out-of-range index taken from an
// attacker-controlled, unmarshalled proto field.
func TestErrorPaths_Signer_Verify_NymEidIdxOutOfRange(t *testing.T) {
	env := buildEidNymRhNymSignature(t)

	t.Run("negative", func(t *testing.T) {
		err := env.verifyMutated(t, func(sig *aries.Signature) { sig.NymEidIdx = -1 })
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid signature: nym eid index out of range")
	})

	t.Run("too_large", func(t *testing.T) {
		err := env.verifyMutated(t, func(sig *aries.Signature) { sig.NymEidIdx = 1 << 20 })
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid signature: nym eid index out of range")
	})
}

// TestErrorPaths_Signer_Verify_NymRhIdxOutOfRange regression-tests F1 for sig.NymRhIdx, the
// analogous index used to look up signatureProof.ProofVC2.Responses for the RhNym equality check.
func TestErrorPaths_Signer_Verify_NymRhIdxOutOfRange(t *testing.T) {
	env := buildEidNymRhNymSignature(t)

	t.Run("negative", func(t *testing.T) {
		err := env.verifyMutated(t, func(sig *aries.Signature) { sig.NymRhIdx = -1 })
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid signature: nym rh index out of range")
	})

	t.Run("too_large", func(t *testing.T) {
		err := env.verifyMutated(t, func(sig *aries.Signature) { sig.NymRhIdx = 1 << 20 })
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid signature: nym rh index out of range")
	})
}

// truncateProofG1Responses re-parses a ProofG1-encoded byte slice and re-serializes it with
// its Responses truncated to n entries, keeping the same Commitment.
func truncateProofG1Responses(t *testing.T, curve *math.Curve, proofBytes []byte, n int) []byte {
	t.Helper()

	proof, err := bbs.NewBBSLib(curve).ParseProofG1(proofBytes)
	require.NoError(t, err)

	truncated := bbs.NewProofG1(proof.Commitment, proof.Responses[:n])

	return truncated.ToBytes()
}

// TestErrorPaths_Signer_Verify_NymProofNotEnoughResponses regression-tests F2: Signer.Verify
// indexed nymProof.Responses[AttributeIndexInNym] without first checking that the attacker-
// controlled, unmarshalled ProofG1 actually had enough responses, which could panic.
func TestErrorPaths_Signer_Verify_NymProofNotEnoughResponses(t *testing.T) {
	env := buildEidNymRhNymSignature(t)

	err := env.verifyMutated(t, func(sig *aries.Signature) {
		sig.NymProof = truncateProofG1Responses(t, env.curve, sig.NymProof, 1)
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid nym proof: not enough responses")
}

// TestErrorPaths_Signer_Verify_NymEidProofNotEnoughResponses regression-tests F2 for
// sig.NymEidProof, the analogous ProofG1 used in the EidNym equality check.
func TestErrorPaths_Signer_Verify_NymEidProofNotEnoughResponses(t *testing.T) {
	env := buildEidNymRhNymSignature(t)

	err := env.verifyMutated(t, func(sig *aries.Signature) {
		sig.NymEidProof = truncateProofG1Responses(t, env.curve, sig.NymEidProof, 1)
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid nym eid proof: not enough responses")
}

// TestErrorPaths_Signer_Verify_NymRhProofNotEnoughResponses regression-tests F2 for
// sig.NymRhProof, the analogous ProofG1 used in the RhNym equality check.
func TestErrorPaths_Signer_Verify_NymRhProofNotEnoughResponses(t *testing.T) {
	env := buildEidNymRhNymSignature(t)

	err := env.verifyMutated(t, func(sig *aries.Signature) {
		sig.NymRhProof = truncateProofG1Responses(t, env.curve, sig.NymRhProof, 1)
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid rh nym proof: not enough responses")
}

// TestErrorPaths_Signer_Verify_SkIndexOutOfRange regression-tests F2's sibling bounds check:
// Signer.Verify computed skRespIdx := IndexOffsetVC2Attributes + skIndex and indexed
// signatureProof.ProofVC2.Responses with it without checking it against the slice length,
// which could panic when the caller-supplied skIndex is out of range.
//
// skIndex must stay within [0, len(attributes)] to avoid panicking earlier, inside
// attributesToSignatureMessage's own slicing on the attributes list — the case exercised here
// is a skIndex that is in range for that slice but still out of range for skRespIdx against
// signatureProof.ProofVC2.Responses.
func TestErrorPaths_Signer_Verify_SkIndexOutOfRange(t *testing.T) {
	env := buildEidNymRhNymSignature(t)

	signer := &aries.Signer{Curve: env.curve}

	err := signer.Verify(
		env.ipk, env.sigBytes, env.msg, env.nym, env.attrs,
		env.rhIndex, env.eidIndex, len(env.attrs), nil, 0,
		types.ExpectEidNymRhNym, nil,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid signature: sk index out of range")
}

// TestErrorPaths_Cred_Verify_SkPosOutOfRange regression-tests F3: Cred.Verify used
// credential.SkPos, an attacker-controlled unmarshalled proto field, to index ipk.PKwG.H and
// to select which credential.Attrs[i] to skip, without validating it against len(ipk.PKwG.H)
// first, which could panic on an out-of-range or negative value.
func TestErrorPaths_Cred_Verify_SkPosOutOfRange(t *testing.T) {
	curve := math.Curves[math.BLS12_381_BBS]
	issuer := &aries.Issuer{Curve: curve}

	attrNames := []string{"attr1", "attr2", "attr3", "attr4"}

	isk, err := issuer.NewKey(attrNames)
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
		{Type: types.IdemixBytesAttribute, Value: []byte("msg1")},
		{Type: types.IdemixIntAttribute, Value: 34},
		{Type: types.IdemixBytesAttribute, Value: []byte("msg3")},
		{Type: types.IdemixBytesAttribute, Value: []byte("msg4")},
	}

	credProto := &aries.Cred{BBS: bbs.New(curve), Curve: curve}

	credBytes, err := credProto.Sign(isk, credReq, credAttrs)
	require.NoError(t, err)

	credBytes, err = cr.Unblind(credBytes, blinding)
	require.NoError(t, err)

	err = credProto.Verify(sk, ipk, credBytes, credAttrs)
	require.NoError(t, err)

	verifyWithSkPos := func(skPos int32) error {
		cred := &aries.Credential{}
		uerr := proto.Unmarshal(credBytes, cred)
		require.NoError(t, uerr)

		cred.SkPos = skPos

		tamperedBytes, merr := proto.Marshal(cred)
		require.NoError(t, merr)

		return credProto.Verify(sk, ipk, tamperedBytes, credAttrs)
	}

	t.Run("negative", func(t *testing.T) {
		err := verifyWithSkPos(-1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid credential: sk_pos [-1] out of range")
	})

	t.Run("too_large", func(t *testing.T) {
		err := verifyWithSkPos(1 << 20)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid credential: sk_pos [1048576] out of range")
	})
}
