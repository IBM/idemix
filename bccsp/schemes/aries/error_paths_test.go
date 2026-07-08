/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries_test

import (
	"crypto/rand"
	"testing"

	"github.com/IBM/idemix/bccsp/schemes/aries"
	"github.com/IBM/idemix/bccsp/types"
	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		assert.Error(t, err)
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
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid issuer public key")
	})

	t.Run("garbage_cred_request_bytes", func(t *testing.T) {
		err := cr.BlindVerify([]byte("garbage"), ipk, []byte("nonce"))
		assert.Error(t, err)
	})

	t.Run("empty_cred_request_bytes", func(t *testing.T) {
		err := cr.BlindVerify([]byte{}, ipk, []byte("nonce"))
		assert.Error(t, err)
	})

	t.Run("wrong_nonce", func(t *testing.T) {
		err := cr.BlindVerify(validCredReq, ipk, []byte("wrong-nonce"))
		assert.Error(t, err)
	})
}

func TestErrorPaths_CredRequest_Unblind(t *testing.T) {
	_, _, _, curve := setup(t)

	cr := &aries.CredRequest{Curve: curve}

	t.Run("malformed_signature_bytes", func(t *testing.T) {
		// Not a valid protobuf
		_, err := cr.Unblind([]byte("not-a-protobuf"), curve.NewRandomZr(rand.Reader).Bytes())
		assert.Error(t, err)
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
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid issuer public key")
	})

	t.Run("malformed_cri_bytes", func(t *testing.T) {
		_, _, err := signer.Sign(
			[]byte("cred"), sk, Nym, RNym, ipk,
			attributes, []byte("msg"), 2, 1, []byte("not-a-protobuf"),
			types.Standard, nil,
		)
		assert.Error(t, err)
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
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Unsupported revocation algorithm")
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
		assert.Error(t, err)
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
			&fakeIPK{}, []byte("sig"), []byte("msg"),
			attributes, 2, 1, 0, nil, 0,
			types.ExpectStandard, nil,
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid issuer public key")
	})

	t.Run("garbage_signature_bytes", func(t *testing.T) {
		err := signer.Verify(
			ipk, []byte("garbage"), []byte("msg"),
			attributes, 2, 1, 0, nil, 0,
			types.ExpectStandard, nil,
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "proto.Unmarshal error")
	})

	t.Run("empty_signature_bytes", func(t *testing.T) {
		err := signer.Verify(
			ipk, []byte{}, []byte("msg"),
			attributes, 2, 1, 0, nil, 0,
			types.ExpectStandard, nil,
		)
		// Empty bytes unmarshal to empty Signature proto with nil NonRevocationProof
		assert.Error(t, err)
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
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid issuer public key")
	})

	t.Run("garbage_signature_AuditExpectSignature", func(t *testing.T) {
		_, ipk, _, _ := setup(t)
		err := signer.AuditNymEid(
			ipk, 1, 0, []byte("garbage"), "eid",
			curve.NewRandomZr(rng), types.AuditExpectSignature,
		)
		assert.Error(t, err)
	})

	t.Run("garbage_signature_AuditExpectEidNym", func(t *testing.T) {
		_, ipk, _, _ := setup(t)
		err := signer.AuditNymEid(
			ipk, 1, 0, []byte("garbage"), "eid",
			curve.NewRandomZr(rng), types.AuditExpectEidNym,
		)
		assert.Error(t, err)
	})

	t.Run("invalid_audit_type", func(t *testing.T) {
		_, ipk, _, _ := setup(t)
		err := signer.AuditNymEid(
			ipk, 1, 0, []byte("sig"), "eid",
			curve.NewRandomZr(rng), types.AuditVerificationType(99),
		)
		assert.Error(t, err)
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
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid issuer public key")
	})

	t.Run("garbage_signature_AuditExpectSignature", func(t *testing.T) {
		_, ipk, _, _ := setup(t)
		err := signer.AuditNymRh(
			ipk, 2, 0, []byte("garbage"), "rh",
			curve.NewRandomZr(rng), types.AuditExpectSignature,
		)
		assert.Error(t, err)
	})

	t.Run("garbage_signature_AuditExpectEidNymRhNym", func(t *testing.T) {
		_, ipk, _, _ := setup(t)
		err := signer.AuditNymRh(
			ipk, 2, 0, []byte("garbage"), "rh",
			curve.NewRandomZr(rng), types.AuditExpectEidNymRhNym,
		)
		assert.Error(t, err)
	})

	t.Run("invalid_audit_type", func(t *testing.T) {
		_, ipk, _, _ := setup(t)
		err := signer.AuditNymRh(
			ipk, 2, 0, []byte("sig"), "rh",
			curve.NewRandomZr(rng), types.AuditVerificationType(99),
		)
		assert.Error(t, err)
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
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nil input")
	})

	t.Run("unsupported_algorithm", func(t *testing.T) {
		key, err := rev.NewKey()
		require.NoError(t, err)

		_, err = rev.Sign(key, nil, 0, types.RevocationAlgorithm(99))
		assert.Error(t, err)
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
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nil input")
	})

	t.Run("garbage_cri_bytes", func(t *testing.T) {
		key, err := rev.NewKey()
		require.NoError(t, err)

		err = rev.Verify(&key.PublicKey, []byte("garbage"), 0, types.AlgNoRevocation)
		assert.Error(t, err)
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
		assert.Error(t, err)
	})
}

func TestErrorPaths_ParseBlindedMessages(t *testing.T) {
	curve := math.Curves[math.BLS12_381_BBS]

	t.Run("too_short_bytes", func(t *testing.T) {
		_, err := aries.ParseBlindedMessages([]byte{0x01, 0x02, 0x03}, curve)
		assert.Error(t, err)
	})

	t.Run("garbage_bytes_full_length", func(t *testing.T) {
		// Provide bytes that are the right length for two G1 points but contain garbage
		garbage := make([]byte, curve.CompressedG1ByteSize*2+100)
		for i := range garbage {
			garbage[i] = 0xAB
		}
		_, err := aries.ParseBlindedMessages(garbage, curve)
		assert.Error(t, err)
	})

	t.Run("empty_bytes", func(t *testing.T) {
		_, err := aries.ParseBlindedMessages([]byte{}, curve)
		assert.Error(t, err)
	})
}

func TestErrorPaths_Issuer_NewKeyFromBytes(t *testing.T) {
	curve := math.Curves[math.BLS12_381_BBS]
	issuer := &aries.Issuer{Curve: curve}

	t.Run("garbage_bytes", func(t *testing.T) {
		_, err := issuer.NewKeyFromBytes([]byte("garbage"), []string{"a", "b"})
		assert.Error(t, err)
	})

	t.Run("empty_bytes", func(t *testing.T) {
		_, err := issuer.NewKeyFromBytes([]byte{}, []string{"a", "b"})
		assert.Error(t, err)
	})
}

func TestErrorPaths_Issuer_NewPublicKeyFromBytes(t *testing.T) {
	curve := math.Curves[math.BLS12_381_BBS]
	issuer := &aries.Issuer{Curve: curve}

	t.Run("garbage_bytes", func(t *testing.T) {
		_, err := issuer.NewPublicKeyFromBytes([]byte("garbage"), []string{"a", "b"})
		assert.Error(t, err)
	})

	t.Run("empty_bytes", func(t *testing.T) {
		_, err := issuer.NewPublicKeyFromBytes([]byte{}, []string{"a", "b"})
		assert.Error(t, err)
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
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid issuer public key")
	})

	t.Run("invalid_ipk_type", func(t *testing.T) {
		_, err := issuer.Bases(ipk, types.CommitmentBasesRequest(99), 2, 1, 0)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid ipk type")
	})

	t.Run("duplicate_indices", func(t *testing.T) {
		_, err := issuer.Bases(ipk, types.Dlog, 1, 1, 0)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid indices")
	})

	t.Run("index_out_of_range", func(t *testing.T) {
		_, err := issuer.Bases(ipk, types.Dlog, 99, 1, 0)
		assert.Error(t, err)
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
		assert.Error(t, err)
	})

	t.Run("wrong_length_bytes", func(t *testing.T) {
		_, err := user.NewKeyFromBytes([]byte{0x01, 0x02, 0x03})
		assert.Error(t, err)
	})
}

func TestErrorPaths_User_NewPublicNymFromBytes(t *testing.T) {
	curve := math.Curves[math.BLS12_381_BBS]
	rng, err := curve.Rand()
	require.NoError(t, err)

	user := &aries.User{Curve: curve, Rng: rng}

	t.Run("garbage_bytes", func(t *testing.T) {
		_, err := user.NewPublicNymFromBytes([]byte("garbage"))
		assert.Error(t, err)
	})
}
