/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"bytes"
	"sync"
	"testing"

	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/require"

	opts "github.com/IBM/idemix/bccsp/schemes"
	"github.com/IBM/idemix/bccsp/schemes/dlog/crypto/translator/amcl"
)

type testEnv struct {
	curve *math.Curve
	tr    Translator
}

var envs = []testEnv{
	{
		curve: math.Curves[math.FP256BN_AMCL],
		tr: &amcl.Fp256bn{
			C: math.Curves[math.FP256BN_AMCL],
		},
	},
	{
		curve: math.Curves[math.FP256BN_AMCL_MIRACL],
		tr: &amcl.Fp256bnMiracl{
			C: math.Curves[math.FP256BN_AMCL_MIRACL],
		},
	},
	{
		curve: math.Curves[math.BN254],
		tr: &amcl.Gurvy{
			C: math.Curves[math.BN254],
		},
	},
	{
		curve: math.Curves[math.BLS12_381],
		tr: &amcl.Gurvy{
			C: math.Curves[math.BLS12_381],
		},
	},
	{
		curve: math.Curves[math.BLS12_381_GURVY],
		tr: &amcl.Gurvy{
			C: math.Curves[math.BLS12_381_GURVY],
		},
	},
	{
		curve: math.Curves[math.BLS12_377_GURVY],
		tr: &amcl.Gurvy{
			C: math.Curves[math.BLS12_377_GURVY],
		},
	},
}

func TestIdemixAllCurves(t *testing.T) {
	for _, e := range envs {
		testIdemix(t, e.curve, e.tr)
	}
}

func testIdemix(t *testing.T, curve *math.Curve, tr Translator) {
	idmx := &Idemix{
		Curve: curve,
	}
	// Test weak BB sigs:
	// Test KeyGen
	rng, err := curve.Rand()
	require.NoError(t, err)
	wbbsk, wbbpk := wbbKeyGen(curve, rng)

	// Get random message
	testmsg := curve.NewRandomZr(rng)

	// Test Signing
	wbbsig := wbbSign(curve, wbbsk, testmsg)

	// Test Verification
	err = wbbVerify(curve, wbbpk, wbbsig, testmsg)
	require.NoError(t, err)

	// Test idemix functionality
	AttributeNames := []string{"Attr1", "Attr2", "Attr3", "Attr4", "Attr5"}
	attrs := make([]*math.Zr, len(AttributeNames))
	for i := range AttributeNames {
		attrs[i] = curve.NewZrFromInt(int64(i))
	}

	// Test issuer key generation
	if err != nil {
		t.Fatalf("Error getting rng: \"%s\"", err)
		return
	}
	// Create a new key pair
	key, err := idmx.NewIssuerKey(AttributeNames, rng, tr)
	if err != nil {
		t.Fatalf("Issuer key generation should have succeeded but gave error \"%s\"", err)
		return
	}

	// Check that the key is valid
	err = key.GetIpk().Check(curve, tr)
	if err != nil {
		t.Fatalf("Issuer public key should be valid")
		return
	}

	// Make sure Check() is invalid for a public key with invalid proof
	proofC := key.Ipk.GetProofC()
	key.Ipk.ProofC = curve.NewRandomZr(rng).Bytes()
	require.Error(t, key.Ipk.Check(curve, tr), "public key with broken zero-knowledge proof should be invalid")

	// Make sure Check() is invalid for a public key with incorrect number of HAttrs
	hAttrs := key.Ipk.GetHAttrs()
	key.Ipk.HAttrs = key.Ipk.HAttrs[:0]
	require.Error(t, key.Ipk.Check(curve, tr), "public key with incorrect number of HAttrs should be invalid")
	key.Ipk.HAttrs = hAttrs

	// Restore IPk to be valid
	key.Ipk.ProofC = proofC
	h := key.Ipk.GetHash()
	require.NoError(t, key.Ipk.Check(curve, tr), "restored public key should be valid")
	require.Zero(t, bytes.Compare(h, key.Ipk.GetHash()), "IPK hash changed on ipk Check")

	// Create public with duplicate attribute names should fail
	_, err = idmx.NewIssuerKey([]string{"Attr1", "Attr2", "Attr1"}, rng, tr)
	require.Error(t, err, "issuer key generation should fail with duplicate attribute names")

	// Test issuance
	sk := curve.NewRandomZr(rng)
	ni := curve.NewRandomZr(rng)
	m, err := idmx.NewCredRequest(sk, ni.Bytes(), key.Ipk, rng, tr)
	require.NoError(t, err, "NewCredRequest failed: \"%s\"", err)

	cred, err := idmx.NewCredential(key, m, attrs, rng, tr)
	require.NoError(t, err, "Failed to issue a credential: \"%s\"", err)

	require.NoError(t, cred.Ver(sk, key.Ipk, idmx.Curve, tr), "credential should be valid")

	// Issuing a credential with the incorrect amount of attributes should fail
	_, err = idmx.NewCredential(key, m, []*math.Zr{}, rng, tr)
	require.Error(t, err, "issuing a credential with the incorrect amount of attributes should fail")

	// Breaking the ZK proof of the CredRequest should make it invalid
	proofC = m.GetProofC()
	m.ProofC = curve.NewRandomZr(rng).Bytes()
	require.Error(t, m.Check(key.Ipk, idmx.Curve, tr), "CredRequest with broken ZK proof should not be valid")

	// Creating a credential from a broken CredRequest should fail
	_, err = idmx.NewCredential(key, m, attrs, rng, tr)
	require.Error(t, err, "creating a credential from an invalid CredRequest should fail")
	m.ProofC = proofC

	// A credential with nil attribute should be invalid
	attrsBackup := cred.GetAttrs()
	cred.Attrs = [][]byte{nil, nil, nil, nil, nil}
	require.Error(t, cred.Ver(sk, key.Ipk, idmx.Curve, tr), "credential with nil attribute should be invalid")
	cred.Attrs = attrsBackup

	// Generate a revocation key pair
	revocationKey, err := idmx.GenerateLongTermRevocationKey()
	require.NoError(t, err)

	// Create CRI that contains no revocation mechanism
	epoch := 0
	cri, err := idmx.CreateCRI(revocationKey, []*math.Zr{}, epoch, ALG_NO_REVOCATION, rng, tr)
	require.NoError(t, err)
	err = idmx.VerifyEpochPK(&revocationKey.PublicKey, cri.EpochPk, cri.EpochPkSig, int(cri.Epoch), RevocationAlgorithm(cri.RevocationAlg))
	require.NoError(t, err)

	// make sure that epoch pk is not valid in future epoch
	err = idmx.VerifyEpochPK(&revocationKey.PublicKey, cri.EpochPk, cri.EpochPkSig, int(cri.Epoch)+1, RevocationAlgorithm(cri.RevocationAlg))
	require.Error(t, err)

	// Test bad input
	_, err = idmx.CreateCRI(nil, []*math.Zr{}, epoch, ALG_NO_REVOCATION, rng, tr)
	require.Error(t, err)
	_, err = idmx.CreateCRI(revocationKey, []*math.Zr{}, epoch, ALG_NO_REVOCATION, nil, tr)
	require.Error(t, err)

	// Test signing no disclosure
	Nym, RandNym, err := idmx.MakeNym(sk, key.Ipk, rng, tr)
	require.NoError(t, err, "MakeNym failed: \"%s\"", err)

	disclosure := []byte{0, 0, 0, 0, 0}
	msg := []byte{1, 2, 3, 4, 5}
	rhindex := 4
	sig, _, err := idmx.NewSignature(cred, sk, Nym, RandNym, key.Ipk, disclosure, msg, rhindex, 0, cri, rng, tr, opts.Standard, nil)
	require.NoError(t, err)

	err = sig.Ver(disclosure, key.Ipk, msg, nil, 0, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.BestEffort, nil)
	if err != nil {
		t.Fatalf("Signature should be valid but verification returned error: %s", err)
		return
	}

	err = sig.Ver(disclosure, key.Ipk, msg, nil, 0, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectStandard, nil)
	if err != nil {
		t.Fatalf("Signature should be valid but verification returned error: %s", err)
		return
	}

	err = sig.Ver(disclosure, key.Ipk, msg, nil, 0, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectEidNym, nil)
	require.Error(t, err)
	require.Equal(t, "no EidNym provided but ExpectEidNym required", err.Error())

	eidIndex := 2
	sig, meta, err := idmx.NewSignature(cred, sk, Nym, RandNym, key.Ipk, disclosure, msg, rhindex, eidIndex, cri, rng, tr, opts.EidNym, nil)
	require.NoError(t, err)

	// assert that the returned randomness is the right one
	H_a_eid, err := tr.G1FromProto(key.Ipk.HAttrs[eidIndex])
	require.NoError(t, err, "G1FromProto failed: \"%s\"", err)
	HRand, err := tr.G1FromProto(key.Ipk.HRand)
	require.NoError(t, err, "G1FromProto failed: \"%s\"", err)
	Nym_eid := H_a_eid.Mul2(attrs[eidIndex], HRand, meta.EidNymAuditData.Rand)
	EidNym, err := tr.G1FromProto(sig.EidNym.Nym)
	require.NoError(t, err, "G1FromProto failed: \"%s\"", err)
	require.True(t, Nym_eid.Equals(EidNym))

	err = sig.Ver(disclosure, key.Ipk, msg, nil, 0, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.BestEffort, nil)
	if err != nil {
		t.Fatalf("Signature should be valid but verification returned error: %s", err)
		return
	}
	err = sig.Ver(disclosure, key.Ipk, msg, attrs, rhindex, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectEidNym, nil)
	require.NoError(t, err)
	err = sig.Ver(disclosure, key.Ipk, msg, attrs, rhindex, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectStandard, nil)
	require.Error(t, err)
	require.Equal(t, "EidNym available but ExpectStandard required", err.Error())

	// supply the meta to audit the nym eid
	err = sig.Ver(disclosure, key.Ipk, msg, attrs, 0, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.BestEffort, meta)
	require.NoError(t, err)
	err = sig.Ver(disclosure, key.Ipk, msg, attrs, 0, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectEidNym, meta)
	require.NoError(t, err)

	sig, meta2, err := idmx.NewSignature(cred, sk, Nym, RandNym, key.Ipk, disclosure, msg, rhindex, eidIndex, cri, rng, tr, opts.EidNym, meta)
	require.NoError(t, err)
	require.True(t, meta.EidNymAuditData.Rand.Equals(meta2.EidNymAuditData.Rand))
	require.True(t, meta.EidNymAuditData.Nym.Equals(meta2.EidNymAuditData.Nym))
	require.True(t, meta.EidNymAuditData.Attr.Equals(meta2.EidNymAuditData.Attr))
	err = sig.Ver(disclosure, key.Ipk, msg, attrs, rhindex, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectEidNym, meta2)
	require.NoError(t, err)
	err = sig.Ver(disclosure, key.Ipk, msg, attrs, rhindex, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectEidNym, meta)
	require.NoError(t, err)
	meta2.EidNym = meta2.EidNymAuditData.Nym.Bytes()
	err = sig.Ver(disclosure, key.Ipk, msg, attrs, rhindex, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectEidNym, meta2)
	require.NoError(t, err)
	meta2.EidNym = []byte{0, 1, 2}
	err = sig.Ver(disclosure, key.Ipk, msg, attrs, rhindex, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectEidNym, meta2)
	require.Equal(t, "signature invalid: nym eid validation failed, failed to unmarshal meta nym ied", err.Error())
	meta2.EidNym = meta2.EidNymAuditData.Nym.Mul(curve.NewZrFromInt(2)).Bytes()
	err = sig.Ver(disclosure, key.Ipk, msg, attrs, rhindex, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectEidNym, meta2)
	require.Equal(t, "signature invalid: nym eid validation failed, signature nym eid does not match metadata", err.Error())
	meta2.EidNym = nil
	meta2.EidNymAuditData.Nym = meta2.EidNymAuditData.Nym.Mul(curve.NewZrFromInt(2))
	err = sig.Ver(disclosure, key.Ipk, msg, attrs, rhindex, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectEidNym, meta2)
	require.Error(t, err)
	require.Equal(t, "signature invalid: nym eid validation failed, does not match metadata", err.Error())
	meta2.EidNymAuditData.Nym = nil
	err = sig.Ver(disclosure, key.Ipk, msg, attrs, rhindex, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectEidNym, meta2)
	require.NoError(t, err)

	// tamper with the randomness of the nym eid to expect a failed verification
	meta.EidNymAuditData.Attr = curve.NewZrFromInt(35)
	err = sig.Ver(disclosure, key.Ipk, msg, attrs, 0, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.BestEffort, meta)
	require.Error(t, err)
	require.Equal(t, "signature invalid: nym eid validation failed, does not match regenerated nym eid", err.Error())
	err = sig.Ver(disclosure, key.Ipk, msg, attrs, 0, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectEidNym, meta)
	require.Error(t, err)
	require.Equal(t, "signature invalid: nym eid validation failed, does not match regenerated nym eid", err.Error())

	// Test signing selective disclosure
	disclosure = []byte{0, 1, 1, 1, 0}
	sig, _, err = idmx.NewSignature(cred, sk, Nym, RandNym, key.Ipk, disclosure, msg, rhindex, 0, cri, rng, tr, opts.Standard, nil)
	require.NoError(t, err)

	err = sig.Ver(disclosure, key.Ipk, msg, attrs, rhindex, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.BestEffort, nil)
	require.NoError(t, err)
	err = sig.Ver(disclosure, key.Ipk, msg, attrs, rhindex, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectStandard, nil)
	require.NoError(t, err)
	err = sig.Ver(disclosure, key.Ipk, msg, attrs, rhindex, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectEidNym, nil)
	require.Error(t, err)
	require.Equal(t, "no EidNym provided but ExpectEidNym required", err.Error())

	// Test NymSignatures
	nymsig, err := idmx.NewNymSignature(sk, Nym, RandNym, key.Ipk, []byte("testing"), rng, tr)
	require.NoError(t, err)

	err = nymsig.Ver(Nym, key.Ipk, []byte("testing"), idmx.Curve, tr)
	if err != nil {
		t.Fatalf("NymSig should be valid but verification returned error: %s", err)
		return
	}
}

func TestCredentialVerParallelAMCL(t *testing.T) {
	t.Parallel()
	curve := math.Curves[math.FP256BN_AMCL_MIRACL]
	testCredentialVerParallel(
		t,
		curve,
		&amcl.Fp256bnMiracl{C: curve},
	)
}

func TestCredentialVerParallelGurvy254(t *testing.T) {
	t.Parallel()
	curve := math.Curves[math.BN254]
	testCredentialVerParallel(
		t,
		curve,
		&amcl.Gurvy{C: curve},
	)
}

func testCredentialVerParallel(t *testing.T, curve *math.Curve, tr Translator) {
	idmx := &Idemix{
		Curve: curve,
	}
	rng, err := curve.Rand()
	require.NoError(t, err)
	AttributeNames := []string{"Attr1", "Attr2", "Attr3", "Attr4", "Attr5"}
	attrs := make([]*math.Zr, len(AttributeNames))
	for i := range AttributeNames {
		attrs[i] = curve.NewZrFromInt(int64(i))
	}
	// Create a new key pair
	key, err := idmx.NewIssuerKey(AttributeNames, rng, tr)
	require.NoError(t, err)

	// Check that the key is valid
	err = key.GetIpk().Check(curve, tr)
	require.NoError(t, err)

	// Test issuance
	waitGroup := &sync.WaitGroup{}
	waitGroup.Add(100)
	for i := 0; i < 100; i++ {
		go func() {
			defer waitGroup.Done()

			rng, err := curve.Rand()
			require.NoError(t, err)
			sk := curve.NewRandomZr(rng)
			ni := curve.NewRandomZr(rng)
			m, err := idmx.NewCredRequest(sk, ni.Bytes(), key.Ipk, rng, tr)
			require.NoError(t, err, "NewCredRequest failed: \"%s\"", err)
			cred, err := idmx.NewCredential(key, m, attrs, rng, tr)
			require.NoError(t, err, "Failed to issue a credential: \"%s\"", err)
			require.NoError(t, cred.Ver(sk, key.Ipk, idmx.Curve, tr), "credential should be valid")
		}()
	}
	waitGroup.Wait()
}

func TestSigParallelAMCL(t *testing.T) {
	t.Parallel()
	curve := math.Curves[math.FP256BN_AMCL_MIRACL]
	testSigParallel(
		t,
		curve,
		&amcl.Fp256bnMiracl{C: curve},
	)
}

func TestSigParallelGurvy254(t *testing.T) {
	t.Parallel()
	curve := math.Curves[math.BN254]
	testSigParallel(
		t,
		curve,
		&amcl.Gurvy{C: curve},
	)
}

func testSigParallel(t *testing.T, curve *math.Curve, tr Translator) {
	idmx := &Idemix{
		Curve: curve,
	}
	// Test weak BB sigs:
	// Test KeyGen
	rng, err := curve.Rand()
	require.NoError(t, err)

	// Test idemix functionality
	AttributeNames := []string{"Attr1", "Attr2", "Attr3", "Attr4", "Attr5"}
	attrs := make([]*math.Zr, len(AttributeNames))
	for i := range AttributeNames {
		attrs[i] = curve.NewZrFromInt(int64(i))
	}

	// Create a new key pair
	key, err := idmx.NewIssuerKey(AttributeNames, rng, tr)
	require.NoError(t, err)

	// Check that the key is valid
	err = key.GetIpk().Check(curve, tr)
	require.NoError(t, err)

	// Test issuance
	sk := curve.NewRandomZr(rng)
	ni := curve.NewRandomZr(rng)
	m, err := idmx.NewCredRequest(sk, ni.Bytes(), key.Ipk, rng, tr)
	require.NoError(t, err, "NewCredRequest failed: \"%s\"", err)

	cred, err := idmx.NewCredential(key, m, attrs, rng, tr)
	require.NoError(t, err, "Failed to issue a credential: \"%s\"", err)
	require.NoError(t, cred.Ver(sk, key.Ipk, idmx.Curve, tr), "credential should be valid")

	// Generate a revocation key pair
	revocationKey, err := idmx.GenerateLongTermRevocationKey()
	require.NoError(t, err)

	// Create CRI that contains no revocation mechanism
	epoch := 0
	cri, err := idmx.CreateCRI(revocationKey, []*math.Zr{}, epoch, ALG_NO_REVOCATION, rng, tr)
	require.NoError(t, err)
	err = idmx.VerifyEpochPK(&revocationKey.PublicKey, cri.EpochPk, cri.EpochPkSig, int(cri.Epoch), RevocationAlgorithm(cri.RevocationAlg))
	require.NoError(t, err)

	Nym, RandNym, err := idmx.MakeNym(sk, key.Ipk, rng, tr)
	require.NoError(t, err, "MakeNym failed: \"%s\"", err)

	waitGroup := &sync.WaitGroup{}
	n := 100

	waitGroup.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer waitGroup.Done()
			rng, _ := curve.Rand()

			// Test signing no disclosure

			disclosure := []byte{0, 0, 0, 0, 0}
			msg := []byte{1, 2, 3, 4, 5}
			rhindex := 4
			sig, _, err := idmx.NewSignature(cred, sk, Nym, RandNym, key.Ipk, disclosure, msg, rhindex, 0, cri, rng, tr, opts.Standard, nil)
			require.NoError(t, err)

			err = sig.Ver(disclosure, key.Ipk, msg, nil, 0, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.BestEffort, nil)
			if err != nil {
				t.Logf("Signature should be valid but verification returned error: %s", err)
				t.Fail()
				return
			}

			err = sig.Ver(disclosure, key.Ipk, msg, nil, 0, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectStandard, nil)
			if err != nil {
				t.Logf("Signature should be valid but verification returned error: %s", err)
				t.Fail()
				return
			}

			err = sig.Ver(disclosure, key.Ipk, msg, nil, 0, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectEidNym, nil)
			require.Error(t, err)
			require.Equal(t, "no EidNym provided but ExpectEidNym required", err.Error())

			eidIndex := 2
			sig, meta, err := idmx.NewSignature(cred, sk, Nym, RandNym, key.Ipk, disclosure, msg, rhindex, eidIndex, cri, rng, tr, opts.EidNym, nil)
			require.NoError(t, err)

			// assert that the returned randomness is the right one
			H_a_eid, err := tr.G1FromProto(key.Ipk.HAttrs[eidIndex])
			if err != nil {
				t.Logf("G1FromProto returned error: %s", err)
				t.Fail()
				return
			}
			HRand, err := tr.G1FromProto(key.Ipk.HRand)
			if err != nil {
				t.Logf("G1FromProto returned error: %s", err)
				t.Fail()
				return
			}
			Nym_eid := H_a_eid.Mul2(attrs[eidIndex], HRand, meta.EidNymAuditData.Rand)
			EidNym, err := tr.G1FromProto(sig.EidNym.Nym)
			if err != nil {
				t.Logf("G1FromProto returned error: %s", err)
				t.Fail()
				return
			}
			require.True(t, Nym_eid.Equals(EidNym))

			err = sig.Ver(disclosure, key.Ipk, msg, nil, 0, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.BestEffort, nil)
			if err != nil {
				t.Logf("Signature should be valid but verification returned error: %s", err)
				t.Fail()
				return
			}
			err = sig.Ver(disclosure, key.Ipk, msg, attrs, rhindex, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectEidNym, nil)
			require.NoError(t, err)
			err = sig.Ver(disclosure, key.Ipk, msg, attrs, rhindex, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectStandard, nil)
			require.Error(t, err)
			require.Equal(t, "EidNym available but ExpectStandard required", err.Error())

			// supply the meta to audit the nym eid
			err = sig.Ver(disclosure, key.Ipk, msg, attrs, 0, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.BestEffort, meta)
			require.NoError(t, err)
			err = sig.Ver(disclosure, key.Ipk, msg, attrs, 0, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectEidNym, meta)
			require.NoError(t, err)
			// tamper with the randomness of the nym eid to expect a failed verification
			meta.EidNymAuditData.Attr = curve.NewZrFromInt(35)
			err = sig.Ver(disclosure, key.Ipk, msg, attrs, 0, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.BestEffort, meta)
			require.Error(t, err)
			require.Equal(t, "signature invalid: nym eid validation failed, does not match regenerated nym eid", err.Error())
			err = sig.Ver(disclosure, key.Ipk, msg, attrs, 0, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectEidNym, meta)
			require.Error(t, err)
			require.Equal(t, "signature invalid: nym eid validation failed, does not match regenerated nym eid", err.Error())

			// Test signing selective disclosure
			disclosure = []byte{0, 1, 1, 1, 0}
			sig, _, err = idmx.NewSignature(cred, sk, Nym, RandNym, key.Ipk, disclosure, msg, rhindex, 0, cri, rng, tr, opts.Standard, nil)
			require.NoError(t, err)

			err = sig.Ver(disclosure, key.Ipk, msg, attrs, rhindex, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.BestEffort, nil)
			require.NoError(t, err)
			err = sig.Ver(disclosure, key.Ipk, msg, attrs, rhindex, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectStandard, nil)
			require.NoError(t, err)
			err = sig.Ver(disclosure, key.Ipk, msg, attrs, rhindex, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectEidNym, nil)
			require.Error(t, err)
			require.Equal(t, "no EidNym provided but ExpectEidNym required", err.Error())
		}()
	}

	waitGroup.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer waitGroup.Done()
			rng, _ := curve.Rand()

			disclosure := []byte{0, 0, 0, 0, 0}
			msg := []byte{1, 2, 3, 4, 5}
			rhindex := 4

			eidIndex := 2
			sig, meta, err := idmx.NewSignature(cred, sk, Nym, RandNym, key.Ipk, disclosure, msg, rhindex, eidIndex, cri, rng, tr, opts.EidNym, nil)
			require.NoError(t, err)

			// assert that the returned randomness is the right one
			H_a_eid, err := tr.G1FromProto(key.Ipk.HAttrs[eidIndex])
			require.NoError(t, err)
			HRand, err := tr.G1FromProto(key.Ipk.HRand)
			require.NoError(t, err)
			Nym_eid := H_a_eid.Mul2(attrs[eidIndex], HRand, meta.EidNymAuditData.Rand)
			EidNym, err := tr.G1FromProto(sig.EidNym.Nym)
			require.NoError(t, err)
			require.True(t, Nym_eid.Equals(EidNym))

			// and now do it with the function
			err = sig.AuditNymEid(key.Ipk, attrs[eidIndex], eidIndex, meta.EidNymAuditData.Rand, idmx.Curve, tr)
			require.NoError(t, err)

			err = NymEID(meta.EidNymAuditData.Nym.Bytes()).AuditNymEid(key.Ipk, attrs[eidIndex], eidIndex, meta.EidNymAuditData.Rand, idmx.Curve, tr)
			require.NoError(t, err)

			err = sig.Ver(disclosure, key.Ipk, msg, nil, 0, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.BestEffort, nil)
			if err != nil {
				t.Logf("Signature should be valid but verification returned error: %s", err)
				t.Fail()
				return
			}
			err = sig.Ver(disclosure, key.Ipk, msg, attrs, rhindex, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectEidNym, nil)
			require.NoError(t, err)
			err = sig.Ver(disclosure, key.Ipk, msg, attrs, rhindex, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectStandard, nil)
			require.Error(t, err)
			require.Equal(t, "EidNym available but ExpectStandard required", err.Error())

			// supply the meta to audit the nym eid
			err = sig.Ver(disclosure, key.Ipk, msg, attrs, 0, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.BestEffort, meta)
			require.NoError(t, err)
			err = sig.Ver(disclosure, key.Ipk, msg, attrs, 0, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectEidNym, meta)
			require.NoError(t, err)
			// tamper with the randomness of the nym eid to expect a failed verification
			meta.EidNymAuditData.Attr = curve.NewZrFromInt(35)
			err = sig.Ver(disclosure, key.Ipk, msg, attrs, 0, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.BestEffort, meta)
			require.Error(t, err)
			require.Equal(t, "signature invalid: nym eid validation failed, does not match regenerated nym eid", err.Error())
			err = sig.Ver(disclosure, key.Ipk, msg, attrs, 0, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectEidNym, meta)
			require.Error(t, err)
			require.Equal(t, "signature invalid: nym eid validation failed, does not match regenerated nym eid", err.Error())
		}()
	}

	waitGroup.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer waitGroup.Done()
			rng, _ := curve.Rand()

			disclosure := []byte{0, 0, 0, 0, 0}
			msg := []byte{1, 2, 3, 4, 5}
			rhindex := 4

			eidIndex := 2
			sig, meta, err := idmx.NewSignature(cred, sk, Nym, RandNym, key.Ipk, disclosure, msg, rhindex, eidIndex, cri, rng, tr, opts.EidNymRhNym, nil)
			require.NoError(t, err)

			// assert that the returned randomness is the right one
			H_a_eid, err := tr.G1FromProto(key.Ipk.HAttrs[eidIndex])
			require.NoError(t, err)
			HRand, err := tr.G1FromProto(key.Ipk.HRand)
			require.NoError(t, err)
			Nym_eid := H_a_eid.Mul2(attrs[eidIndex], HRand, meta.EidNymAuditData.Rand)
			EidNym, err := tr.G1FromProto(sig.EidNym.Nym)
			require.NoError(t, err)
			require.True(t, Nym_eid.Equals(EidNym))

			// and now do it with the function
			err = sig.AuditNymEid(key.Ipk, attrs[eidIndex], eidIndex, meta.EidNymAuditData.Rand, idmx.Curve, tr)
			require.NoError(t, err)

			err = NymEID(meta.EidNymAuditData.Nym.Bytes()).AuditNymEid(key.Ipk, attrs[eidIndex], eidIndex, meta.EidNymAuditData.Rand, idmx.Curve, tr)
			require.NoError(t, err)

			err = sig.AuditNymRh(key.Ipk, attrs[rhindex], rhindex, meta.RhNymAuditData.Rand, idmx.Curve, tr)
			require.NoError(t, err)

			err = NymRH(meta.RhNymAuditData.Nym.Bytes()).AuditNymRh(key.Ipk, attrs[rhindex], rhindex, meta.RhNymAuditData.Rand, idmx.Curve, tr)
			require.NoError(t, err)

			err = sig.Ver(disclosure, key.Ipk, msg, nil, rhindex, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.BestEffort, nil)
			if err != nil {
				t.Logf("Signature should be valid but verification returned error: %s", err)
				t.Fail()
				return
			}
			err = sig.Ver(disclosure, key.Ipk, msg, attrs, rhindex, eidIndex, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectEidNymRhNym, nil)
			require.NoError(t, err)
			err = sig.Ver(disclosure, key.Ipk, msg, attrs, rhindex, eidIndex, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectEidNym, nil)
			require.Error(t, err)
			err = sig.Ver(disclosure, key.Ipk, msg, attrs, rhindex, eidIndex, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectStandard, nil)
			require.Error(t, err)
			require.Equal(t, "RhNym available but ExpectStandard required", err.Error())

			// supply the meta to audit the nym eid and rh
			err = sig.Ver(disclosure, key.Ipk, msg, attrs, rhindex, eidIndex, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.BestEffort, meta)
			require.NoError(t, err)
			err = sig.Ver(disclosure, key.Ipk, msg, attrs, rhindex, eidIndex, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectEidNym, meta)
			require.Error(t, err)
			err = sig.Ver(disclosure, key.Ipk, msg, attrs, rhindex, eidIndex, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectEidNymRhNym, meta)
			require.NoError(t, err)

			// tamper with the randomness of the nym eid to expect a failed verification
			tmp := meta.EidNymAuditData.Attr
			meta.EidNymAuditData.Attr = curve.NewZrFromInt(35)
			err = sig.Ver(disclosure, key.Ipk, msg, attrs, rhindex, eidIndex, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.BestEffort, meta)
			require.Error(t, err)
			require.Equal(t, "signature invalid: nym eid validation failed, does not match regenerated nym eid", err.Error())
			err = sig.Ver(disclosure, key.Ipk, msg, attrs, rhindex, eidIndex, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectEidNym, meta)
			require.Error(t, err)
			require.Equal(t, "signature invalid: nym eid validation failed, does not match regenerated nym eid", err.Error())
			err = sig.Ver(disclosure, key.Ipk, msg, attrs, rhindex, eidIndex, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectEidNymRhNym, meta)
			require.Error(t, err)
			require.Equal(t, "signature invalid: nym eid validation failed, does not match regenerated nym eid", err.Error())
			meta.EidNymAuditData.Attr = tmp

			// tamper with the randomness of the nym rh to expect a failed verification
			meta.RhNymAuditData.Attr = curve.NewZrFromInt(35)
			err = sig.Ver(disclosure, key.Ipk, msg, attrs, rhindex, eidIndex, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.BestEffort, meta)
			require.Error(t, err)
			require.Equal(t, "signature invalid: nym rh validation failed, does not match regenerated nym rh", err.Error())
			err = sig.Ver(disclosure, key.Ipk, msg, attrs, rhindex, eidIndex, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectEidNymRhNym, meta)
			require.Error(t, err)
			require.Equal(t, "signature invalid: nym rh validation failed, does not match regenerated nym rh", err.Error())
			err = sig.Ver(disclosure, key.Ipk, msg, attrs, rhindex, eidIndex, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectEidNym, meta)
			require.Error(t, err)
			require.Equal(t, "signature invalid: zero-knowledge proof is invalid", err.Error())
		}()
	}

	waitGroup.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer waitGroup.Done()
			rng, _ := curve.Rand()

			msg := []byte{1, 2, 3, 4, 5}
			rhindex := 4

			// Test signing selective disclosure
			disclosure := []byte{0, 1, 1, 1, 0}
			sig, _, err := idmx.NewSignature(cred, sk, Nym, RandNym, key.Ipk, disclosure, msg, rhindex, 0, cri, rng, tr, opts.Standard, nil)
			require.NoError(t, err)

			err = sig.Ver(disclosure, key.Ipk, msg, attrs, rhindex, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.BestEffort, nil)
			require.NoError(t, err)
			err = sig.Ver(disclosure, key.Ipk, msg, attrs, rhindex, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectStandard, nil)
			require.NoError(t, err)
			err = sig.Ver(disclosure, key.Ipk, msg, attrs, rhindex, 2, &revocationKey.PublicKey, epoch, idmx.Curve, tr, opts.ExpectEidNym, nil)
			require.Error(t, err)
			require.Equal(t, "no EidNym provided but ExpectEidNym required", err.Error())
		}()
	}

	waitGroup.Wait()
}

func TestNymSigParallelAMCL(t *testing.T) {
	t.Parallel()
	curve := math.Curves[math.FP256BN_AMCL_MIRACL]
	testNymSigParallel(
		t,
		curve,
		&amcl.Fp256bnMiracl{C: curve},
	)
}

func TestNymSigParallelGurvy254(t *testing.T) {
	t.Parallel()
	curve := math.Curves[math.BN254]
	testNymSigParallel(
		t,
		curve,
		&amcl.Gurvy{C: curve},
	)
}

func testNymSigParallel(t *testing.T, curve *math.Curve, tr Translator) {
	idmx := &Idemix{
		Curve: curve,
	}
	// Test weak BB sigs:
	// Test KeyGen
	rng, err := curve.Rand()
	require.NoError(t, err)

	// Test idemix functionality
	AttributeNames := []string{"Attr1", "Attr2", "Attr3", "Attr4", "Attr5"}
	attrs := make([]*math.Zr, len(AttributeNames))
	for i := range AttributeNames {
		attrs[i] = curve.NewZrFromInt(int64(i))
	}

	// Create a new key pair
	key, err := idmx.NewIssuerKey(AttributeNames, rng, tr)
	require.NoError(t, err)

	// Check that the key is valid
	err = key.GetIpk().Check(curve, tr)
	require.NoError(t, err)

	// Test issuance
	sk := curve.NewRandomZr(rng)
	ni := curve.NewRandomZr(rng)
	m, err := idmx.NewCredRequest(sk, ni.Bytes(), key.Ipk, rng, tr)
	require.NoError(t, err)

	cred, err := idmx.NewCredential(key, m, attrs, rng, tr)
	require.NoError(t, err, "Failed to issue a credential: \"%s\"", err)
	require.NoError(t, cred.Ver(sk, key.Ipk, idmx.Curve, tr), "credential should be valid")

	// Generate a revocation key pair
	revocationKey, err := idmx.GenerateLongTermRevocationKey()
	require.NoError(t, err)

	// Create CRI that contains no revocation mechanism
	epoch := 0
	cri, err := idmx.CreateCRI(revocationKey, []*math.Zr{}, epoch, ALG_NO_REVOCATION, rng, tr)
	require.NoError(t, err)
	err = idmx.VerifyEpochPK(&revocationKey.PublicKey, cri.EpochPk, cri.EpochPkSig, int(cri.Epoch), RevocationAlgorithm(cri.RevocationAlg))
	require.NoError(t, err)

	Nym, RandNym, err := idmx.MakeNym(sk, key.Ipk, rng, tr)
	require.NoError(t, err)

	waitGroup := &sync.WaitGroup{}
	n := 100

	waitGroup.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer waitGroup.Done()
			rng, _ := curve.Rand()

			// Test NymSignatures
			nymsig, err := idmx.NewNymSignature(sk, Nym, RandNym, key.Ipk, []byte("testing"), rng, tr)
			require.NoError(t, err)

			err = nymsig.Ver(Nym, key.Ipk, []byte("testing"), idmx.Curve, tr)
			if err != nil {
				t.Logf("NymSig should be valid but verification returned error: %s", err)
				t.Fail()
				return
			}
		}()
	}

	waitGroup.Wait()
}

func TestIPKCheckAMCL(t *testing.T) {
	t.Parallel()
	curve := math.Curves[math.FP256BN_AMCL_MIRACL]
	testIPKCheck(
		t,
		curve,
		&amcl.Fp256bnMiracl{C: curve},
	)
}

func TestIPKCheckGurvy254(t *testing.T) {
	t.Parallel()
	curve := math.Curves[math.BN254]
	testIPKCheck(
		t,
		curve,
		&amcl.Gurvy{C: curve},
	)
}

func testIPKCheck(t *testing.T, curve *math.Curve, tr Translator) {
	idmx := &Idemix{
		Curve: curve,
	}
	waitGroup := &sync.WaitGroup{}
	n := 50
	waitGroup.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer waitGroup.Done()
			// Test weak BB sigs:
			// Test KeyGen
			rng, err := curve.Rand()
			require.NoError(t, err)

			// Test idemix functionality
			AttributeNames := []string{"Attr1", "Attr2", "Attr3", "Attr4", "Attr5"}
			attrs := make([]*math.Zr, len(AttributeNames))
			for i := range AttributeNames {
				attrs[i] = curve.NewZrFromInt(int64(i))
			}

			// Create a new key pair
			key, err := idmx.NewIssuerKey(AttributeNames, rng, tr)
			require.NoError(t, err)

			// Check that the key is valid
			err = key.GetIpk().Check(curve, tr)
			require.NoError(t, err)
		}()
	}
	waitGroup.Wait()
}
