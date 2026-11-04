/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"testing"
	"time"

	"github.com/IBM/idemix/bccsp/schemes/aries"
	idemix "github.com/IBM/idemix/bccsp/schemes/dlog/crypto"
	im "github.com/IBM/idemix/msp/config"
	m "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// findingSchemeCurves is a small, fast subset of the fixtures (one per scheme).
var findingSchemeCurves = []schemeCurve{
	{scheme: "dlog", curveID: curveIDBN254},
	{scheme: "aries", curveID: curveIDBLS12_381_BBS},
}

func forFindingSchemeCurves(t *testing.T, fn func(t *testing.T, sc schemeCurve)) {
	t.Helper()
	for _, sc := range findingSchemeCurves {
		t.Run(sc.name(), func(t *testing.T) { fn(t, sc) })
	}
}

// serializedIdemix returns the inner SerializedIdemixIdentity of id.
func serializedIdemix(t *testing.T, id Identity) *im.SerializedIdemixIdentity {
	t.Helper()
	raw, err := id.Serialize()
	require.NoError(t, err)
	sID := &m.SerializedIdentity{}
	require.NoError(t, proto.Unmarshal(raw, sID))
	s := &im.SerializedIdemixIdentity{}
	require.NoError(t, proto.Unmarshal(sID.IdBytes, s))

	return s
}

func outerIdentity(t *testing.T, mspID string, s *im.SerializedIdemixIdentity) []byte {
	t.Helper()
	inner, err := proto.Marshal(s)
	require.NoError(t, err)
	outer, err := proto.Marshal(&m.SerializedIdentity{Mspid: mspID, IdBytes: inner})
	require.NoError(t, err)

	return outer
}

// FINDING-MSP-1: MSP.Validate (and therefore MSP.SatisfiesPrincipal) only compares the MSP
// *name* of the identity and then calls identity.Validate, which verifies the association
// proof with the identity's own MSP instance (its csp, ipk, revocation pk). An identity built
// by MSP A is therefore accepted by MSP B as long as both are named the same, even if B trusts
// a completely different issuer.
func TestFindingValidateUsesIdentityOwnMSPNotReceiver(t *testing.T) {
	// Two MSPs with the same name but different issuers (different CA key material).
	mspA, err := setupCurve(t, schemeCurve{scheme: "dlog", curveID: curveIDBN254}, "SameName")
	require.NoError(t, err)
	mspB, err := setupCurve(t, schemeCurve{scheme: "dlog", curveID: curveIDBLS12_381}, "SameName")
	require.NoError(t, err)
	require.NotEqual(t, mspA.IssuerPublicKey(), mspB.IssuerPublicKey())

	idA, err := mspA.GetDefaultSigningIdentity()
	require.NoError(t, err)

	// Sanity: the serialized identity of A is rejected by B (B uses its own ipk).
	raw, err := idA.Serialize()
	require.NoError(t, err)
	if d, err := mspB.DeserializeIdentity(raw); err == nil {
		require.Error(t, mspB.Validate(d))
	}

	// But the in-memory identity object of A is accepted by B.
	require.Error(t, mspB.Validate(idA), "an identity certified by another issuer must not validate under this MSP")

	member, err := proto.Marshal(&m.MSPRole{MspIdentifier: "SameName", Role: m.MSPRole_MEMBER})
	require.NoError(t, err)
	require.Error(t, mspB.SatisfiesPrincipal(idA, &m.MSPPrincipal{
		PrincipalClassification: m.MSPPrincipal_ROLE,
		Principal:               member,
	}), "an identity certified by another issuer must not satisfy this MSP's principals")
}

// FINDING-MSP-2: satisfiesPrincipalValidated recurses on COMBINED principals without any
// depth bound. Each level re-unmarshals (and copies) the remaining nested bytes, so a ~1MB
// principal of 100k nested levels takes >10s of CPU (quadratic), and deeper nesting is only
// bounded by the Go stack limit.
func TestFindingCombinedPrincipalUnboundedNesting(t *testing.T) {
	mspI, err := setupCurve(t, schemeCurve{scheme: "dlog", curveID: curveIDBN254}, "MSP1")
	require.NoError(t, err)
	id, err := mspI.GetDefaultSigningIdentity()
	require.NoError(t, err)

	member, err := proto.Marshal(&m.MSPRole{Role: m.MSPRole_MEMBER, MspIdentifier: "MSP1"})
	require.NoError(t, err)
	p := &m.MSPPrincipal{PrincipalClassification: m.MSPPrincipal_ROLE, Principal: member}
	const depth = 20000
	for range depth {
		cb, err := proto.Marshal(&m.CombinedPrincipal{Principals: []*m.MSPPrincipal{p}})
		require.NoError(t, err)
		p = &m.MSPPrincipal{PrincipalClassification: m.MSPPrincipal_COMBINED, Principal: cb}
	}

	start := time.Now()
	err = id.SatisfiesPrincipal(p)
	t.Logf("depth %d evaluated in %v", depth, time.Since(start))
	require.Error(t, err, "a COMBINED principal nested %d levels deep must be rejected by a nesting limit", depth)
}

// FINDING-MSP-3: SatisfiesPrincipal dereferences a nil principal (after the expensive identity
// validation) instead of returning an error.
func TestFindingSatisfiesPrincipalNilPrincipal(t *testing.T) {
	forFindingSchemeCurves(t, func(t *testing.T, sc schemeCurve) {
		t.Helper()
		mspI, err := setupCurve(t, sc, "MSP1")
		require.NoError(t, err)
		id, err := mspI.GetDefaultSigningIdentity()
		require.NoError(t, err)

		require.NotPanics(t, func() { err = id.SatisfiesPrincipal(nil) })
		require.Error(t, err)
		require.NotPanics(t, func() { err = mspI.SatisfiesPrincipal(id, nil) })
		require.Error(t, err)
	})
}

// FINDING-MSP-4: DeserializeIdentity accepts non-canonical encodings of a valid identity,
// i.e. distinct byte strings that all validate as the same identity:
//   - the NymX/NymY split is not checked (only their concatenation is imported);
//   - an out-of-range MSPRole value is silently mapped to MEMBER by getIdemixRoleFromMSPRoleValue,
//     so a MEMBER credential validates under any unknown role value.
func TestFindingDeserializeIdentityAcceptsNonCanonicalEncodings(t *testing.T) {
	forFindingSchemeCurves(t, func(t *testing.T, sc schemeCurve) {
		t.Helper()
		mspI, err := setupCurve(t, sc, "MSP1")
		require.NoError(t, err)
		id, err := mspI.GetDefaultSigningIdentity()
		require.NoError(t, err)
		base := serializedIdemix(t, id)

		t.Run("shifted nym split", func(t *testing.T) {
			s := proto.Clone(base).(*im.SerializedIdemixIdentity)
			nym := append(append([]byte{}, s.NymX...), s.NymY...)
			s.NymX, s.NymY = nym[:1], nym[1:]
			d, err := mspI.DeserializeIdentity(outerIdentity(t, "MSP1", s))
			if err == nil {
				err = d.Validate()
			}
			require.Error(t, err, "NymX/NymY must each be one coordinate")
		})

		t.Run("unknown role value", func(t *testing.T) {
			s := proto.Clone(base).(*im.SerializedIdemixIdentity)
			role, err := proto.Marshal(&m.MSPRole{MspIdentifier: "MSP1", Role: m.MSPRole_MSPRoleType(99)})
			require.NoError(t, err)
			s.Role = role
			d, err := mspI.DeserializeIdentity(outerIdentity(t, "MSP1", s))
			if err == nil {
				err = d.Validate()
			}
			require.Error(t, err, "an identity claiming an undefined MSP role must be rejected")
		})
	})
}

// FINDING-MSP-5: IsWellFormed only checks that IdBytes unmarshals as a SerializedIdemixIdentity.
// Empty IdBytes (an identity without a pseudonym) is reported as well formed although
// DeserializeIdentity rejects it.
func TestFindingIsWellFormedAcceptsUndeserializableIdentity(t *testing.T) {
	forFindingSchemeCurves(t, func(t *testing.T, sc schemeCurve) {
		t.Helper()
		mspI, err := setupCurve(t, sc, "MSP1")
		require.NoError(t, err)

		sID := &m.SerializedIdentity{Mspid: "MSP1", IdBytes: nil}
		raw, err := proto.Marshal(sID)
		require.NoError(t, err)
		_, derr := mspI.DeserializeIdentity(raw)
		require.Error(t, derr)

		require.Error(t, mspI.IsWellFormed(sID), "IsWellFormed must reject what DeserializeIdentity rejects")
	})
}

// FINDING-MSP-6: the revocation material carried inside the association proof is never
// checked. identity.verifyProof passes msp.revocationPK and msp.epoch to the verifier, but
// (a) msp.epoch is never assigned from IdemixMSPConfig.Epoch in Setup, and (b) neither
// scheme's Verify uses the revocation public key / epoch (no VerifyEpochPK on
// RevocationEpochPk/RevocationPkSig/Epoch). An attacker can therefore replace the epoch and the
// revocation authority's signature inside the proof with arbitrary values and the identity
// still validates.
func TestFindingAssociationProofRevocationFieldsUnchecked(t *testing.T) {
	forFindingSchemeCurves(t, func(t *testing.T, sc schemeCurve) {
		t.Helper()
		mspI, err := setupCurve(t, sc, "MSP1")
		require.NoError(t, err)
		id, err := mspI.GetDefaultSigningIdentity()
		require.NoError(t, err)
		base := serializedIdemix(t, id)

		var tampered []byte
		if sc.scheme == "dlog" {
			sig := &idemix.Signature{}
			require.NoError(t, proto.Unmarshal(base.Proof, sig))
			sig.Epoch = 123456
			sig.RevocationPkSig = []byte("not a signature of the revocation authority")
			tampered, err = proto.Marshal(sig)
		} else {
			sig := &aries.Signature{}
			require.NoError(t, proto.Unmarshal(base.Proof, sig))
			sig.Epoch = 123456
			sig.RevocationPkSig = []byte("not a signature of the revocation authority")
			tampered, err = proto.Marshal(sig)
		}
		require.NoError(t, err)

		s := proto.Clone(base).(*im.SerializedIdemixIdentity)
		s.Proof = tampered
		d, err := mspI.DeserializeIdentity(outerIdentity(t, "MSP1", s))
		require.NoError(t, err)
		require.Error(t, mspI.Validate(d), "a proof with a forged epoch / revocation signature must be rejected")
	})
}

// FINDING-MSP-7: Setup ignores IdemixMSPConfig.Epoch: MSP.epoch is never written, so the
// verifier always checks against epoch 0 regardless of the configured epoch.
func TestFindingSetupIgnoresConfiguredEpoch(t *testing.T) {
	sc := schemeCurve{scheme: "dlog", curveID: curveIDBN254}
	conf := loadCurveConfig(t, sc, "MSP1", IDEMIX)
	ic := &im.IdemixMSPConfig{}
	require.NoError(t, proto.Unmarshal(conf.Config, ic))
	ic.Epoch = 7
	raw, err := proto.Marshal(ic)
	require.NoError(t, err)
	conf.Config = raw

	mspI, err := NewMSP(MSPv1_3)
	require.NoError(t, err)
	if err := mspI.Setup(conf); err != nil {
		// rejecting a config whose signer CRI is for another epoch is also acceptable
		return
	}
	require.Equal(t, 7, mspI.epoch, "the configured epoch must be used for verification")
}
