/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"fmt"
	"testing"

	idemix "github.com/IBM/idemix/bccsp/schemes/dlog/crypto"
	amclt "github.com/IBM/idemix/bccsp/schemes/dlog/crypto/translator/amcl"
	bccsp "github.com/IBM/idemix/bccsp/types"
	im "github.com/IBM/idemix/msp/config"
	math "github.com/IBM/mathlib"
	m "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func getDefaultSigner(t *testing.T, msp *MSP) (SigningIdentity, error) {
	t.Helper()
	id, err := msp.GetDefaultSigningIdentity()
	if err != nil {
		return nil, fmt.Errorf("Getting default signing identity failed: %w", err)
	}

	err = id.Validate()
	if err != nil {
		return nil, fmt.Errorf("Default signing identity invalid: %w", err)
	}

	err = msp.Validate(id)
	if err != nil {
		return nil, fmt.Errorf("Default signing identity invalid: %w", err)
	}

	return id, nil
}

func TestSetup(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)

		require.Equal(t, IDEMIX, msp.GetType())
	})
}

func TestSetupBad(t *testing.T) {
	curve := math.Curves[math.FP256BN_AMCL]
	tr := &amclt.Fp256bn{
		C: curve,
	}
	sc := schemeCurve{scheme: "dlog", curveID: curveIDFP256BN_AMCL}

	_, err := NewIdemixMsp(MSPv1_3)
	require.NoError(t, err)

	_, err = GetIdemixMspConfigWithType("testdata/idemix-does-not-exist", "MSPID", IDEMIX)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to read issuer public key file")

	msp1, err := NewIdemixMsp(MSPv1_3)
	require.NoError(t, err)

	// Setup with nil config
	err = msp1.Setup(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "setup error: nil conf reference")

	// Setup with incorrect MSP type
	conf := &m.MSPConfig{Type: 1234, Config: nil}
	err = msp1.Setup(conf)
	require.Error(t, err)
	require.Contains(t, err.Error(), "setup error:")

	// Setup with bad idemix config bytes
	conf = &m.MSPConfig{Type: int32(IDEMIX), Config: []byte("barf")}
	err = msp1.Setup(conf)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed unmarshalling idemix msp config")

	conf = loadCurveConfig(t, sc, "IdemixMSP1", IDEMIX)
	idemixconfig := &im.IdemixMSPConfig{}
	err = proto.Unmarshal(conf.Config, idemixconfig)
	require.NoError(t, err)

	// Create MSP config with IPK with incorrect attribute names
	idmx := &idemix.Idemix{
		Curve: curve,
	}
	rng, err := curve.Rand()
	require.NoError(t, err)
	key, err := idmx.NewIssuerKey([]string{}, rng, tr)
	require.NoError(t, err)
	ipkBytes, err := proto.Marshal(key.Ipk)
	require.NoError(t, err)
	idemixconfig.Ipk = ipkBytes

	idemixConfigBytes, err := proto.Marshal(idemixconfig)
	require.NoError(t, err)
	conf.Config = idemixConfigBytes

	err = msp1.Setup(conf)
	require.Error(t, err)
	require.Contains(t, err.Error(), "issuer public key must have attributes OU, Role, EnrollmentId, and RevocationHandle")

	// Create MSP config with bad IPK bytes
	ipkBytes = []byte("barf")
	idemixconfig.Ipk = ipkBytes

	idemixConfigBytes, err = proto.Marshal(idemixconfig)
	require.NoError(t, err)
	conf.Config = idemixConfigBytes

	err = msp1.Setup(conf)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to unmarshal ipk from idemix msp config")
}

func TestSigning(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp, err := setupCurve(t, sc, "MSP1")
		require.NoError(t, err)

		id, err := getDefaultSigner(t, msp)
		require.NoError(t, err)

		msg := []byte("TestMessage")
		sig, err := id.Sign(msg)
		require.NoError(t, err)

		err = id.Verify(msg, sig)
		require.NoError(t, err)

		err = id.Verify([]byte("OtherMessage"), sig)
		require.Error(t, err)
		require.Contains(t, err.Error(), badSigVerifyError(sc))

		verMsp, err := setupCurveVerifier(t, sc, "MSP1")
		require.NoError(t, err)
		err = verMsp.Validate(id)
		require.NoError(t, err)
		_, err = verMsp.GetDefaultSigningIdentity()
		require.Error(t, err)
		require.Contains(t, err.Error(), "no default signer setup")
	})
}

func TestSigningBad(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)

		id, err := getDefaultSigner(t, msp)
		require.NoError(t, err)

		msg := []byte("TestMessage")
		sig := []byte("barf")

		err = id.Verify(msg, sig)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error unmarshalling signature")
	})
}

func TestIdentitySerialization(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)

		id, err := getDefaultSigner(t, msp)
		require.NoError(t, err)

		// Test serialization of identities
		serializedID, err := id.Serialize()
		require.NoError(t, err)

		verID, err := msp.DeserializeIdentity(serializedID)
		require.NoError(t, err)

		err = verID.Validate()
		require.NoError(t, err)

		err = msp.Validate(verID)
		require.NoError(t, err)
	})
}

func TestIdentitySerializationBad(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)

		_, err = msp.DeserializeIdentity([]byte("barf"))
		require.Error(t, err, "DeserializeIdentity should have failed for bad input")
		require.Contains(t, err.Error(), "could not deserialize a SerializedIdentity")
	})
}

func TestIdentitySerializationWrongMSP(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)
		msp2, err := setupCurve(t, sc, "MSP2OU1")
		require.NoError(t, err)
		id2, err := getDefaultSigner(t, msp2)
		require.NoError(t, err)

		idBytes, err := id2.Serialize()
		require.NoError(t, err)

		_, err = msp1.DeserializeIdentity(idBytes)
		require.Error(t, err, "DeserializeIdentity should have failed for ID of other MSP")
		require.Contains(t, err.Error(), "expected MSP ID MSP1OU1, received MSP2OU1")
	})
}

// TestNymSwapAttack demonstrates and confirms the fix for the following attack:
// an adversary takes a legitimately-obtained identity - with its genuine
// associationProof, OU and Role untouched - and swaps out only its NymPublicKey
// for a different, unrelated (but well-formed) pseudonym. Both pseudonyms are
// properly derived from the *same* credential secret key, so this is not a case
// of a malformed or garbage nym: it is a valid pseudonym that simply was not the
// one the association proof was actually generated for.
//
// Before the fix, Idemixidentity.verifyProof did not pass the claimed
// NymPublicKey to the verifier, so the cryptographic check only established
// "some valid credential/nym pair produced this proof" without ever confirming
// that pair matches the nym the caller is presenting as the identity's public
// pseudonym. That let an adversary re-attribute a valid anonymous credential
// proof to an arbitrary pseudonym of their choosing.
func TestNymSwapAttack(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		mspI, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)

		id, err := getDefaultSigner(t, mspI)
		require.NoError(t, err)

		signingID, ok := id.(*signingIdentity)
		require.True(t, ok)

		idemixMsp := mspI

		// The adversary derives another, unlinkable pseudonym from the very same
		// credential secret key. This nym is perfectly well-formed - it is just not
		// the one bound into signingID.associationProof.
		otherNymKey, err := idemixMsp.csp.KeyDeriv(
			signingID.UserKey,
			&bccsp.IdemixNymKeyDerivationOpts{Temporary: true, IssuerPK: idemixMsp.ipk},
		)
		require.NoError(t, err)
		otherNymPublicKey, err := otherNymKey.PublicKey()
		require.NoError(t, err)

		originalNymBytes, err := signingID.NymPublicKey.Bytes()
		require.NoError(t, err)
		otherNymBytes, err := otherNymPublicKey.Bytes()
		require.NoError(t, err)
		require.NotEqual(t, originalNymBytes, otherNymBytes, "the two pseudonyms must be different for this attack to make sense")

		// Forge an identity: same associationProof, OU and Role as the genuine
		// identity, but with the swapped-in NymPublicKey.
		forged := NewIdemixIdentity(idemixMsp, otherNymPublicKey, signingID.Role, signingID.OU, signingID.associationProof)

		err = idemixMsp.Validate(forged)
		require.Error(t, err, "the forged identity must be rejected: its claimed nym does not match the nym bound to the association proof")
		require.Contains(t, err.Error(), "invalid nym")

		// The genuine identity, unmodified, must still validate correctly.
		require.NoError(t, idemixMsp.Validate(signingID))
	})
}

func TestPrincipalIdentity(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)

		id1, err := getDefaultSigner(t, msp1)
		require.NoError(t, err)

		idBytes, err := id1.Serialize()
		require.NoError(t, err)

		principal := &m.MSPPrincipal{
			PrincipalClassification: m.MSPPrincipal_IDENTITY,
			Principal:               idBytes}

		err = id1.SatisfiesPrincipal(principal)
		require.NoError(t, err)
	})
}

func TestPrincipalIdentityWrongIdentity(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)

		id1, err := getDefaultSigner(t, msp1)
		require.NoError(t, err)

		msp2, err := setupCurve(t, sc, "MSP1OU2")
		require.NoError(t, err)

		id2, err := getDefaultSigner(t, msp2)
		require.NoError(t, err)

		idBytes, err := id1.Serialize()
		require.NoError(t, err)

		principal := &m.MSPPrincipal{
			PrincipalClassification: m.MSPPrincipal_IDENTITY,
			Principal:               idBytes}

		err = id2.SatisfiesPrincipal(principal)
		require.Error(t, err, "Identity MSP principal for different user should fail")
		require.Contains(t, err.Error(), "the identities do not match")
	})
}

func TestPrincipalIdentityBadIdentity(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)

		id1, err := getDefaultSigner(t, msp1)
		require.NoError(t, err)

		idBytes := []byte("barf")

		principal := &m.MSPPrincipal{
			PrincipalClassification: m.MSPPrincipal_IDENTITY,
			Principal:               idBytes}

		err = id1.SatisfiesPrincipal(principal)
		require.Error(t, err, "Identity MSP principal for a bad principal should fail")
		require.Contains(t, err.Error(), "the identities do not match")
	})
}

func TestAnonymityPrincipal(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)

		id1, err := getDefaultSigner(t, msp1)
		require.NoError(t, err)

		principalBytes, err := proto.Marshal(&m.MSPIdentityAnonymity{AnonymityType: m.MSPIdentityAnonymity_ANONYMOUS})
		require.NoError(t, err)

		principal := &m.MSPPrincipal{
			PrincipalClassification: m.MSPPrincipal_ANONYMITY,
			Principal:               principalBytes}

		err = id1.SatisfiesPrincipal(principal)
		require.NoError(t, err)
	})
}

func TestAnonymityPrincipalBad(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)

		id1, err := getDefaultSigner(t, msp1)
		require.NoError(t, err)

		principalBytes, err := proto.Marshal(&m.MSPIdentityAnonymity{AnonymityType: m.MSPIdentityAnonymity_NOMINAL})
		require.NoError(t, err)

		principal := &m.MSPPrincipal{
			PrincipalClassification: m.MSPPrincipal_ANONYMITY,
			Principal:               principalBytes}

		err = id1.SatisfiesPrincipal(principal)
		require.Error(t, err, "Idemix identity is anonymous and should not pass NOMINAL anonymity principal")
		require.Contains(t, err.Error(), "principal is nominal, but idemix MSP is anonymous")
	})
}

func TestAnonymityPrincipalV11(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurveWithVersion(t, sc, "MSP1OU1", MSPv1_1)
		require.NoError(t, err)

		id1, err := getDefaultSigner(t, msp1)
		require.NoError(t, err)

		principalBytes, err := proto.Marshal(&m.MSPIdentityAnonymity{AnonymityType: m.MSPIdentityAnonymity_NOMINAL})
		require.NoError(t, err)

		principal := &m.MSPPrincipal{
			PrincipalClassification: m.MSPPrincipal_ANONYMITY,
			Principal:               principalBytes}

		err = id1.SatisfiesPrincipal(principal)
		require.Error(t, err)
		require.Contains(t, err.Error(), "anonymity MSP Principals are unsupported in MSPv1_1")
	})
}

func TestIdemixIsWellFormed(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		idemixMSP, err := setupCurve(t, sc, "TestName")
		require.NoError(t, err)

		id, err := getDefaultSigner(t, idemixMSP)
		require.NoError(t, err)
		rawId, err := id.Serialize()
		require.NoError(t, err)
		sId := &m.SerializedIdentity{}
		err = proto.Unmarshal(rawId, sId)
		require.NoError(t, err)
		err = idemixMSP.IsWellFormed(sId)
		require.NoError(t, err)
		// Corrupt the identity bytes
		sId.IdBytes = append(sId.IdBytes, 1)
		err = idemixMSP.IsWellFormed(sId)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not an idemix identity")
	})
}

func TestPrincipalOU(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)

		id1, err := getDefaultSigner(t, msp1)
		require.NoError(t, err)

		ou := &m.OrganizationUnit{
			OrganizationalUnitIdentifier: id1.GetOrganizationalUnits()[0].OrganizationalUnitIdentifier,
			MspIdentifier:                id1.GetMSPIdentifier(),
			CertifiersIdentifier:         nil,
		}
		bytes, err := proto.Marshal(ou)
		require.NoError(t, err)

		principal := &m.MSPPrincipal{
			PrincipalClassification: m.MSPPrincipal_ORGANIZATION_UNIT,
			Principal:               bytes}

		err = id1.SatisfiesPrincipal(principal)
		require.NoError(t, err)
	})
}

func TestPrincipalOUWrongOU(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)

		id1, err := getDefaultSigner(t, msp1)
		require.NoError(t, err)

		ou := &m.OrganizationUnit{
			OrganizationalUnitIdentifier: "DifferentOU",
			MspIdentifier:                id1.GetMSPIdentifier(),
			CertifiersIdentifier:         nil,
		}
		bytes, err := proto.Marshal(ou)
		require.NoError(t, err)

		principal := &m.MSPPrincipal{
			PrincipalClassification: m.MSPPrincipal_ORGANIZATION_UNIT,
			Principal:               bytes}

		err = id1.SatisfiesPrincipal(principal)
		require.Error(t, err, "OU MSP principal should have failed for user of different OU")
		require.Contains(t, err.Error(), "user is not part of the desired organizational unit")
	})
}

func TestPrincipalOUWrongMSP(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)

		id1, err := getDefaultSigner(t, msp1)
		require.NoError(t, err)

		ou := &m.OrganizationUnit{
			OrganizationalUnitIdentifier: "OU1",
			MspIdentifier:                "OtherMSP",
			CertifiersIdentifier:         nil,
		}
		bytes, err := proto.Marshal(ou)
		require.NoError(t, err)

		principal := &m.MSPPrincipal{
			PrincipalClassification: m.MSPPrincipal_ORGANIZATION_UNIT,
			Principal:               bytes}

		err = id1.SatisfiesPrincipal(principal)
		require.Error(t, err, "OU MSP principal should have failed for user of different MSP")
		require.Contains(t, err.Error(), "the identity is a member of a different MSP")
	})
}

func TestPrincipalOUBad(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)

		id1, err := getDefaultSigner(t, msp1)
		require.NoError(t, err)

		bytes := []byte("barf")
		require.NoError(t, err)

		principal := &m.MSPPrincipal{
			PrincipalClassification: m.MSPPrincipal_ORGANIZATION_UNIT,
			Principal:               bytes}

		err = id1.SatisfiesPrincipal(principal)
		require.Error(t, err, "OU MSP principal should have failed for a bad OU principal")
		require.Contains(t, err.Error(), "could not unmarshal OU from principal")
	})
}

func TestPrincipalRoleMember(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)

		id1, err := getDefaultSigner(t, msp1)
		require.NoError(t, err)

		principalBytes, err := proto.Marshal(&m.MSPRole{Role: m.MSPRole_MEMBER, MspIdentifier: id1.GetMSPIdentifier()})
		require.NoError(t, err)

		principal := &m.MSPPrincipal{
			PrincipalClassification: m.MSPPrincipal_ROLE,
			Principal:               principalBytes}

		err = id1.SatisfiesPrincipal(principal)
		require.NoError(t, err)

		// Member should also satisfy client
		principalBytes, err = proto.Marshal(&m.MSPRole{Role: m.MSPRole_CLIENT, MspIdentifier: id1.GetMSPIdentifier()})
		require.NoError(t, err)

		principal = &m.MSPPrincipal{
			PrincipalClassification: m.MSPPrincipal_ROLE,
			Principal:               principalBytes}

		err = id1.SatisfiesPrincipal(principal)
		require.NoError(t, err)
	})
}

func TestPrincipalRoleAdmin(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurveAdmin(t, sc, "MSP1OU1Admin")
		require.NoError(t, err)

		id1, err := getDefaultSigner(t, msp1)
		require.NoError(t, err)

		principalBytes, err := proto.Marshal(&m.MSPRole{Role: m.MSPRole_MEMBER, MspIdentifier: id1.GetMSPIdentifier()})
		require.NoError(t, err)

		principal := &m.MSPPrincipal{
			PrincipalClassification: m.MSPPrincipal_ROLE,
			Principal:               principalBytes}

		// Admin should also satisfy member
		err = id1.SatisfiesPrincipal(principal)
		require.NoError(t, err)

		principalBytes, err = proto.Marshal(&m.MSPRole{Role: m.MSPRole_ADMIN, MspIdentifier: id1.GetMSPIdentifier()})
		require.NoError(t, err)

		principal = &m.MSPPrincipal{
			PrincipalClassification: m.MSPPrincipal_ROLE,
			Principal:               principalBytes}

		err = id1.SatisfiesPrincipal(principal)
		require.NoError(t, err)
	})
}

func TestPrincipalRoleNotPeer(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurveAdmin(t, sc, "MSP1OU1")
		require.NoError(t, err)

		id1, err := getDefaultSigner(t, msp1)
		require.NoError(t, err)

		principalBytes, err := proto.Marshal(&m.MSPRole{Role: m.MSPRole_PEER, MspIdentifier: id1.GetMSPIdentifier()})
		require.NoError(t, err)

		principal := &m.MSPPrincipal{
			PrincipalClassification: m.MSPPrincipal_ROLE,
			Principal:               principalBytes}

		err = id1.SatisfiesPrincipal(principal)
		require.Error(t, err, "Admin should not satisfy PEER principal")
		require.Contains(t, err.Error(), "idemixmsp only supports client use, so it cannot satisfy an MSPRole PEER principal")
	})
}

func TestPrincipalRoleNotAdmin(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)

		id1, err := getDefaultSigner(t, msp1)
		require.NoError(t, err)

		principalBytes, err := proto.Marshal(&m.MSPRole{Role: m.MSPRole_ADMIN, MspIdentifier: id1.GetMSPIdentifier()})
		require.NoError(t, err)

		principal := &m.MSPPrincipal{
			PrincipalClassification: m.MSPPrincipal_ROLE,
			Principal:               principalBytes}

		err = id1.SatisfiesPrincipal(principal)
		require.Error(t, err, "Member should not satisfy Admin principal")
		require.Contains(t, err.Error(), "user is not an admin")
	})
}

func TestPrincipalRoleWrongMSP(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)

		id1, err := getDefaultSigner(t, msp1)
		require.NoError(t, err)

		principalBytes, err := proto.Marshal(&m.MSPRole{Role: m.MSPRole_MEMBER, MspIdentifier: "OtherMSP"})
		require.NoError(t, err)

		principal := &m.MSPPrincipal{
			PrincipalClassification: m.MSPPrincipal_ROLE,
			Principal:               principalBytes}

		err = id1.SatisfiesPrincipal(principal)
		require.Error(t, err, "Role MSP principal should have failed for user of different MSP")
		require.Contains(t, err.Error(), "the identity is a member of a different MSP")
	})
}

func TestPrincipalRoleBadRole(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)

		id1, err := getDefaultSigner(t, msp1)
		require.NoError(t, err)

		// Make principal for nonexisting role 1234
		principalBytes, err := proto.Marshal(&m.MSPRole{Role: 1234, MspIdentifier: id1.GetMSPIdentifier()})
		require.NoError(t, err)

		principal := &m.MSPPrincipal{
			PrincipalClassification: m.MSPPrincipal_ROLE,
			Principal:               principalBytes}

		err = id1.SatisfiesPrincipal(principal)
		require.Error(t, err, "Role MSP principal should have failed for a bad Role")
		require.Contains(t, err.Error(), "invalid MSP role type")
	})
}

func TestPrincipalBad(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)

		id1, err := getDefaultSigner(t, msp1)
		require.NoError(t, err)

		principal := &m.MSPPrincipal{
			PrincipalClassification: 1234,
			Principal:               nil}

		err = id1.SatisfiesPrincipal(principal)
		require.Error(t, err, "Principal with bad Classification should fail")
		require.Contains(t, err.Error(), "invalid principal type")
	})
}

func TestPrincipalCombined(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)

		id1, err := getDefaultSigner(t, msp1)
		require.NoError(t, err)

		ou := &m.OrganizationUnit{
			OrganizationalUnitIdentifier: id1.GetOrganizationalUnits()[0].OrganizationalUnitIdentifier,
			MspIdentifier:                id1.GetMSPIdentifier(),
			CertifiersIdentifier:         nil,
		}
		principalBytes, err := proto.Marshal(ou)
		require.NoError(t, err)

		principalOU := &m.MSPPrincipal{
			PrincipalClassification: m.MSPPrincipal_ORGANIZATION_UNIT,
			Principal:               principalBytes}

		principalBytes, err = proto.Marshal(&m.MSPRole{Role: m.MSPRole_MEMBER, MspIdentifier: id1.GetMSPIdentifier()})
		require.NoError(t, err)

		principalRole := &m.MSPPrincipal{
			PrincipalClassification: m.MSPPrincipal_ROLE,
			Principal:               principalBytes}

		principals := []*m.MSPPrincipal{principalOU, principalRole}

		combinedPrincipal := &m.CombinedPrincipal{Principals: principals}
		combinedPrincipalBytes, err := proto.Marshal(combinedPrincipal)

		require.NoError(t, err)

		principalsCombined := &m.MSPPrincipal{PrincipalClassification: m.MSPPrincipal_COMBINED, Principal: combinedPrincipalBytes}

		err = id1.SatisfiesPrincipal(principalsCombined)
		require.NoError(t, err)
	})
}

func TestPrincipalCombinedBad(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)

		id1, err := getDefaultSigner(t, msp1)
		require.NoError(t, err)

		// create combined principal requiring membership of OU1 in MSP1 and requiring admin role
		ou := &m.OrganizationUnit{
			OrganizationalUnitIdentifier: id1.GetOrganizationalUnits()[0].OrganizationalUnitIdentifier,
			MspIdentifier:                id1.GetMSPIdentifier(),
			CertifiersIdentifier:         nil,
		}
		principalBytes, err := proto.Marshal(ou)
		require.NoError(t, err)

		principalOU := &m.MSPPrincipal{
			PrincipalClassification: m.MSPPrincipal_ORGANIZATION_UNIT,
			Principal:               principalBytes}

		principalBytes, err = proto.Marshal(&m.MSPRole{Role: m.MSPRole_ADMIN, MspIdentifier: id1.GetMSPIdentifier()})
		require.NoError(t, err)

		principalRole := &m.MSPPrincipal{
			PrincipalClassification: m.MSPPrincipal_ROLE,
			Principal:               principalBytes}

		principals := []*m.MSPPrincipal{principalOU, principalRole}

		combinedPrincipal := &m.CombinedPrincipal{Principals: principals}
		combinedPrincipalBytes, err := proto.Marshal(combinedPrincipal)

		require.NoError(t, err)

		principalsCombined := &m.MSPPrincipal{PrincipalClassification: m.MSPPrincipal_COMBINED, Principal: combinedPrincipalBytes}

		err = id1.SatisfiesPrincipal(principalsCombined)
		require.Error(t, err, "non-admin member of OU1 in MSP1 should not satisfy principal admin and OU1 in MSP1")
		require.Contains(t, err.Error(), "user is not an admin")
	})
}

func TestPrincipalCombinedV11(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurveWithVersion(t, sc, "MSP1OU1", MSPv1_1)
		require.NoError(t, err)

		id1, err := getDefaultSigner(t, msp1)
		require.NoError(t, err)

		ou := &m.OrganizationUnit{
			OrganizationalUnitIdentifier: id1.GetOrganizationalUnits()[0].OrganizationalUnitIdentifier,
			MspIdentifier:                id1.GetMSPIdentifier(),
			CertifiersIdentifier:         nil,
		}
		principalBytes, err := proto.Marshal(ou)
		require.NoError(t, err)

		principalOU := &m.MSPPrincipal{
			PrincipalClassification: m.MSPPrincipal_ORGANIZATION_UNIT,
			Principal:               principalBytes}

		principalBytes, err = proto.Marshal(&m.MSPRole{Role: m.MSPRole_MEMBER, MspIdentifier: id1.GetMSPIdentifier()})
		require.NoError(t, err)

		principalRole := &m.MSPPrincipal{
			PrincipalClassification: m.MSPPrincipal_ROLE,
			Principal:               principalBytes}

		principals := []*m.MSPPrincipal{principalOU, principalRole}

		combinedPrincipal := &m.CombinedPrincipal{Principals: principals}
		combinedPrincipalBytes, err := proto.Marshal(combinedPrincipal)

		require.NoError(t, err)

		principalsCombined := &m.MSPPrincipal{PrincipalClassification: m.MSPPrincipal_COMBINED, Principal: combinedPrincipalBytes}

		err = id1.SatisfiesPrincipal(principalsCombined)
		require.Error(t, err)
		require.Contains(t, err.Error(), "combined MSP Principals are unsupported in MSPv1_1")
	})
}

func TestRoleClientV11(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurveWithVersion(t, sc, "MSP1OU1", MSPv1_1)
		require.NoError(t, err)
		id1, err := getDefaultSigner(t, msp1)
		require.NoError(t, err)

		principalBytes, err := proto.Marshal(&m.MSPRole{Role: m.MSPRole_CLIENT, MspIdentifier: id1.GetMSPIdentifier()})
		require.NoError(t, err)
		principalRole := &m.MSPPrincipal{
			PrincipalClassification: m.MSPPrincipal_ROLE,
			Principal:               principalBytes}
		err = id1.SatisfiesPrincipal(principalRole)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid MSP role type")
	})
}

func TestRolePeerV11(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurveWithVersion(t, sc, "MSP1OU1", MSPv1_1)
		require.NoError(t, err)
		id1, err := getDefaultSigner(t, msp1)
		require.NoError(t, err)

		principalBytes, err := proto.Marshal(&m.MSPRole{Role: m.MSPRole_PEER, MspIdentifier: id1.GetMSPIdentifier()})
		require.NoError(t, err)
		principalRole := &m.MSPPrincipal{
			PrincipalClassification: m.MSPPrincipal_ROLE,
			Principal:               principalBytes}
		err = id1.SatisfiesPrincipal(principalRole)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid MSP role type")
	})
}
