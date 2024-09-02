/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"github.com/stretchr/testify/require"
)

func TestSigningAries(t *testing.T) {
	msp, err := setupWithTypeAndVersion("testdata/aries/MSP1OU1eid1/", "MSP1", MSPv1_3, IDEMIX_ARIES)
	require.NoError(t, err)

	id, err := getDefaultSigner(msp)
	require.NoError(t, err)

	msg := []byte("TestMessage")
	sig, err := id.Sign(msg)
	require.NoError(t, err)

	err = id.Verify(msg, sig)
	require.NoError(t, err)

	err = id.Verify([]byte("OtherMessage"), sig)
	require.Error(t, err)
	require.Contains(t, err.Error(), "contribution is not zero")

	verMsp, err := setupWithTypeAndVersion("testdata/aries/MSP1Verifier", "MSP1", MSPv1_3, IDEMIX_ARIES)
	require.NoError(t, err)
	err = verMsp.Validate(id)
	require.NoError(t, err)
	_, err = verMsp.GetDefaultSigningIdentity()
	require.Error(t, err)
	require.Contains(t, err.Error(), "no default signer setup")
}

func TestSigningBadAries(t *testing.T) {
	msp, err := setupWithTypeAndVersion("testdata/aries/MSP1OU1eid1/", "MSP1", MSPv1_3, IDEMIX_ARIES)
	require.NoError(t, err)

	id, err := getDefaultSigner(msp)
	require.NoError(t, err)

	msg := []byte("TestMessage")
	sig := []byte("barf")

	err = id.Verify(msg, sig)
	require.Error(t, err)
	require.Contains(t, err.Error(), "error unmarshalling signature")
}

func TestIdentitySerializationAries(t *testing.T) {
	msp, err := setupWithTypeAndVersion("testdata/aries/MSP1OU1eid1/", "MSP1", MSPv1_3, IDEMIX_ARIES)
	require.NoError(t, err)

	id, err := getDefaultSigner(msp)
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
}

func TestIdentitySerializationBadAries(t *testing.T) {
	msp, err := setupWithTypeAndVersion("testdata/aries/MSP1OU1eid1/", "MSP1", MSPv1_3, IDEMIX_ARIES)
	require.NoError(t, err)

	_, err = msp.DeserializeIdentity([]byte("barf"))
	require.Error(t, err, "DeserializeIdentity should have failed for bad input")
	require.Contains(t, err.Error(), "could not deserialize a SerializedIdentity")
}

func TestIdentitySerializationWrongMSPAries(t *testing.T) {
	msp1, err := setupWithTypeAndVersion("testdata/aries/MSP1OU1eid1/", "MSP1OU1", MSPv1_3, IDEMIX_ARIES)
	require.NoError(t, err)
	msp2, err := setupWithTypeAndVersion("testdata/aries/MSP2OU1eid1/", "MSP2OU1", MSPv1_3, IDEMIX_ARIES)
	require.NoError(t, err)
	id2, err := getDefaultSigner(msp2)
	require.NoError(t, err)

	idBytes, err := id2.Serialize()
	require.NoError(t, err)

	_, err = msp1.DeserializeIdentity(idBytes)
	require.Error(t, err, "DeserializeIdentity should have failed for ID of other MSP")
	require.Contains(t, err.Error(), "expected MSP ID MSP1OU1, received MSP2OU1")
}

func TestPrincipalIdentityAries(t *testing.T) {
	msp1, err := setupWithTypeAndVersion("testdata/aries/MSP1OU1eid1/", "MSP1", MSPv1_3, IDEMIX_ARIES)
	require.NoError(t, err)

	id1, err := getDefaultSigner(msp1)
	require.NoError(t, err)

	idBytes, err := id1.Serialize()
	require.NoError(t, err)

	principal := &msp.MSPPrincipal{
		PrincipalClassification: msp.MSPPrincipal_IDENTITY,
		Principal:               idBytes}

	err = id1.SatisfiesPrincipal(principal)
	require.NoError(t, err)
}

func TestPrincipalIdentityWrongIdentityAries(t *testing.T) {
	msp1, err := setupWithTypeAndVersion("testdata/aries/MSP1OU1eid1/", "MSP1OU1", MSPv1_3, IDEMIX_ARIES)
	require.NoError(t, err)

	id1, err := getDefaultSigner(msp1)
	require.NoError(t, err)

	msp2, err := setupWithTypeAndVersion("testdata/aries/MSP2OU1eid1/", "MSP2OU1", MSPv1_3, IDEMIX_ARIES)
	require.NoError(t, err)

	id2, err := getDefaultSigner(msp2)
	require.NoError(t, err)

	idBytes, err := id1.Serialize()
	require.NoError(t, err)

	principal := &msp.MSPPrincipal{
		PrincipalClassification: msp.MSPPrincipal_IDENTITY,
		Principal:               idBytes}

	err = id2.SatisfiesPrincipal(principal)
	require.Error(t, err, "Identity MSP principal for different user should fail")
	require.Contains(t, err.Error(), "the identities do not match")

}

func TestPrincipalIdentityBadIdentityAries(t *testing.T) {
	msp1, err := setupWithTypeAndVersion("testdata/aries/MSP1OU1eid1/", "MSP1OU1", MSPv1_3, IDEMIX_ARIES)
	require.NoError(t, err)

	id1, err := getDefaultSigner(msp1)
	require.NoError(t, err)

	idBytes := []byte("barf")

	principal := &msp.MSPPrincipal{
		PrincipalClassification: msp.MSPPrincipal_IDENTITY,
		Principal:               idBytes}

	err = id1.SatisfiesPrincipal(principal)
	require.Error(t, err, "Identity MSP principal for a bad principal should fail")
	require.Contains(t, err.Error(), "the identities do not match")
}

func TestAnonymityPrincipalAries(t *testing.T) {
	msp1, err := setupWithTypeAndVersion("testdata/aries/MSP1OU1eid1/", "MSP1", MSPv1_3, IDEMIX_ARIES)
	require.NoError(t, err)

	id1, err := getDefaultSigner(msp1)
	require.NoError(t, err)

	principalBytes, err := proto.Marshal(&msp.MSPIdentityAnonymity{AnonymityType: msp.MSPIdentityAnonymity_ANONYMOUS})
	require.NoError(t, err)

	principal := &msp.MSPPrincipal{
		PrincipalClassification: msp.MSPPrincipal_ANONYMITY,
		Principal:               principalBytes}

	err = id1.SatisfiesPrincipal(principal)
	require.NoError(t, err)
}

func TestAnonymityPrincipalBadAries(t *testing.T) {
	msp1, err := setupWithTypeAndVersion("testdata/aries/MSP1OU1eid1/", "MSP1", MSPv1_3, IDEMIX_ARIES)
	require.NoError(t, err)

	id1, err := getDefaultSigner(msp1)
	require.NoError(t, err)

	principalBytes, err := proto.Marshal(&msp.MSPIdentityAnonymity{AnonymityType: msp.MSPIdentityAnonymity_NOMINAL})
	require.NoError(t, err)

	principal := &msp.MSPPrincipal{
		PrincipalClassification: msp.MSPPrincipal_ANONYMITY,
		Principal:               principalBytes}

	err = id1.SatisfiesPrincipal(principal)
	require.Error(t, err, "Idemix identity is anonymous and should not pass NOMINAL anonymity principal")
	require.Contains(t, err.Error(), "principal is nominal, but idemix MSP is anonymous")
}

func TestAnonymityPrincipalV11Aries(t *testing.T) {
	msp1, err := setupWithTypeAndVersion("testdata/aries/MSP1OU1eid1/", "MSP1", MSPv1_1, IDEMIX_ARIES)
	require.NoError(t, err)

	id1, err := getDefaultSigner(msp1)
	require.NoError(t, err)

	principalBytes, err := proto.Marshal(&msp.MSPIdentityAnonymity{AnonymityType: msp.MSPIdentityAnonymity_NOMINAL})
	require.NoError(t, err)

	principal := &msp.MSPPrincipal{
		PrincipalClassification: msp.MSPPrincipal_ANONYMITY,
		Principal:               principalBytes}

	err = id1.SatisfiesPrincipal(principal)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Anonymity MSP Principals are unsupported in MSPv1_1")
}

func TestIdemixIsWellFormedAries(t *testing.T) {
	idemixMSP, err := setupWithTypeAndVersion("testdata/aries/MSP1OU1eid1/", "MSP1", MSPv1_3, IDEMIX_ARIES)
	require.NoError(t, err)

	id, err := getDefaultSigner(idemixMSP)
	require.NoError(t, err)
	rawId, err := id.Serialize()
	require.NoError(t, err)
	sId := &msp.SerializedIdentity{}
	err = proto.Unmarshal(rawId, sId)
	require.NoError(t, err)
	err = idemixMSP.IsWellFormed(sId)
	require.NoError(t, err)
	// Corrupt the identity bytes
	sId.IdBytes = append(sId.IdBytes, 1)
	err = idemixMSP.IsWellFormed(sId)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not an idemix identity")
}

func TestPrincipalOUAries(t *testing.T) {
	msp1, err := setupWithTypeAndVersion("testdata/aries/MSP1OU1eid1/", "MSP1", MSPv1_3, IDEMIX_ARIES)
	require.NoError(t, err)

	id1, err := getDefaultSigner(msp1)
	require.NoError(t, err)

	ou := &msp.OrganizationUnit{
		OrganizationalUnitIdentifier: id1.GetOrganizationalUnits()[0].OrganizationalUnitIdentifier,
		MspIdentifier:                id1.GetMSPIdentifier(),
		CertifiersIdentifier:         nil,
	}
	bytes, err := proto.Marshal(ou)
	require.NoError(t, err)

	principal := &msp.MSPPrincipal{
		PrincipalClassification: msp.MSPPrincipal_ORGANIZATION_UNIT,
		Principal:               bytes}

	err = id1.SatisfiesPrincipal(principal)
	require.NoError(t, err)
}

func TestPrincipalOUWrongOUAries(t *testing.T) {
	msp1, err := setupWithTypeAndVersion("testdata/aries/MSP1OU1eid1/", "MSP1", MSPv1_3, IDEMIX_ARIES)
	require.NoError(t, err)

	id1, err := getDefaultSigner(msp1)
	require.NoError(t, err)

	ou := &msp.OrganizationUnit{
		OrganizationalUnitIdentifier: "DifferentOU",
		MspIdentifier:                id1.GetMSPIdentifier(),
		CertifiersIdentifier:         nil,
	}
	bytes, err := proto.Marshal(ou)
	require.NoError(t, err)

	principal := &msp.MSPPrincipal{
		PrincipalClassification: msp.MSPPrincipal_ORGANIZATION_UNIT,
		Principal:               bytes}

	err = id1.SatisfiesPrincipal(principal)
	require.Error(t, err, "OU MSP principal should have failed for user of different OU")
	require.Contains(t, err.Error(), "user is not part of the desired organizational unit")

}

func TestPrincipalOUWrongMSPAries(t *testing.T) {
	msp1, err := setupWithTypeAndVersion("testdata/aries/MSP1OU1eid1/", "MSP1", MSPv1_3, IDEMIX_ARIES)
	require.NoError(t, err)

	id1, err := getDefaultSigner(msp1)
	require.NoError(t, err)

	ou := &msp.OrganizationUnit{
		OrganizationalUnitIdentifier: "OU1",
		MspIdentifier:                "OtherMSP",
		CertifiersIdentifier:         nil,
	}
	bytes, err := proto.Marshal(ou)
	require.NoError(t, err)

	principal := &msp.MSPPrincipal{
		PrincipalClassification: msp.MSPPrincipal_ORGANIZATION_UNIT,
		Principal:               bytes}

	err = id1.SatisfiesPrincipal(principal)
	require.Error(t, err, "OU MSP principal should have failed for user of different MSP")
	require.Contains(t, err.Error(), "the identity is a member of a different MSP")

}

func TestPrincipalOUBadAries(t *testing.T) {
	msp1, err := setupWithTypeAndVersion("testdata/aries/MSP1OU1eid1/", "MSP1", MSPv1_3, IDEMIX_ARIES)
	require.NoError(t, err)

	id1, err := getDefaultSigner(msp1)
	require.NoError(t, err)

	bytes := []byte("barf")
	require.NoError(t, err)

	principal := &msp.MSPPrincipal{
		PrincipalClassification: msp.MSPPrincipal_ORGANIZATION_UNIT,
		Principal:               bytes}

	err = id1.SatisfiesPrincipal(principal)
	require.Error(t, err, "OU MSP principal should have failed for a bad OU principal")
	require.Contains(t, err.Error(), "could not unmarshal OU from principal")
}

func TestPrincipalRoleMemberAries(t *testing.T) {
	msp1, err := setupWithTypeAndVersion("testdata/aries/MSP1OU1eid1/", "MSP1", MSPv1_3, IDEMIX_ARIES)
	require.NoError(t, err)

	id1, err := getDefaultSigner(msp1)
	require.NoError(t, err)

	principalBytes, err := proto.Marshal(&msp.MSPRole{Role: msp.MSPRole_MEMBER, MspIdentifier: id1.GetMSPIdentifier()})
	require.NoError(t, err)

	principal := &msp.MSPPrincipal{
		PrincipalClassification: msp.MSPPrincipal_ROLE,
		Principal:               principalBytes}

	err = id1.SatisfiesPrincipal(principal)
	require.NoError(t, err)

	// Member should also satisfy client
	principalBytes, err = proto.Marshal(&msp.MSPRole{Role: msp.MSPRole_CLIENT, MspIdentifier: id1.GetMSPIdentifier()})
	require.NoError(t, err)

	principal = &msp.MSPPrincipal{
		PrincipalClassification: msp.MSPPrincipal_ROLE,
		Principal:               principalBytes}

	err = id1.SatisfiesPrincipal(principal)
	require.NoError(t, err)
}

func TestPrincipalRoleAdminAries(t *testing.T) {
	msp1, err := setupWithTypeAndVersion("testdata/aries/MSP1OU1eid1Admin/", "MSP1", MSPv1_3, IDEMIX_ARIES)
	require.NoError(t, err)

	id1, err := getDefaultSigner(msp1)
	require.NoError(t, err)

	principalBytes, err := proto.Marshal(&msp.MSPRole{Role: msp.MSPRole_MEMBER, MspIdentifier: id1.GetMSPIdentifier()})
	require.NoError(t, err)

	principal := &msp.MSPPrincipal{
		PrincipalClassification: msp.MSPPrincipal_ROLE,
		Principal:               principalBytes}

	// Admin should also satisfy member
	err = id1.SatisfiesPrincipal(principal)
	require.NoError(t, err)

	principalBytes, err = proto.Marshal(&msp.MSPRole{Role: msp.MSPRole_ADMIN, MspIdentifier: id1.GetMSPIdentifier()})
	require.NoError(t, err)

	principal = &msp.MSPPrincipal{
		PrincipalClassification: msp.MSPPrincipal_ROLE,
		Principal:               principalBytes}

	err = id1.SatisfiesPrincipal(principal)
	require.NoError(t, err)
}

func TestPrincipalRoleNotPeerAries(t *testing.T) {
	msp1, err := setupWithTypeAndVersion("testdata/aries/MSP1OU1eid1Admin/", "MSP1", MSPv1_3, IDEMIX_ARIES)
	require.NoError(t, err)

	id1, err := getDefaultSigner(msp1)
	require.NoError(t, err)

	principalBytes, err := proto.Marshal(&msp.MSPRole{Role: msp.MSPRole_PEER, MspIdentifier: id1.GetMSPIdentifier()})
	require.NoError(t, err)

	principal := &msp.MSPPrincipal{
		PrincipalClassification: msp.MSPPrincipal_ROLE,
		Principal:               principalBytes}

	err = id1.SatisfiesPrincipal(principal)
	require.Error(t, err, "Admin should not satisfy PEER principal")
	require.Contains(t, err.Error(), "idemixmsp only supports client use, so it cannot satisfy an MSPRole PEER principal")
}

func TestPrincipalRoleNotAdminAries(t *testing.T) {
	msp1, err := setupWithTypeAndVersion("testdata/aries/MSP1OU1eid1/", "MSP1", MSPv1_3, IDEMIX_ARIES)
	require.NoError(t, err)

	id1, err := getDefaultSigner(msp1)
	require.NoError(t, err)

	principalBytes, err := proto.Marshal(&msp.MSPRole{Role: msp.MSPRole_ADMIN, MspIdentifier: id1.GetMSPIdentifier()})
	require.NoError(t, err)

	principal := &msp.MSPPrincipal{
		PrincipalClassification: msp.MSPPrincipal_ROLE,
		Principal:               principalBytes}

	err = id1.SatisfiesPrincipal(principal)
	require.Error(t, err, "Member should not satisfy Admin principal")
	require.Contains(t, err.Error(), "user is not an admin")
}

func TestPrincipalRoleWrongMSPAries(t *testing.T) {
	msp1, err := setupWithTypeAndVersion("testdata/aries/MSP1OU1eid1/", "MSP1", MSPv1_3, IDEMIX_ARIES)
	require.NoError(t, err)

	id1, err := getDefaultSigner(msp1)
	require.NoError(t, err)

	principalBytes, err := proto.Marshal(&msp.MSPRole{Role: msp.MSPRole_MEMBER, MspIdentifier: "OtherMSP"})
	require.NoError(t, err)

	principal := &msp.MSPPrincipal{
		PrincipalClassification: msp.MSPPrincipal_ROLE,
		Principal:               principalBytes}

	err = id1.SatisfiesPrincipal(principal)
	require.Error(t, err, "Role MSP principal should have failed for user of different MSP")
	require.Contains(t, err.Error(), "the identity is a member of a different MSP")
}

func TestPrincipalRoleBadRoleAries(t *testing.T) {
	msp1, err := setupWithTypeAndVersion("testdata/aries/MSP1OU1eid1/", "MSP1", MSPv1_3, IDEMIX_ARIES)
	require.NoError(t, err)

	id1, err := getDefaultSigner(msp1)
	require.NoError(t, err)

	// Make principal for nonexisting role 1234
	principalBytes, err := proto.Marshal(&msp.MSPRole{Role: 1234, MspIdentifier: id1.GetMSPIdentifier()})
	require.NoError(t, err)

	principal := &msp.MSPPrincipal{
		PrincipalClassification: msp.MSPPrincipal_ROLE,
		Principal:               principalBytes}

	err = id1.SatisfiesPrincipal(principal)
	require.Error(t, err, "Role MSP principal should have failed for a bad Role")
	require.Contains(t, err.Error(), "invalid MSP role type")
}

func TestPrincipalBadAries(t *testing.T) {
	msp1, err := setupWithTypeAndVersion("testdata/aries/MSP1OU1eid1/", "MSP1", MSPv1_3, IDEMIX_ARIES)
	require.NoError(t, err)

	id1, err := getDefaultSigner(msp1)
	require.NoError(t, err)

	principal := &msp.MSPPrincipal{
		PrincipalClassification: 1234,
		Principal:               nil}

	err = id1.SatisfiesPrincipal(principal)
	require.Error(t, err, "Principal with bad Classification should fail")
	require.Contains(t, err.Error(), "invalid principal type")
}

func TestPrincipalCombinedAries(t *testing.T) {
	msp1, err := setupWithTypeAndVersion("testdata/aries/MSP1OU1eid1/", "MSP1", MSPv1_3, IDEMIX_ARIES)
	require.NoError(t, err)

	id1, err := getDefaultSigner(msp1)
	require.NoError(t, err)

	ou := &msp.OrganizationUnit{
		OrganizationalUnitIdentifier: id1.GetOrganizationalUnits()[0].OrganizationalUnitIdentifier,
		MspIdentifier:                id1.GetMSPIdentifier(),
		CertifiersIdentifier:         nil,
	}
	principalBytes, err := proto.Marshal(ou)
	require.NoError(t, err)

	principalOU := &msp.MSPPrincipal{
		PrincipalClassification: msp.MSPPrincipal_ORGANIZATION_UNIT,
		Principal:               principalBytes}

	principalBytes, err = proto.Marshal(&msp.MSPRole{Role: msp.MSPRole_MEMBER, MspIdentifier: id1.GetMSPIdentifier()})
	require.NoError(t, err)

	principalRole := &msp.MSPPrincipal{
		PrincipalClassification: msp.MSPPrincipal_ROLE,
		Principal:               principalBytes}

	principals := []*msp.MSPPrincipal{principalOU, principalRole}

	combinedPrincipal := &msp.CombinedPrincipal{Principals: principals}
	combinedPrincipalBytes, err := proto.Marshal(combinedPrincipal)

	require.NoError(t, err)

	principalsCombined := &msp.MSPPrincipal{PrincipalClassification: msp.MSPPrincipal_COMBINED, Principal: combinedPrincipalBytes}

	err = id1.SatisfiesPrincipal(principalsCombined)
	require.NoError(t, err)
}

func TestPrincipalCombinedBadAries(t *testing.T) {
	msp1, err := setupWithTypeAndVersion("testdata/aries/MSP1OU1eid1/", "MSP1", MSPv1_3, IDEMIX_ARIES)
	require.NoError(t, err)

	id1, err := getDefaultSigner(msp1)
	require.NoError(t, err)

	// create combined principal requiring membership of OU1 in MSP1 and requiring admin role
	ou := &msp.OrganizationUnit{
		OrganizationalUnitIdentifier: id1.GetOrganizationalUnits()[0].OrganizationalUnitIdentifier,
		MspIdentifier:                id1.GetMSPIdentifier(),
		CertifiersIdentifier:         nil,
	}
	principalBytes, err := proto.Marshal(ou)
	require.NoError(t, err)

	principalOU := &msp.MSPPrincipal{
		PrincipalClassification: msp.MSPPrincipal_ORGANIZATION_UNIT,
		Principal:               principalBytes}

	principalBytes, err = proto.Marshal(&msp.MSPRole{Role: msp.MSPRole_ADMIN, MspIdentifier: id1.GetMSPIdentifier()})
	require.NoError(t, err)

	principalRole := &msp.MSPPrincipal{
		PrincipalClassification: msp.MSPPrincipal_ROLE,
		Principal:               principalBytes}

	principals := []*msp.MSPPrincipal{principalOU, principalRole}

	combinedPrincipal := &msp.CombinedPrincipal{Principals: principals}
	combinedPrincipalBytes, err := proto.Marshal(combinedPrincipal)

	require.NoError(t, err)

	principalsCombined := &msp.MSPPrincipal{PrincipalClassification: msp.MSPPrincipal_COMBINED, Principal: combinedPrincipalBytes}

	err = id1.SatisfiesPrincipal(principalsCombined)
	require.Error(t, err, "non-admin member of OU1 in MSP1 should not satisfy principal admin and OU1 in MSP1")
	require.Contains(t, err.Error(), "user is not an admin")
}

func TestPrincipalCombinedV11Aries(t *testing.T) {
	msp1, err := setupWithTypeAndVersion("testdata/aries/MSP1OU1eid1/", "MSP1", MSPv1_1, IDEMIX_ARIES)
	require.NoError(t, err)

	id1, err := getDefaultSigner(msp1)
	require.NoError(t, err)

	ou := &msp.OrganizationUnit{
		OrganizationalUnitIdentifier: id1.GetOrganizationalUnits()[0].OrganizationalUnitIdentifier,
		MspIdentifier:                id1.GetMSPIdentifier(),
		CertifiersIdentifier:         nil,
	}
	principalBytes, err := proto.Marshal(ou)
	require.NoError(t, err)

	principalOU := &msp.MSPPrincipal{
		PrincipalClassification: msp.MSPPrincipal_ORGANIZATION_UNIT,
		Principal:               principalBytes}

	principalBytes, err = proto.Marshal(&msp.MSPRole{Role: msp.MSPRole_MEMBER, MspIdentifier: id1.GetMSPIdentifier()})
	require.NoError(t, err)

	principalRole := &msp.MSPPrincipal{
		PrincipalClassification: msp.MSPPrincipal_ROLE,
		Principal:               principalBytes}

	principals := []*msp.MSPPrincipal{principalOU, principalRole}

	combinedPrincipal := &msp.CombinedPrincipal{Principals: principals}
	combinedPrincipalBytes, err := proto.Marshal(combinedPrincipal)

	require.NoError(t, err)

	principalsCombined := &msp.MSPPrincipal{PrincipalClassification: msp.MSPPrincipal_COMBINED, Principal: combinedPrincipalBytes}

	err = id1.SatisfiesPrincipal(principalsCombined)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Combined MSP Principals are unsupported in MSPv1_1")
}

func TestRoleClientV11Aries(t *testing.T) {
	msp1, err := setupWithTypeAndVersion("testdata/aries/MSP1OU1eid1/", "MSP1", MSPv1_1, IDEMIX_ARIES)
	require.NoError(t, err)
	id1, err := getDefaultSigner(msp1)
	require.NoError(t, err)

	principalBytes, err := proto.Marshal(&msp.MSPRole{Role: msp.MSPRole_CLIENT, MspIdentifier: id1.GetMSPIdentifier()})
	require.NoError(t, err)
	principalRole := &msp.MSPPrincipal{
		PrincipalClassification: msp.MSPPrincipal_ROLE,
		Principal:               principalBytes}
	err = id1.SatisfiesPrincipal(principalRole)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid MSP role type")
}

func TestRolePeerV11Aries(t *testing.T) {
	msp1, err := setupWithTypeAndVersion("testdata/aries/MSP1OU1eid1/", "MSP1", MSPv1_1, IDEMIX_ARIES)
	require.NoError(t, err)
	id1, err := getDefaultSigner(msp1)
	require.NoError(t, err)

	principalBytes, err := proto.Marshal(&msp.MSPRole{Role: msp.MSPRole_PEER, MspIdentifier: id1.GetMSPIdentifier()})
	require.NoError(t, err)
	principalRole := &msp.MSPPrincipal{
		PrincipalClassification: msp.MSPPrincipal_ROLE,
		Principal:               principalBytes}
	err = id1.SatisfiesPrincipal(principalRole)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid MSP role type")
}
