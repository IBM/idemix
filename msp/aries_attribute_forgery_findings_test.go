/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"testing"

	bccsp "github.com/IBM/idemix/bccsp/types"
	im "github.com/IBM/idemix/msp/config"
	m "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// FINDING-MSP-ARIES-ATTR: end-to-end version of the Aries Signer.Verify finding
// (TestFindingSignerVerifyAcceptsUndisclosedAttribute). A MEMBER with a genuine credential for
// OU1 builds its association proof with every attribute hidden, then serializes an identity
// claiming another OU and the ADMIN role. The receiving MSP must reject it in Validate, and
// therefore it must not satisfy an ADMIN or OU principal. The same forgery is attempted on dlog
// as a control: dlog binds the disclosure pattern into the proof and rejects it.
func TestFindingForgedOUAndRoleAcceptedByMSP(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		t.Helper()

		mspI, err := setupCurve(t, sc, "MSP1")
		require.NoError(t, err)
		signer := mspI.signer
		require.Equal(t, m.MSPRole_MEMBER, signer.Role.Role)

		proof, err := mspI.csp.Sign(signer.UserKey, nil, &bccsp.IdemixSignerOpts{
			Credential: signer.Cred,
			Nym:        signer.NymKey,
			IssuerPK:   mspI.ipk,
			Attributes: []bccsp.IdemixAttribute{
				{Type: bccsp.IdemixHiddenAttribute},
				{Type: bccsp.IdemixHiddenAttribute},
				{Type: bccsp.IdemixHiddenAttribute},
				{Type: bccsp.IdemixHiddenAttribute},
			},
			RhIndex:  rhIndex,
			EidIndex: eidIndex,
			CRI:      mspI.conf.Signer.CredentialRevocationInformation,
			SigType:  bccsp.Standard,
		})
		if err != nil {
			// dlog may refuse to produce such a proof; that is not the bug under test.
			t.Skipf("scheme refuses all-hidden proof: %v", err)
		}

		nym, err := signer.NymPublicKey.Bytes()
		require.NoError(t, err)
		ou, err := proto.Marshal(&m.OrganizationUnit{
			MspIdentifier:                "MSP1",
			OrganizationalUnitIdentifier: "EVIL-OU",
			CertifiersIdentifier:         mspI.ipk.SKI(),
		})
		require.NoError(t, err)
		role, err := proto.Marshal(&m.MSPRole{MspIdentifier: "MSP1", Role: m.MSPRole_ADMIN})
		require.NoError(t, err)
		inner, err := proto.Marshal(&im.SerializedIdemixIdentity{
			NymX: nym[:len(nym)/2], NymY: nym[len(nym)/2:], Ou: ou, Role: role, Proof: proof,
		})
		require.NoError(t, err)
		raw, err := proto.Marshal(&m.SerializedIdentity{Mspid: "MSP1", IdBytes: inner})
		require.NoError(t, err)

		forged, err := mspI.DeserializeIdentity(raw)
		require.NoError(t, err)

		require.Error(t, mspI.Validate(forged), "a member must not be able to claim another OU and the ADMIN role")

		admin, err := proto.Marshal(&m.MSPRole{MspIdentifier: "MSP1", Role: m.MSPRole_ADMIN})
		require.NoError(t, err)
		require.Error(t, mspI.SatisfiesPrincipal(forged, &m.MSPPrincipal{
			PrincipalClassification: m.MSPPrincipal_ROLE, Principal: admin,
		}), "a forged identity must not satisfy an ADMIN principal")
	})
}
