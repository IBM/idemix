/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"testing"

	m "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// An identity built by one MSP instance must still validate under another instance set up from
// the same configuration (same issuer, same name).
func TestValidateIdentityFromEquivalentMSPInstance(t *testing.T) {
	forFindingSchemeCurves(t, func(t *testing.T, sc schemeCurve) {
		t.Helper()
		mspA, err := setupCurve(t, sc, "MSP1")
		require.NoError(t, err)
		mspB, err := setupCurveVerifier(t, sc, "MSP1")
		require.NoError(t, err)

		id, err := mspA.GetDefaultSigningIdentity()
		require.NoError(t, err)
		require.NoError(t, mspB.Validate(id))

		member, err := proto.Marshal(&m.MSPRole{MspIdentifier: "MSP1", Role: m.MSPRole_MEMBER})
		require.NoError(t, err)
		require.NoError(t, mspB.SatisfiesPrincipal(id, &m.MSPPrincipal{
			PrincipalClassification: m.MSPPrincipal_ROLE,
			Principal:               member,
		}))
	})
}

// COMBINED principals nested up to maxCombinedPrincipalDepth levels are still evaluated.
func TestCombinedPrincipalNestingWithinLimit(t *testing.T) {
	mspI, err := setupCurve(t, findingSchemeCurves[0], "MSP1")
	require.NoError(t, err)
	id, err := mspI.GetDefaultSigningIdentity()
	require.NoError(t, err)

	member, err := proto.Marshal(&m.MSPRole{Role: m.MSPRole_MEMBER, MspIdentifier: "MSP1"})
	require.NoError(t, err)
	nest := func(levels int) *m.MSPPrincipal {
		p := &m.MSPPrincipal{PrincipalClassification: m.MSPPrincipal_ROLE, Principal: member}
		for range levels {
			cb, err := proto.Marshal(&m.CombinedPrincipal{Principals: []*m.MSPPrincipal{p}})
			require.NoError(t, err)
			p = &m.MSPPrincipal{PrincipalClassification: m.MSPPrincipal_COMBINED, Principal: cb}
		}

		return p
	}

	require.NoError(t, id.SatisfiesPrincipal(nest(maxCombinedPrincipalDepth)))
	require.Error(t, id.SatisfiesPrincipal(nest(maxCombinedPrincipalDepth+1)))
}

// IsWellFormed accepts honest identities and rejects undefined roles and malformed pseudonyms.
func TestIsWellFormedStructuralChecks(t *testing.T) {
	forFindingSchemeCurves(t, func(t *testing.T, sc schemeCurve) {
		t.Helper()
		mspI, err := setupCurve(t, sc, "MSP1")
		require.NoError(t, err)
		id, err := mspI.GetDefaultSigningIdentity()
		require.NoError(t, err)
		require.NoError(t, mspI.IsWellFormed(&m.SerializedIdentity{Mspid: "MSP1", IdBytes: mustMarshal(t, serializedIdemix(t, id))}))

		bad := serializedIdemix(t, id)
		bad.NymY = bad.NymY[1:]
		require.Error(t, mspI.IsWellFormed(&m.SerializedIdentity{Mspid: "MSP1", IdBytes: mustMarshal(t, bad)}))

		bad = serializedIdemix(t, id)
		bad.Role = mustMarshal(t, &m.MSPRole{MspIdentifier: "MSP1", Role: m.MSPRole_ORDERER})
		require.Error(t, mspI.IsWellFormed(&m.SerializedIdentity{Mspid: "MSP1", IdBytes: mustMarshal(t, bad)}))
	})
}

func mustMarshal(t *testing.T, msg proto.Message) []byte {
	t.Helper()
	raw, err := proto.Marshal(msg)
	require.NoError(t, err)

	return raw
}
