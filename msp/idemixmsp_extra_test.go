/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"testing"
	"time"

	m "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestMSPGetVersionAndIdentifier(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)

		require.Equal(t, MSPVersion(MSPv1_3), msp1.GetVersion())

		id, err := msp1.GetIdentifier()
		require.NoError(t, err)
		require.Equal(t, "MSP1OU1", id)
	})
}

func TestMSPGetTLSCerts(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)

		require.Nil(t, msp1.GetTLSRootCerts())
		require.Nil(t, msp1.GetTLSIntermediateCerts())
	})
}

func TestMSPSatisfiesPrincipal(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)

		id1, err := getDefaultSigner(t, msp1)
		require.NoError(t, err)

		principalBytes, err := proto.Marshal(&m.MSPRole{Role: m.MSPRole_MEMBER, MspIdentifier: id1.GetMSPIdentifier()})
		require.NoError(t, err)

		principal := &m.MSPPrincipal{
			PrincipalClassification: m.MSPPrincipal_ROLE,
			Principal:               principalBytes,
		}

		require.NoError(t, msp1.SatisfiesPrincipal(id1, principal))
	})
}

func TestMSPSatisfiesPrincipalInvalidIdentity(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)
		msp2, err := setupCurve(t, sc, "MSP2OU1")
		require.NoError(t, err)

		id2, err := getDefaultSigner(t, msp2)
		require.NoError(t, err)

		err = msp1.SatisfiesPrincipal(id2, &m.MSPPrincipal{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "identity is not valid with respect to this MSP")
	})
}

func TestPseudonym(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)

		idemixMsp := msp1

		pseudo, revocationHandle, err := idemixMsp.Pseudonym()
		require.NoError(t, err)
		require.Nil(t, revocationHandle)
		require.NotNil(t, pseudo)

		require.NoError(t, msp1.Validate(pseudo))

		msg := []byte("pseudonym message")
		sig, err := pseudo.Sign(msg)
		require.NoError(t, err)
		require.NoError(t, pseudo.Verify(msg, sig))
	})
}

func TestEnrollmentID(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)

		require.Equal(t, msp1.conf.Signer.EnrollmentId, msp1.EnrollmentID())
	})
}

func TestIdentityAnonymousAndExpiry(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)

		id1, err := getDefaultSigner(t, msp1)
		require.NoError(t, err)

		require.True(t, id1.Anonymous())
		require.True(t, id1.ExpiresAt().IsZero())
		require.Equal(t, time.Time{}, id1.ExpiresAt())
	})
}

func TestSigningIdentityGetPublicVersion(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)

		id1, err := getDefaultSigner(t, msp1)
		require.NoError(t, err)

		signingID, ok := id1.(*signingIdentity)
		require.True(t, ok)

		pub := signingID.GetPublicVersion()
		require.Equal(t, signingID.identity, pub)
	})
}

func TestValidateUnrecognizedIdentityType(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)

		err = msp1.Validate(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "identity type")
	})
}

func TestProviderTypeToString(t *testing.T) {
	require.Equal(t, "bccsp", ProviderTypeToString(FABRIC))
	require.Equal(t, "idemix", ProviderTypeToString(IDEMIX))
	require.Equal(t, "", ProviderTypeToString(OTHER))
}

func TestRoleMask(t *testing.T) {
	require.Equal(t, int(MEMBER), GetRoleMaskFromIdemixRole(MEMBER))
	require.Equal(t, int(ADMIN), GetRoleMaskFromIdemixRole(ADMIN))
	require.True(t, CheckRole(GetRoleMaskFromIdemixRole(MEMBER), MEMBER))
	require.False(t, CheckRole(GetRoleMaskFromIdemixRole(MEMBER), ADMIN))
}

func TestGetIdemixMspConfig(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		conf, err := GetIdemixMspConfig(sc.dir(), "MSP1OU1")
		require.NoError(t, err)
		require.Equal(t, int32(IDEMIX), conf.Type)
	})
}

func TestStdLogger(t *testing.T) {
	logger := &stdLogger{prefix: "test"}
	require.True(t, logger.IsEnabledFor(0))
	logger.Debug("hello")
	logger.Debugf("hello %s", "world")
	logger.Errorf("bad %s", "thing")
}
