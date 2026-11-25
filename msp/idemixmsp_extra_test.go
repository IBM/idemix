/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"testing"
	"time"

	im "github.com/IBM/idemix/msp/config"
	m "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestMSPGetVersionAndIdentifier(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		t.Helper()

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
		t.Helper()

		msp1, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)

		require.Nil(t, msp1.GetTLSRootCerts())
		require.Nil(t, msp1.GetTLSIntermediateCerts())
	})
}

func TestMSPSatisfiesPrincipal(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		t.Helper()

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
		t.Helper()

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
		t.Helper()

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
		t.Helper()

		msp1, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)

		require.Equal(t, msp1.conf.Signer.EnrollmentId, msp1.EnrollmentID())
	})
}

func TestIdentityAnonymousAndExpiry(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		t.Helper()

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
		t.Helper()

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
		t.Helper()

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
	require.Empty(t, ProviderTypeToString(OTHER))

	// The value formerly used by IDEMIX_ARIES stays reserved so OTHER keeps its old value.
	require.Equal(t, OTHER, ProviderType(3))
	require.Empty(t, ProviderTypeToString(ProviderType(2)))
}

func TestRoleMask(t *testing.T) {
	require.Equal(t, int(MEMBER), GetRoleMaskFromIdemixRole(MEMBER))
	require.Equal(t, int(ADMIN), GetRoleMaskFromIdemixRole(ADMIN))
	require.True(t, CheckRole(GetRoleMaskFromIdemixRole(MEMBER), MEMBER))
	require.False(t, CheckRole(GetRoleMaskFromIdemixRole(MEMBER), ADMIN))
}

func TestGetIdemixMspConfig(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		t.Helper()

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

func TestAccessorsDoNotPanicWithoutSigner(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		t.Helper()

		verMsp, err := setupCurveVerifier(t, sc, "MSP1OU1")
		require.NoError(t, err)

		_, _, err = verMsp.Pseudonym()
		require.EqualError(t, err, "no default signer setup")
		require.Empty(t, verMsp.EnrollmentID())
		require.NotEmpty(t, verMsp.IssuerPublicKey())
	})
}

func TestAccessorsBeforeSetup(t *testing.T) {
	mspInst, err := NewIdemixMsp(MSPv1_3)
	require.NoError(t, err)

	_, _, err = mspInst.Pseudonym()
	require.Error(t, err)
	_, err = mspInst.DeserializeSigningIdentity([]byte("x"))
	require.Error(t, err)
	require.Empty(t, mspInst.EnrollmentID())
	require.Empty(t, mspInst.IssuerPublicKey())
}

func TestSetupResetsStateOnRepeat(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		t.Helper()

		mspInst, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)
		require.NotNil(t, mspInst.signer)

		require.NoError(t, mspInst.Setup(loadCurveVerifierConfig(t, sc, "MSP1OU1", IDEMIX)))
		require.Nil(t, mspInst.signer)
	})
}

// TestSetupFailureKeepsPreviousState checks that a failed re-Setup leaves a working MSP intact.
func TestSetupFailureKeepsPreviousState(t *testing.T) {
	sc := schemeCurve{scheme: "aries", curveID: curveIDBLS12_381_BBS}
	mspInst, err := setupCurve(t, sc, "MSP1OU1")
	require.NoError(t, err)

	bad := loadCurveConfig(t, sc, "MSP1OU1", IDEMIX)
	bad.Type = int32(FABRIC)
	require.Error(t, mspInst.Setup(bad))

	idemixConfig := &im.IdemixMSPConfig{}
	require.NoError(t, proto.Unmarshal(loadCurveConfig(t, sc, "MSP1OU1", IDEMIX).Config, idemixConfig))
	idemixConfig.Ipk = []byte("barf")
	raw, err := proto.Marshal(idemixConfig)
	require.NoError(t, err)
	require.Error(t, mspInst.Setup(&m.MSPConfig{Type: int32(IDEMIX), Config: raw}))

	id, err := getDefaultSigner(t, mspInst)
	require.NoError(t, err)
	sig, err := id.Sign([]byte("msg"))
	require.NoError(t, err)
	require.NoError(t, id.Verify([]byte("msg"), sig))
	require.Equal(t, SchemeAries, mspInst.Scheme())
}

func TestSchemeAccessor(t *testing.T) {
	for _, sc := range []schemeCurve{
		{scheme: "dlog", curveID: curveIDFP256BN_AMCL},
		{scheme: "aries", curveID: curveIDBLS12_381_BBS},
	} {
		mspInst, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)
		require.Equal(t, CryptoScheme(sc.scheme), mspInst.Scheme())
	}
}

func TestDeserializeBeforeSetup(t *testing.T) {
	mspInst, err := NewIdemixMsp(MSPv1_3)
	require.NoError(t, err)
	_, err = mspInst.DeserializeIdentity(nil)
	require.Error(t, err)
	_, err = mspInst.deserializeIdentityInternal([]byte{1})
	require.ErrorContains(t, err, "not set up")
}

func TestGetIdemixMspConfigRejectsNonIdemixType(t *testing.T) {
	_, err := GetIdemixMspConfigWithType("testdata/curves/dlog/FP256BN_AMCL", "X", FABRIC)
	require.Error(t, err)
}

func TestIssuerPublicKeyReturnsCopy(t *testing.T) {
	sc := schemeCurve{scheme: "dlog", curveID: curveIDFP256BN_AMCL}
	mspInst, err := setupCurve(t, sc, "MSP1OU1")
	require.NoError(t, err)
	a := mspInst.IssuerPublicKey()
	a[0] ^= 0xff
	require.NotEqual(t, a, mspInst.IssuerPublicKey())
}

func TestIsWellFormedNil(t *testing.T) {
	mspInst, err := NewIdemixMsp(MSPv1_3)
	require.NoError(t, err)
	require.Error(t, mspInst.IsWellFormed(nil))
}
