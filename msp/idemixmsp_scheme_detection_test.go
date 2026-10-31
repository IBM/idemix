/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"os"
	"path/filepath"
	"testing"

	im "github.com/IBM/idemix/msp/config"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// TestSetupSchemeAutoDetection checks that Setup accepts both dlog- and Aries-flavored
// material under the single IDEMIX config type, auto-detecting which scheme applies, and
// still rejects a config that does not declare type IDEMIX.
func TestSetupSchemeAutoDetection(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		t.Helper()

		type testCase struct {
			name         string
			declaredType ProviderType
			expectErr    string // empty means Setup must succeed and identity must sign/verify
		}

		cases := []testCase{
			{"IDEMIX", IDEMIX, ""},
			{"FABRIC", FABRIC, "unsupported config type"},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				mspInst, err := NewIdemixMsp(MSPv1_3)
				require.NoError(t, err)

				conf := loadCurveConfig(t, sc, "MSP1OU1", IDEMIX)
				conf.Type = int32(tc.declaredType) //nolint:gosec // small enum

				err = mspInst.Setup(conf)

				if tc.expectErr != "" {
					require.Error(t, err)
					require.Contains(t, err.Error(), tc.expectErr)

					return
				}

				require.NoError(t, err)

				id2, err := getDefaultSigner(t, mspInst)
				require.NoError(t, err)

				msg := []byte("TestMessage")
				sig, err := id2.Sign(msg)
				require.NoError(t, err)
				require.NoError(t, id2.Verify(msg, sig))
			})
		}
	})
}

func TestSetupCurveFromConfig(t *testing.T) {
	mspInst, err := NewIdemixMsp(MSPv1_3)
	require.NoError(t, err)

	conf, err := GetIdemixMspConfigWithType("testdata/curves/aries/BLS12_381_BBS", "MSP1OU1eid1", IDEMIX)
	require.NoError(t, err)

	idemixConfig := &im.IdemixMSPConfig{}
	require.NoError(t, proto.Unmarshal(conf.Config, idemixConfig))
	idemixConfig.CurveId = curveIDBLS12_381_BBS_GURVY

	confBytes, err := proto.Marshal(idemixConfig)
	require.NoError(t, err)
	conf.Config = confBytes

	err = mspInst.Setup(conf)
	require.NoError(t, err)

	id, err := getDefaultSigner(t, mspInst)
	require.NoError(t, err)

	msg := []byte("TestMessage")
	sig, err := id.Sign(msg)
	require.NoError(t, err)
	require.NoError(t, id.Verify(msg, sig))
}

// TestSetupCurveMismatch checks Setup's behavior when Aries material is re-stamped with a
// non-BBS curve of the same compressed-G2 size as its true curve (BLS12_381 vs
// BLS12_381_BBS): the IPK import no longer discriminates on curve family, so it succeeds, and
// the mismatch only surfaces once the default signer's credential is verified against the
// wrong curve's generators.
func TestSetupCurveMismatch(t *testing.T) {
	mspInst, err := NewIdemixMsp(MSPv1_3)
	require.NoError(t, err)

	conf, err := GetIdemixMspConfigWithType("testdata/curves/aries/BLS12_381_BBS", "MSP1OU1eid1", IDEMIX)
	require.NoError(t, err)

	idemixConfig := &im.IdemixMSPConfig{}
	require.NoError(t, proto.Unmarshal(conf.Config, idemixConfig))
	idemixConfig.CurveId = curveIDBLS12_381

	confBytes, err := proto.Marshal(idemixConfig)
	require.NoError(t, err)
	conf.Config = confBytes

	err = mspInst.Setup(conf)
	require.Error(t, err)
	require.Contains(t, err.Error(), "credential is not cryptographically valid")
}

func TestSetupWithLoggerNilLogger(t *testing.T) {
	mspInst, err := NewIdemixMspWithLogger(MSPv1_3, nil)
	require.NoError(t, err)
	require.NotNil(t, mspInst)
}

func TestSetupNilConf(t *testing.T) {
	mspInst, err := NewIdemixMsp(MSPv1_3)
	require.NoError(t, err)

	err = mspInst.Setup(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "setup error: nil conf reference")
}

// TestSetupDefaultCurve checks that Setup resolves each scheme's default curve when the
// config leaves CurveId empty.
func TestSetupDefaultCurve(t *testing.T) {
	for _, sc := range []schemeCurve{
		{scheme: "dlog", curveID: curveIDFP256BN_AMCL},
		{scheme: "aries", curveID: curveIDBLS12_381_BBS},
	} {
		t.Run(sc.name(), func(t *testing.T) {
			mspInst, err := NewIdemixMsp(MSPv1_3)
			require.NoError(t, err)

			conf, err := GetIdemixMspConfigWithType(sc.dir(), "MSP1OU1", IDEMIX)
			require.NoError(t, err)
			stampCurveID(t, conf, "")

			err = mspInst.Setup(conf)
			require.NoError(t, err)

			id, err := getDefaultSigner(t, mspInst)
			require.NoError(t, err)

			msg := []byte("TestMessage")
			sig, err := id.Sign(msg)
			require.NoError(t, err)
			require.NoError(t, id.Verify(msg, sig))
		})
	}
}

// TestSetupUnstampedConfig loads every fixture through GetIdemixMspConfig alone, i.e. relying on
// the curve_id recorded in SignerConfig by idemixgen rather than on stampCurveID, and checks that both a
// full and a verification-only MSP come up on the right curve: the verifier must accept the
// signer's identity. BLS12_381 and BLS12_381_BBS share the same G2 encoding, so without the
// curve id a verifier-only Aries BLS12_381 config would set up on the wrong curve.
func TestSetupUnstampedConfig(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		t.Helper()

		conf, err := GetIdemixMspConfig(sc.dir(), "MSP1OU1")
		require.NoError(t, err)
		signerMsp, err := NewIdemixMsp(MSPv1_3)
		require.NoError(t, err)
		require.NoError(t, signerMsp.Setup(conf))
		require.Equal(t, CryptoScheme(sc.scheme), signerMsp.Scheme())

		id, err := signerMsp.GetDefaultSigningIdentity()
		require.NoError(t, err)
		serialized, err := id.Serialize()
		require.NoError(t, err)

		verConf, err := GetIdemixMspConfig(sc.dir(), "MSP1OU1")
		require.NoError(t, err)
		idemixConfig := &im.IdemixMSPConfig{}
		require.NoError(t, proto.Unmarshal(verConf.Config, idemixConfig))
		idemixConfig.Signer = nil
		verConf.Config, err = proto.Marshal(idemixConfig)
		require.NoError(t, err)

		verMsp, err := NewIdemixMsp(MSPv1_3)
		require.NoError(t, err)
		require.NoError(t, verMsp.Setup(verConf))

		got, err := verMsp.DeserializeIdentity(serialized)
		require.NoError(t, err)
		require.NoError(t, verMsp.Validate(got))
	})
}

// TestGetIdemixMspConfigInvalidCurveID checks that an unknown curve id in the signer config is
// rejected when loading the config.
func TestGetIdemixMspConfigInvalidCurveID(t *testing.T) {
	dir := t.TempDir()
	src := "testdata/curves/dlog/FP256BN_AMCL/"
	for _, f := range []string{
		filepath.Join(IdemixConfigDirMsp, IdemixConfigFileIssuerPublicKey),
		filepath.Join(IdemixConfigDirMsp, IdemixConfigFileRevocationPublicKey),
		filepath.Join(IdemixConfigDirUser, IdemixConfigFileSigner),
	} {
		raw, err := os.ReadFile(src + f)
		require.NoError(t, err)
		if f == filepath.Join(IdemixConfigDirUser, IdemixConfigFileSigner) {
			signer := &im.IdemixMSPSignerConfig{}
			require.NoError(t, proto.Unmarshal(raw, signer))
			signer.CurveId = "NOPE"
			raw, err = proto.Marshal(signer)
			require.NoError(t, err)
		}
		dst := filepath.Join(dir, f)
		require.NoError(t, os.MkdirAll(filepath.Dir(dst), 0o750))
		require.NoError(t, os.WriteFile(dst, raw, 0o600)) //nolint:gosec // dst is under t.TempDir()
	}

	_, err := GetIdemixMspConfig(dir, "X")
	require.ErrorContains(t, err, "invalid curve id")
}
