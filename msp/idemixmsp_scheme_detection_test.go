/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
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

				conf := loadCurveConfig(t, sc, "MSP1OU1", tc.declaredType)

				err = mspInst.Setup(conf)

				if tc.expectErr != "" {
					require.Error(t, err)
					require.Contains(t, err.Error(), tc.expectErr)

					return
				}

				require.NoError(t, err)

				id2, err := getDefaultSigner(mspInst)
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

	id, err := getDefaultSigner(mspInst)
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

			err = mspInst.Setup(conf)
			require.NoError(t, err)

			id, err := getDefaultSigner(mspInst)
			require.NoError(t, err)

			msg := []byte("TestMessage")
			sig, err := id.Sign(msg)
			require.NoError(t, err)
			require.NoError(t, id.Verify(msg, sig))
		})
	}
}
