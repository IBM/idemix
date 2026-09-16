/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"testing"

	im "github.com/IBM/idemix/msp/config"
	m "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// allCurveIDs mirrors the curve set idemixgen can produce (tools/idemixgen/main.go)
// and that curveAndTranslator understands (msp/idemixmsp.go).
var allCurveIDs = []string{
	curveIDFP256BN_AMCL,
	curveIDBN254,
	curveIDFP256BN_AMCL_MIRACL,
	curveIDBLS12_377_GURVY,
	curveIDBLS12_381_GURVY,
	curveIDBLS12_381,
	curveIDBLS12_381_BBS,
	curveIDBLS12_381_BBS_GURVY,
}

// loadCurveConfig builds an MSPConfig from the fixtures generated under
// testdata/curves/<scheme>/<curveID> (via `idemixgen ca-keygen [--aries] -c <curveID>` and
// `idemixgen signerconfig [--aries] -c <curveID> ...`), declaring it as declaredType and
// stamping CurveId explicitly so Setup resolves the curve from the config as intended.
func loadCurveConfig(t *testing.T, scheme, curveID string, declaredType ProviderType) *m.MSPConfig {
	t.Helper()

	dir := "testdata/curves/" + scheme + "/" + curveID
	conf, err := GetIdemixMspConfigWithType(dir, "CurveTestMSP", declaredType)
	require.NoError(t, err)

	idemixConfig := &im.IdemixMSPConfig{}
	require.NoError(t, proto.Unmarshal(conf.Config, idemixConfig))
	idemixConfig.CurveId = curveID

	confBytes, err := proto.Marshal(idemixConfig)
	require.NoError(t, err)
	conf.Config = confBytes

	return conf
}

func verifySignsAndVerifies(t *testing.T, mspInst MSP) {
	t.Helper()

	id, err := getDefaultSigner(mspInst)
	require.NoError(t, err)

	msg := []byte("TestMessage")
	sig, err := id.Sign(msg)
	require.NoError(t, err)
	require.NoError(t, id.Verify(msg, sig))
}

// TestDlogAllCurves checks that NewIdemixMsp's Setup accepts every curve idemixgen can
// generate dlog material for.
func TestDlogAllCurves(t *testing.T) {
	for _, curveID := range allCurveIDs {
		t.Run(curveID, func(t *testing.T) {
			mspInst, err := NewIdemixMsp(MSPv1_3)
			require.NoError(t, err)

			conf := loadCurveConfig(t, "dlog", curveID, IDEMIX)

			require.NoError(t, mspInst.Setup(conf))
			verifySignsAndVerifies(t, mspInst)
		})
	}
}

// TestAriesAllCurves checks that Setup's Aries/BBS+ fallback accepts every curve idemixgen
// can generate Aries-flavored material for, with no BBS-only restriction.
func TestAriesAllCurves(t *testing.T) {
	for _, curveID := range allCurveIDs {
		t.Run(curveID, func(t *testing.T) {
			mspInst, err := NewIdemixMsp(MSPv1_3)
			require.NoError(t, err)

			conf := loadCurveConfig(t, "aries", curveID, IDEMIX)

			require.NoError(t, mspInst.Setup(conf))
			verifySignsAndVerifies(t, mspInst)
		})
	}
}
