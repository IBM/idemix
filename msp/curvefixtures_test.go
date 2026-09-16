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
// and that curveAndTranslator understands (MSP/idemixmsp.go).
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

// schemeCurve identifies one of the fixture sets generated under
// testdata/curves/<scheme>/<curveID>/ by testdata/curves/generate.sh.
type schemeCurve struct {
	scheme  string
	curveID string
}

func (sc schemeCurve) name() string     { return sc.scheme + "/" + sc.curveID }
func (sc schemeCurve) dir() string      { return "testdata/curves/" + sc.scheme + "/" + sc.curveID }
func (sc schemeCurve) adminDir() string { return sc.dir() + "/admin" }

// allSchemeCurves returns every combination of scheme and curve that has fixtures under
// testdata/curves/.
func allSchemeCurves() []schemeCurve {
	schemeCurves := make([]schemeCurve, 0, 2*len(allCurveIDs))
	for _, scheme := range []string{"dlog", "aries"} {
		for _, curveID := range allCurveIDs {
			schemeCurves = append(schemeCurves, schemeCurve{scheme: scheme, curveID: curveID})
		}
	}

	return schemeCurves
}

// forEachSchemeCurve runs fn as a subtest for every scheme/curve combination available
// under testdata/curves/. Subtests run sequentially: the underlying amcl/BLS12-381 curve
// libraries use package-level scratch state that is not safe for concurrent use, so
// t.Parallel() here would trigger spurious data races under -race.
func forEachSchemeCurve(t *testing.T, fn func(t *testing.T, sc schemeCurve)) {
	t.Helper()

	for _, sc := range allSchemeCurves() {
		t.Run(sc.name(), func(t *testing.T) {
			fn(t, sc)
		})
	}
}

// stampCurveID rewrites conf's embedded IdemixMSPConfig.CurveId, so that Setup resolves the
// curve/translator pair explicitly named by curveID rather than falling back to a scheme's
// default curve.
func stampCurveID(t *testing.T, conf *m.MSPConfig, curveID string) {
	t.Helper()

	idemixConfig := &im.IdemixMSPConfig{}
	require.NoError(t, proto.Unmarshal(conf.Config, idemixConfig))
	idemixConfig.CurveId = curveID

	confBytes, err := proto.Marshal(idemixConfig)
	require.NoError(t, err)
	conf.Config = confBytes
}

// loadCurveConfig loads the default (single OU1/eid1/rh1 member signer) fixture for sc.
func loadCurveConfig(t *testing.T, sc schemeCurve, mspID string, mspType ProviderType) *m.MSPConfig {
	t.Helper()

	conf, err := GetIdemixMspConfigWithType(sc.dir(), mspID, mspType)
	require.NoError(t, err)
	stampCurveID(t, conf, sc.curveID)

	return conf
}

// loadCurveAdminConfig loads the admin-role signer fixture for sc (same CA/MSP as the
// default fixture, but the signer's credential is issued with the ADMIN role mask).
func loadCurveAdminConfig(t *testing.T, sc schemeCurve, mspID string, mspType ProviderType) *m.MSPConfig {
	t.Helper()

	conf, err := GetIdemixMspConfigWithType(sc.adminDir(), mspID, mspType)
	require.NoError(t, err)
	stampCurveID(t, conf, sc.curveID)

	return conf
}

// loadCurveVerifierConfig loads the default fixture for sc with its signer credential
// stripped out, producing a verification-only MSP config (no default signing identity).
func loadCurveVerifierConfig(t *testing.T, sc schemeCurve, mspID string, mspType ProviderType) *m.MSPConfig {
	t.Helper()

	conf := loadCurveConfig(t, sc, mspID, mspType)

	idemixConfig := &im.IdemixMSPConfig{}
	require.NoError(t, proto.Unmarshal(conf.Config, idemixConfig))
	idemixConfig.Signer = nil

	confBytes, err := proto.Marshal(idemixConfig)
	require.NoError(t, err)
	conf.Config = confBytes

	return conf
}

func setupCurveWithTypeAndVersion(t *testing.T, sc schemeCurve, mspID string, version MSPVersion, mspType ProviderType) (*MSP, error) {
	t.Helper()

	mspInst, err := NewIdemixMsp(version)
	if err != nil {
		return nil, err
	}

	if err := mspInst.Setup(loadCurveConfig(t, sc, mspID, mspType)); err != nil {
		return nil, err
	}

	return mspInst, nil
}

func setupCurve(t *testing.T, sc schemeCurve, mspID string) (*MSP, error) {
	t.Helper()

	return setupCurveWithTypeAndVersion(t, sc, mspID, MSPv1_3, IDEMIX)
}

func setupCurveWithVersion(t *testing.T, sc schemeCurve, mspID string, version MSPVersion) (*MSP, error) {
	t.Helper()

	return setupCurveWithTypeAndVersion(t, sc, mspID, version, IDEMIX)
}

func setupCurveAdmin(t *testing.T, sc schemeCurve, mspID string) (*MSP, error) {
	t.Helper()

	mspInst, err := NewIdemixMsp(MSPv1_3)
	if err != nil {
		return nil, err
	}

	if err := mspInst.Setup(loadCurveAdminConfig(t, sc, mspID, IDEMIX)); err != nil {
		return nil, err
	}

	return mspInst, nil
}

func setupCurveVerifier(t *testing.T, sc schemeCurve, mspID string) (*MSP, error) {
	t.Helper()

	mspInst, err := NewIdemixMsp(MSPv1_3)
	if err != nil {
		return nil, err
	}

	if err := mspInst.Setup(loadCurveVerifierConfig(t, sc, mspID, IDEMIX)); err != nil {
		return nil, err
	}

	return mspInst, nil
}

// badSigVerifyError returns the error message id.Verify produces for a corrupted signature
// under sc's scheme: dlog and Aries fail this check in different internal proof steps.
func badSigVerifyError(sc schemeCurve) string {
	if sc.scheme == "aries" {
		return "contribution is not zero"
	}

	return "zero-knowledge proof is invalid"
}
