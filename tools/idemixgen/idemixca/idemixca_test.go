/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemixca

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	m "github.com/IBM/idemix"
	idemix "github.com/IBM/idemix/bccsp/schemes/dlog/crypto"
	amclt "github.com/IBM/idemix/bccsp/schemes/dlog/crypto/translator/amcl"
	math "github.com/IBM/mathlib"
	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

var testDir = filepath.Join(os.TempDir(), "idemixca-test")

func TestIdemixCa(t *testing.T) {
	cleanup()

	curve := math.Curves[math.FP256BN_AMCL]
	tr := &amclt.Fp256bn{
		C: curve,
	}

	idmx := &idemix.Idemix{
		Curve: curve,
	}

	isk, ipkBytes, err := GenerateIssuerKey(idmx, tr)
	require.NoError(t, err)

	revocationkey, err := idmx.GenerateLongTermRevocationKey()
	require.NoError(t, err)

	ipk := &idemix.IssuerPublicKey{}
	err = proto.Unmarshal(ipkBytes, ipk)
	require.NoError(t, err)

	encodedRevocationPK, err := x509.MarshalPKIXPublicKey(revocationkey.Public())
	require.NoError(t, err)
	pemEncodedRevocationPK := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encodedRevocationPK})

	writeVerifierToFile(ipkBytes, pemEncodedRevocationPK)

	key := &idemix.IssuerKey{Isk: isk, Ipk: ipk}

	conf, err := GenerateSignerConfig(m.GetRoleMaskFromIdemixRole(m.MEMBER), "OU1", "enrollmentid1", "1", key, revocationkey, idmx, tr)
	require.NoError(t, err)
	cleanupSigner()
	require.NoError(t, writeSignerToFile(conf))
	require.NoError(t, setupMSP())

	conf, err = GenerateSignerConfig(m.GetRoleMaskFromIdemixRole(m.ADMIN), "OU1", "enrollmentid2", "1234", key, revocationkey, idmx, tr)
	require.NoError(t, err)
	cleanupSigner()
	require.NoError(t, writeSignerToFile(conf))
	require.NoError(t, setupMSP())

	// Without the verifier dir present, setup should give an error
	cleanupVerifier()
	require.Error(t, setupMSP())

	_, err = GenerateSignerConfig(m.GetRoleMaskFromIdemixRole(m.ADMIN), "", "enrollmentid", "1", key, revocationkey, idmx, tr)
	require.EqualError(t, err, "the OU attribute value is empty")

	_, err = GenerateSignerConfig(m.GetRoleMaskFromIdemixRole(m.ADMIN), "OU1", "", "1", key, revocationkey, idmx, tr)
	require.EqualError(t, err, "the enrollment id value is empty")
}

func cleanup() error {
	// clean up any previous files
	err := os.RemoveAll(testDir)
	if err != nil {
		return nil
	}
	return os.Mkdir(testDir, os.ModePerm)
}

func cleanupSigner() {
	os.RemoveAll(filepath.Join(testDir, m.IdemixConfigDirUser))
}

func cleanupVerifier() {
	os.RemoveAll(filepath.Join(testDir, m.IdemixConfigDirMsp))
}

func writeVerifierToFile(ipkBytes []byte, revpkBytes []byte) error {
	err := os.Mkdir(filepath.Join(testDir, m.IdemixConfigDirMsp), os.ModePerm)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filepath.Join(testDir, m.IdemixConfigDirMsp, m.IdemixConfigFileIssuerPublicKey), ipkBytes, 0644)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filepath.Join(testDir, m.IdemixConfigDirMsp, m.IdemixConfigFileRevocationPublicKey), revpkBytes, 0644)
}

func writeSignerToFile(signerBytes []byte) error {
	err := os.Mkdir(filepath.Join(testDir, m.IdemixConfigDirUser), os.ModePerm)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filepath.Join(testDir, m.IdemixConfigDirUser, m.IdemixConfigFileSigner), signerBytes, 0644)
}

// setupMSP tests whether we can successfully setup an idemix msp
// with the generated config bytes
func setupMSP() error {
	// setup an idemix msp from the test directory
	msp, err := m.NewIdemixMsp(m.MSPv1_1)
	if err != nil {
		return errors.Wrap(err, "Getting MSP failed")
	}
	mspConfig, err := m.GetIdemixMspConfig(testDir, "TestName")

	if err != nil {
		return err
	}

	return msp.Setup(mspConfig)
}
