/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemixca

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/IBM/idemix/bccsp/schemes/aries"
	idemix "github.com/IBM/idemix/bccsp/schemes/dlog/crypto"
	amclt "github.com/IBM/idemix/bccsp/schemes/dlog/crypto/translator/amcl"
	imsp "github.com/IBM/idemix/msp"
	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

var testDir = filepath.Join(os.TempDir(), "idemixca-test")

func TestIdemixCaAries(t *testing.T) {
	cleanup()

	curve := math.Curves[math.BLS12_381_BBS]
	rng, err := curve.Rand()
	require.NoError(t, err)

	iskBytes, ipkBytes, err := GenerateIssuerKeyAries(curve)
	require.NoError(t, err)

	revAuth := &aries.RevocationAuthority{
		Curve: curve,
		Rng:   rng,
	}

	issuer := &aries.Issuer{Curve: curve}

	revocationkey, err := revAuth.NewKey()
	require.NoError(t, err)

	AttributeNames := []string{imsp.AttributeNameOU, imsp.AttributeNameRole, imsp.AttributeNameEnrollmentId, imsp.AttributeNameRevocationHandle}
	ipk, err := issuer.NewPublicKeyFromBytes(ipkBytes, AttributeNames)
	require.NoError(t, err)
	isk, err := issuer.NewKeyFromBytes(iskBytes, AttributeNames)
	require.NoError(t, err)

	_ = ipk
	_ = isk

	encodedRevocationPK, err := x509.MarshalPKIXPublicKey(revocationkey.Public())
	require.NoError(t, err)
	pemEncodedRevocationPK := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encodedRevocationPK})

	writeVerifierToFile(ipkBytes, pemEncodedRevocationPK)

	conf, err := GenerateSignerConfigAries(imsp.GetRoleMaskFromIdemixRole(imsp.MEMBER), "OU1", "enrollmentid1", "1", iskBytes, ipkBytes, revocationkey, curve)
	require.NoError(t, err)
	cleanupSigner()
	require.NoError(t, writeSignerToFile(conf))
	require.NoError(t, setupMSP(imsp.IDEMIX_ARIES))

	conf, err = GenerateSignerConfigAries(imsp.GetRoleMaskFromIdemixRole(imsp.ADMIN), "OU1", "enrollmentid2", "1234", iskBytes, ipkBytes, revocationkey, curve)
	require.NoError(t, err)
	cleanupSigner()
	require.NoError(t, writeSignerToFile(conf))
	require.NoError(t, setupMSP(imsp.IDEMIX_ARIES))

	// Without the verifier dir present, setup should give an error
	cleanupVerifier()
	require.Error(t, setupMSP(imsp.IDEMIX_ARIES))

	_, err = GenerateSignerConfigAries(imsp.GetRoleMaskFromIdemixRole(imsp.ADMIN), "", "enrollmentid", "1", iskBytes, ipkBytes, revocationkey, curve)
	require.EqualError(t, err, "the OU attribute value is empty")

	_, err = GenerateSignerConfigAries(imsp.GetRoleMaskFromIdemixRole(imsp.ADMIN), "OU1", "", "1", iskBytes, ipkBytes, revocationkey, curve)
	require.EqualError(t, err, "the enrollment id value is empty")
}

func TestIdemixCa(t *testing.T) {
	cleanup()

	curve := math.Curves[math.FP256BN_AMCL]
	tr := &amclt.Fp256bn{
		C: curve,
	}

	idmx := &idemix.Idemix{
		Curve: curve,
	}

	iskBytes, ipkBytes, err := GenerateIssuerKey(idmx, tr)
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

	conf, err := GenerateSignerConfig(imsp.GetRoleMaskFromIdemixRole(imsp.MEMBER), "OU1", "enrollmentid1", "1", iskBytes, ipkBytes, revocationkey, idmx, tr)
	require.NoError(t, err)
	cleanupSigner()
	require.NoError(t, writeSignerToFile(conf))
	require.NoError(t, setupMSP(imsp.IDEMIX))

	conf, err = GenerateSignerConfig(imsp.GetRoleMaskFromIdemixRole(imsp.ADMIN), "OU1", "enrollmentid2", "1234", iskBytes, ipkBytes, revocationkey, idmx, tr)
	require.NoError(t, err)
	cleanupSigner()
	require.NoError(t, writeSignerToFile(conf))
	require.NoError(t, setupMSP(imsp.IDEMIX))

	// Without the verifier dir present, setup should give an error
	cleanupVerifier()
	require.Error(t, setupMSP(imsp.IDEMIX))

	_, err = GenerateSignerConfig(imsp.GetRoleMaskFromIdemixRole(imsp.ADMIN), "", "enrollmentid", "1", iskBytes, ipkBytes, revocationkey, idmx, tr)
	require.EqualError(t, err, "the OU attribute value is empty")

	_, err = GenerateSignerConfig(imsp.GetRoleMaskFromIdemixRole(imsp.ADMIN), "OU1", "", "1", iskBytes, ipkBytes, revocationkey, idmx, tr)
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
	os.RemoveAll(filepath.Join(testDir, imsp.IdemixConfigDirUser))
}

func cleanupVerifier() {
	os.RemoveAll(filepath.Join(testDir, imsp.IdemixConfigDirMsp))
}

func writeVerifierToFile(ipkBytes []byte, revpkBytes []byte) error {
	err := os.Mkdir(filepath.Join(testDir, imsp.IdemixConfigDirMsp), os.ModePerm)
	if err != nil {
		return err
	}
	err = os.WriteFile(filepath.Join(testDir, imsp.IdemixConfigDirMsp, imsp.IdemixConfigFileIssuerPublicKey), ipkBytes, 0644)
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(testDir, imsp.IdemixConfigDirMsp, imsp.IdemixConfigFileRevocationPublicKey), revpkBytes, 0644)
}

func writeSignerToFile(signerBytes []byte) error {
	err := os.Mkdir(filepath.Join(testDir, imsp.IdemixConfigDirUser), os.ModePerm)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(testDir, imsp.IdemixConfigDirUser, imsp.IdemixConfigFileSigner), signerBytes, 0644)
}

// setupMSP tests whether we can successfully setup an idemix msp
// with the generated config bytes
func setupMSP(idType imsp.ProviderType) error {
	// setup an idemix msp from the test directory
	var msp imsp.MSP
	var err error
	if idType == imsp.IDEMIX {
		msp, err = imsp.NewIdemixMsp(imsp.MSPv1_1)
	} else {
		msp, err = imsp.NewIdemixMspAries(imsp.MSPv1_1)
	}
	if err != nil {
		return fmt.Errorf("Getting MSP failed: %w", err)
	}

	mspConfig, err := imsp.GetIdemixMspConfigWithType(testDir, "TestName", idType)
	if err != nil {
		return err
	}

	return msp.Setup(mspConfig)
}
