/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

// idemixgen is a command line tool that generates the CA's keys and
// generates MSP configs for siging and for verification
// This tool can be used to setup the peers and CA to support
// the Identity Mixer MSP

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	math "github.com/IBM/mathlib"
	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	"gopkg.in/alecthomas/kingpin.v2"

	imsp "github.com/IBM/idemix"
	idemix "github.com/IBM/idemix/bccsp/schemes/dlog/crypto"
	"github.com/IBM/idemix/bccsp/schemes/dlog/crypto/translator/amcl"
	"github.com/IBM/idemix/tools/idemixgen/idemixca"
	"github.com/IBM/idemix/tools/idemixgen/metadata"
)

const (
	IdemixDirIssuer             = "ca"
	IdemixConfigIssuerSecretKey = "IssuerSecretKey"
	IdemixConfigRevocationKey   = "RevocationKey"

	FP256BN_AMCL = "FP256BN_AMCL"
	BN254 = "BN254"
	FP256BN_AMCL_MIRACL = "FP256BN_AMCL_MIRACL"
)

// command line flags
var (
	app = kingpin.New("idemixgen", "Utility for generating key material to be used with the Identity Mixer MSP in Hyperledger Fabric")

	outputDir = app.Flag("output", "The output directory in which to place artifacts").Default("idemix-config").String()
	curveID = app.Flag("curve", "The curve to use to generate the crypto material").Short('c').Default(FP256BN_AMCL).Enum(FP256BN_AMCL, BN254, FP256BN_AMCL_MIRACL)

	genIssuerKey            = app.Command("ca-keygen", "Generate CA key material")
	genSignerConfig         = app.Command("signerconfig", "Generate a default signer for this Idemix MSP")
	genCAInput              = genSignerConfig.Flag("ca-input", "The folder where CA's secrets are stored").String()
	genCredOU               = genSignerConfig.Flag("org-unit", "The Organizational Unit of the default signer").Short('u').String()
	genCredIsAdmin          = genSignerConfig.Flag("admin", "Make the default signer admin").Short('a').Bool()
	genCredEnrollmentId     = genSignerConfig.Flag("enrollmentId", "The enrollment id of the default signer").Short('e').String()
	genCredRevocationHandle = genSignerConfig.Flag("revocationHandle", "The handle used to revoke this signer").Short('r').Int()

	version = app.Command("version", "Show version information")
)

func main() {
	app.HelpFlag.Short('h')

	command := kingpin.MustParse(app.Parse(os.Args[1:]))

	var curve *math.Curve
	switch *curveID {
	case FP256BN_AMCL:
        curve = math.Curves[math.FP256BN_AMCL]
	case BN254:
		curve = math.Curves[math.BN254]
	case FP256BN_AMCL_MIRACL:
		curve = math.Curves[math.FP256BN_AMCL_MIRACL]
	default:
		handleError(fmt.Errorf("invalid curve [%s]", *curveID))
	}

	tr := &amcl.Fp256bn{
		C: curve,
	}

	idmx := &idemix.Idemix{
		Curve: curve,
	}

	switch  command {

	case genIssuerKey.FullCommand():
		isk, ipk, err := idemixca.GenerateIssuerKey(idmx, tr)
		handleError(err)

		revocationKey, err := idmx.GenerateLongTermRevocationKey()
		handleError(err)
		encodedRevocationSK, err := x509.MarshalECPrivateKey(revocationKey)
		handleError(err)
		pemEncodedRevocationSK := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedRevocationSK})
		handleError(err)
		encodedRevocationPK, err := x509.MarshalPKIXPublicKey(revocationKey.Public())
		handleError(err)
		pemEncodedRevocationPK := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encodedRevocationPK})

		// Prevent overwriting the existing key
		path := filepath.Join(*outputDir, IdemixDirIssuer)
		checkDirectoryNotExists(path, fmt.Sprintf("Directory %s already exists", path))

		path = filepath.Join(*outputDir, imsp.IdemixConfigDirMsp)
		checkDirectoryNotExists(path, fmt.Sprintf("Directory %s already exists", path))

		// write private and public keys to the file
		handleError(os.MkdirAll(filepath.Join(*outputDir, IdemixDirIssuer), 0770))
		handleError(os.MkdirAll(filepath.Join(*outputDir, imsp.IdemixConfigDirMsp), 0770))
		writeFile(filepath.Join(*outputDir, IdemixDirIssuer, IdemixConfigIssuerSecretKey), isk)
		writeFile(filepath.Join(*outputDir, IdemixDirIssuer, IdemixConfigRevocationKey), pemEncodedRevocationSK)
		writeFile(filepath.Join(*outputDir, IdemixDirIssuer, imsp.IdemixConfigFileIssuerPublicKey), ipk)
		writeFile(filepath.Join(*outputDir, imsp.IdemixConfigDirMsp, imsp.IdemixConfigFileRevocationPublicKey), pemEncodedRevocationPK)
		writeFile(filepath.Join(*outputDir, imsp.IdemixConfigDirMsp, imsp.IdemixConfigFileIssuerPublicKey), ipk)

	case genSignerConfig.FullCommand():
		roleMask := 0
		if *genCredIsAdmin {
			roleMask = imsp.GetRoleMaskFromIdemixRole(imsp.ADMIN)
		} else {
			roleMask = imsp.GetRoleMaskFromIdemixRole(imsp.MEMBER)
		}
		if *genCAInput == "" {
			genCAInput = outputDir
		}
		ipk, ipkRaw := readIssuerKey()
		rsk := readRevocationKey()
		rpk := readRevocationPublicKey()

		config, err := idemixca.GenerateSignerConfig(
			roleMask,
			*genCredOU,
			*genCredEnrollmentId,
			*genCredRevocationHandle,
			ipk, rsk, idmx, tr,
		)
		handleError(err)

		path := filepath.Join(*outputDir, imsp.IdemixConfigDirUser)
		checkDirectoryNotExists(path, fmt.Sprintf("This MSP config already contains a directory \"%s\"", path))

		// Write config to file
		handleError(os.MkdirAll(filepath.Join(*outputDir, imsp.IdemixConfigDirUser), 0770))
		writeFile(filepath.Join(*outputDir, imsp.IdemixConfigDirUser, imsp.IdemixConfigFileSigner), config)

		// Write CA public info in case genCAInput != outputDir
		if *genCAInput != *outputDir {
			handleError(os.MkdirAll(filepath.Join(*outputDir, imsp.IdemixConfigDirMsp), 0770))
			writeFile(filepath.Join(*outputDir, imsp.IdemixConfigDirMsp, imsp.IdemixConfigFileRevocationPublicKey), rpk)
			writeFile(filepath.Join(*outputDir, imsp.IdemixConfigDirMsp, imsp.IdemixConfigFileIssuerPublicKey), ipkRaw)
		}

	case version.FullCommand():
		printVersion()

	}
}

func printVersion() {
	fmt.Println(metadata.GetVersionInfo())
}

// writeFile writes bytes to a file and panics in case of an error
func writeFile(path string, contents []byte) {
	handleError(ioutil.WriteFile(path, contents, 0640))
}

// readIssuerKey reads the issuer key from the current directory
func readIssuerKey() (*idemix.IssuerKey, []byte) {
	path := filepath.Join(*genCAInput, IdemixDirIssuer, IdemixConfigIssuerSecretKey)
	isk, err := ioutil.ReadFile(path)
	if err != nil {
		handleError(errors.Wrapf(err, "failed to open issuer secret key file: %s", path))
	}
	path = filepath.Join(*genCAInput, IdemixDirIssuer, imsp.IdemixConfigFileIssuerPublicKey)
	ipkBytes, err := ioutil.ReadFile(path)
	if err != nil {
		handleError(errors.Wrapf(err, "failed to open issuer public key file: %s", path))
	}
	ipk := &idemix.IssuerPublicKey{}
	handleError(proto.Unmarshal(ipkBytes, ipk))
	key := &idemix.IssuerKey{Isk: isk, Ipk: ipk}

	return key, ipkBytes
}

func readRevocationKey() *ecdsa.PrivateKey {
	path := filepath.Join(*genCAInput, IdemixDirIssuer, IdemixConfigRevocationKey)
	keyBytes, err := ioutil.ReadFile(path)
	if err != nil {
		handleError(errors.Wrapf(err, "failed to open revocation secret key file: %s", path))
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		handleError(errors.Errorf("failed to decode ECDSA private key"))
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	handleError(err)

	return key
}

func readRevocationPublicKey() []byte {
	path := filepath.Join(*genCAInput, imsp.IdemixConfigDirMsp, imsp.IdemixConfigFileRevocationPublicKey)
	keyBytes, err := ioutil.ReadFile(path)
	if err != nil {
		handleError(errors.Wrapf(err, "failed to open revocation secret key file: %s", path))
	}

	return keyBytes
}

// checkDirectoryNotExists checks whether a directory with the given path already exists and exits if this is the case
func checkDirectoryNotExists(path string, errorMessage string) {
	_, err := os.Stat(path)
	if err == nil {
		handleError(errors.New(errorMessage))
	}
}

func handleError(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
