/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	im "github.com/IBM/idemix/msp/config"
	m "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"google.golang.org/protobuf/proto"
)

func readFile(file string) ([]byte, error) {
	fileCont, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("could not read file %s: %w", file, err)
	}

	return fileCont, nil
}

const (
	IdemixConfigDirMsp                  = "msp"
	IdemixConfigDirUser                 = "user"
	IdemixConfigFileIssuerPublicKey     = "IssuerPublicKey"
	IdemixConfigFileRevocationPublicKey = "RevocationPublicKey"
	IdemixConfigFileSigner              = "SignerConfig"
)

// GetIdemixMspConfig returns the configuration for the Idemix MSP
func GetIdemixMspConfig(dir string, ID string) (*m.MSPConfig, error) {
	return GetIdemixMspConfigWithType(dir, ID, IDEMIX)
}

// GetIdemixMspConfigWithType returns the configuration for the Idemix MSP of the specified type.
// The curve is taken from the curve_id field of the signer config (written by idemixgen); when
// there is no signer config, or it names no curve, IdemixMSPConfig.CurveId is left empty and Setup
// uses the per-scheme default. Callers of a verification-only MSP on a non-default curve must set
// IdemixMSPConfig.CurveId themselves.
//
// Deprecated: IDEMIX is the only supported type; use GetIdemixMspConfig.
func GetIdemixMspConfigWithType(dir string, ID string, mspType ProviderType) (*m.MSPConfig, error) {
	if mspType != IDEMIX {
		return nil, fmt.Errorf("msp type %d is not supported", mspType)
	}

	ipkBytes, err := readFile(filepath.Join(dir, IdemixConfigDirMsp, IdemixConfigFileIssuerPublicKey))
	if err != nil {
		return nil, fmt.Errorf("failed to read issuer public key file: %w", err)
	}

	revocationPkBytes, err := readFile(filepath.Join(dir, IdemixConfigDirMsp, IdemixConfigFileRevocationPublicKey))
	if err != nil {
		return nil, fmt.Errorf("failed to read revocation public key file: %w", err)
	}

	idemixConfig := &im.IdemixMSPConfig{
		Name:         ID,
		Ipk:          ipkBytes,
		RevocationPk: revocationPkBytes,
	}

	signerBytes, err := readFile(filepath.Join(dir, IdemixConfigDirUser, IdemixConfigFileSigner))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("failed to read signer config file: %w", err)
	}
	if err == nil {
		signerConfig := &im.IdemixMSPSignerConfig{}
		err = proto.Unmarshal(signerBytes, signerConfig)
		if err != nil {
			return nil, err
		}
		idemixConfig.Signer = signerConfig
		idemixConfig.CurveId = signerConfig.CurveId
	}

	if idemixConfig.CurveId != "" {
		if _, _, err := curveAndTranslator(idemixConfig.CurveId); err != nil {
			return nil, fmt.Errorf("invalid curve id: %w", err)
		}
	}

	confBytes, err := proto.Marshal(idemixConfig)
	if err != nil {
		return nil, err
	}

	return &m.MSPConfig{Config: confBytes, Type: int32(mspType)}, nil
}
