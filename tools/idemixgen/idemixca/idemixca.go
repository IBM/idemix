/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemixca

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	stdmath "math"

	idemix "github.com/IBM/idemix/bccsp/schemes/dlog/crypto"
	imsp "github.com/IBM/idemix/msp"
	im "github.com/IBM/idemix/msp/config"
	math "github.com/IBM/mathlib"
	"google.golang.org/protobuf/proto"
)

// GenerateIssuerKey invokes Idemix library to generate an issuer (CA) signing key pair.
// Currently four attributes are supported by the issuer:
// AttributeNameOU is the organization unit name
// AttributeNameRole is the role (member or admin) name
// AttributeNameEnrollmentId is the enrollment id
// AttributeNameRevocationHandle contains the revocation handle, which can be used to revoke this user
// Generated keys are serialized to bytes.
func GenerateIssuerKey(idmx *idemix.Idemix, tr idemix.Translator) ([]byte, []byte, error) {
	rng, err := idmx.Curve.Rand()
	if err != nil {
		return nil, nil, err
	}
	AttributeNames := []string{imsp.AttributeNameOU, imsp.AttributeNameRole, imsp.AttributeNameEnrollmentId, imsp.AttributeNameRevocationHandle}
	key, err := idmx.NewIssuerKey(AttributeNames, rng, tr)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot generate CA key: %w", err)
	}
	ipkSerialized, err := proto.Marshal(key.Ipk)

	return key.Isk, ipkSerialized, err
}

// GenerateSignerConfig creates a new signer config.
// It generates a fresh user secret and issues a credential
// with four attributes (described above) using the CA's key pair.
func GenerateSignerConfig(
	roleMask int,
	ouString string,
	enrollmentId,
	revocationHandle string,
	iskBytes, ipkBytes []byte,
	revKey *ecdsa.PrivateKey,
	idmx *idemix.Idemix,
	tr idemix.Translator,
) ([]byte, error) {
	attrs := make([]*math.Zr, 4)

	if ouString == "" {
		return nil, errors.New("the OU attribute value is empty")
	}

	if enrollmentId == "" {
		return nil, errors.New("the enrollment id value is empty")
	}

	attrs[imsp.AttributeIndexOU] = idmx.Curve.HashToZr([]byte(ouString))
	attrs[imsp.AttributeIndexRole] = idmx.Curve.NewZrFromInt(int64(roleMask))
	attrs[imsp.AttributeIndexEnrollmentId] = idmx.Curve.HashToZr([]byte(enrollmentId))
	attrs[imsp.AttributeIndexRevocationHandle] = idmx.Curve.HashToZr([]byte(revocationHandle))

	ipk := &idemix.IssuerPublicKey{}
	err := proto.Unmarshal(ipkBytes, ipk)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling ipk: %w", err)
	}
	key := &idemix.IssuerKey{Isk: iskBytes, Ipk: ipk}

	rng, err := idmx.Curve.Rand()
	if err != nil {
		return nil, fmt.Errorf("error getting PRNG: %w", err)
	}
	sk := idmx.Curve.NewRandomZr(rng)
	ni := idmx.Curve.NewRandomZr(rng).Bytes()
	msg, err := idmx.NewCredRequest(sk, ni, key.Ipk, rng, tr)
	if err != nil {
		return nil, fmt.Errorf("failed to generate a credential request: %w", err)
	}
	cred, err := idmx.NewCredential(key, msg, attrs, rng, tr)
	if err != nil {
		return nil, fmt.Errorf("failed to generate a credential: %w", err)
	}

	credBytes, err := proto.Marshal(cred)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential: %w", err)
	}

	// NOTE currently, idemixca creates CRI's with "ALG_NO_REVOCATION"
	cri, err := idmx.CreateCRI(revKey, []*math.Zr{idmx.Curve.HashToZr([]byte(revocationHandle))}, 0, idemix.ALG_NO_REVOCATION, rng, tr)
	if err != nil {
		return nil, err
	}
	criBytes, err := proto.Marshal(cri)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CRI: %w", err)
	}

	if roleMask < stdmath.MinInt32 || roleMask > stdmath.MaxInt32 {
		return nil, fmt.Errorf("roleMask out of range for int32: %d", roleMask)
	}
	signer := &im.IdemixMSPSignerConfig{
		Cred:                            credBytes,
		Sk:                              sk.Bytes(),
		OrganizationalUnitIdentifier:    ouString,
		Role:                            int32(roleMask),
		EnrollmentId:                    enrollmentId,
		RevocationHandle:                revocationHandle,
		CredentialRevocationInformation: criBytes,
	}

	return proto.Marshal(signer)
}
