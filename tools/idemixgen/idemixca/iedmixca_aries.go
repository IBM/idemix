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

	"github.com/IBM/idemix/bbs"
	"github.com/IBM/idemix/bccsp/schemes/aries"
	bccsp "github.com/IBM/idemix/bccsp/types"
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
func GenerateIssuerKeyAries(curve *math.Curve) ([]byte, []byte, error) {
	issuer := &aries.Issuer{Curve: curve}

	AttributeNames := []string{imsp.AttributeNameOU, imsp.AttributeNameRole, imsp.AttributeNameEnrollmentId, imsp.AttributeNameRevocationHandle}

	key, err := issuer.NewKey(AttributeNames)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot generate CA key: %w", err)
	}

	iskSerialised, err := key.(*aries.IssuerSecretKey).Bytes()
	if err != nil {
		return nil, nil, fmt.Errorf("isk byte conversion error: %w", err)
	}

	ipkSerialized, err := key.Public().Bytes()
	if err != nil {
		return nil, nil, fmt.Errorf("ipk byte conversion error: %w", err)
	}

	return iskSerialised, ipkSerialized, nil
}

// GenerateSignerConfig creates a new signer config.
// It generates a fresh user secret and issues a credential
// with four attributes (described above) using the CA's key pair.
func GenerateSignerConfigAries(
	roleMask int,
	ouString string,
	enrollmentId, revocationHandle string,
	iskBytes, ipkBytes []byte,
	revKey *ecdsa.PrivateKey,
	curve *math.Curve,
) ([]byte, error) {
	if ouString == "" {
		return nil, errors.New("the OU attribute value is empty")
	}

	if enrollmentId == "" {
		return nil, errors.New("the enrollment id value is empty")
	}

	rng, err := curve.Rand()
	if err != nil {
		return nil, fmt.Errorf("error getting PRNG: %w", err)
	}

	blindSigner := &aries.CredRequest{
		Curve: curve,
	}

	credentialSigner := &aries.Cred{
		Curve: curve,
		BBS:   bbs.New(curve),
	}

	revocationAuthority := &aries.RevocationAuthority{
		Curve: curve,
		Rng:   rng,
	}

	issuer := &aries.Issuer{Curve: curve}
	AttributeNames := []string{imsp.AttributeNameOU, imsp.AttributeNameRole, imsp.AttributeNameEnrollmentId, imsp.AttributeNameRevocationHandle}
	isk, err := issuer.NewKeyFromBytes(iskBytes, AttributeNames)
	if err != nil {
		return nil, fmt.Errorf("issuer.NewKeyFromBytes failed: %w", err)
	}

	attrs := make([]bccsp.IdemixAttribute, 4)
	attrs[imsp.AttributeIndexOU] = bccsp.IdemixAttribute{
		Type:  bccsp.IdemixBytesAttribute,
		Value: []byte(ouString),
	}
	attrs[imsp.AttributeIndexRole] = bccsp.IdemixAttribute{
		Type:  bccsp.IdemixIntAttribute,
		Value: roleMask,
	}
	attrs[imsp.AttributeIndexEnrollmentId] = bccsp.IdemixAttribute{
		Type:  bccsp.IdemixBytesAttribute,
		Value: []byte(enrollmentId),
	}
	attrs[imsp.AttributeIndexRevocationHandle] = bccsp.IdemixAttribute{
		Type:  bccsp.IdemixBytesAttribute,
		Value: []byte(revocationHandle),
	}

	sk := curve.NewRandomZr(rng)
	ni := curve.NewRandomZr(rng).Bytes()

	cr, blinding, err := blindSigner.Blind(sk, isk.Public(), ni)
	if err != nil {
		return nil, fmt.Errorf("blindSigner.Blind failed: %w", err)
	}

	err = blindSigner.BlindVerify(cr, isk.Public(), ni)
	if err != nil {
		return nil, fmt.Errorf("blindSigner.BlindVerify failed: %w", err)
	}

	cred, err := credentialSigner.Sign(isk, cr, attrs)
	if err != nil {
		return nil, fmt.Errorf("credentialSigner.Sign failed: %w", err)
	}

	cred, err = blindSigner.Unblind(cred, blinding)
	if err != nil {
		return nil, fmt.Errorf("blindSigner.Unblind failed: %w", err)
	}

	err = credentialSigner.Verify(sk, isk.Public(), cred, attrs)
	if err != nil {
		return nil, fmt.Errorf("credentialSigner.Verify failed: %w", err)
	}

	cri, err := revocationAuthority.Sign(revKey, nil, 0, bccsp.AlgNoRevocation)
	if err != nil {
		return nil, fmt.Errorf("revocationAuthority.Sign failed: %w", err)
	}

	if roleMask < stdmath.MinInt32 || roleMask > stdmath.MaxInt32 {
		return nil, fmt.Errorf("roleMask out of range for int32: %d", roleMask)
	}
	signer := &im.IdemixMSPSignerConfig{
		Cred:                            cred,
		Sk:                              sk.Bytes(),
		OrganizationalUnitIdentifier:    ouString,
		Role:                            int32(roleMask),
		EnrollmentId:                    enrollmentId,
		RevocationHandle:                revocationHandle,
		CredentialRevocationInformation: cri,
	}

	return proto.Marshal(signer)
}
