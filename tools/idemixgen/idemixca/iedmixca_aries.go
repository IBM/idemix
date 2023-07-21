/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemixca

import (
	"crypto/ecdsa"

	imsp "github.com/IBM/idemix"
	bccsp "github.com/IBM/idemix/bccsp/schemes"
	"github.com/IBM/idemix/bccsp/schemes/aries"
	im "github.com/IBM/idemix/idemixmsp"
	math "github.com/IBM/mathlib"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
	"github.com/pkg/errors"
)

// GenerateIssuerKey invokes Idemix library to generate an issuer (CA) signing key pair.
// Currently four attributes are supported by the issuer:
// AttributeNameOU is the organization unit name
// AttributeNameRole is the role (member or admin) name
// AttributeNameEnrollmentId is the enrollment id
// AttributeNameRevocationHandle contains the revocation handle, which can be used to revoke this user
// Generated keys are serialized to bytes.
func GenerateIssuerKeyAries(curve *math.Curve) ([]byte, []byte, error) {
	issuer := &aries.Issuer{}

	AttributeNames := []string{imsp.AttributeNameOU, imsp.AttributeNameRole, imsp.AttributeNameEnrollmentId, imsp.AttributeNameRevocationHandle}

	key, err := issuer.NewKey(AttributeNames)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "cannot generate CA key")
	}

	iskSerialised, err := key.(*aries.IssuerSecretKey).Bytes()
	if err != nil {
		return nil, nil, errors.WithMessage(err, "isk byte conversion error")
	}

	ipkSerialized, err := key.Public().Bytes()
	if err != nil {
		return nil, nil, errors.WithMessage(err, "ipk byte conversion error")
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
		return nil, errors.Errorf("the OU attribute value is empty")
	}

	if enrollmentId == "" {
		return nil, errors.Errorf("the enrollment id value is empty")
	}

	rng, err := curve.Rand()
	if err != nil {
		return nil, errors.WithMessage(err, "Error getting PRNG")
	}

	blindSigner := &aries.CredRequest{
		Curve: curve,
	}

	credentialSigner := &aries.Cred{
		Curve: curve,
		Bls:   bbs12381g2pub.New(),
	}

	revocationAuthority := &aries.RevocationAuthority{
		Curve: curve,
		Rng:   rng,
	}

	issuer := &aries.Issuer{}
	AttributeNames := []string{imsp.AttributeNameOU, imsp.AttributeNameRole, imsp.AttributeNameEnrollmentId, imsp.AttributeNameRevocationHandle}
	isk, err := issuer.NewKeyFromBytes(iskBytes, AttributeNames)
	if err != nil {
		return nil, errors.WithMessage(err, "issuer.NewKeyFromBytes failed")
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
		return nil, errors.WithMessage(err, "blindSigner.Blind failed")
	}

	err = blindSigner.BlindVerify(cr, isk.Public(), ni)
	if err != nil {
		return nil, errors.WithMessage(err, "blindSigner.BlindVerify failed")
	}

	cred, err := credentialSigner.Sign(isk, cr, attrs)
	if err != nil {
		return nil, errors.WithMessage(err, "credentialSigner.Sign failed")
	}

	cred, err = blindSigner.Unblind(cred, blinding)
	if err != nil {
		return nil, errors.WithMessage(err, "blindSigner.Unblind failed")
	}

	err = credentialSigner.Verify(sk, isk.Public(), cred, attrs)
	if err != nil {
		return nil, errors.WithMessage(err, "credentialSigner.Verify failed")
	}

	cri, err := revocationAuthority.Sign(revKey, nil, 0, bccsp.AlgNoRevocation)
	if err != nil {
		return nil, errors.WithMessage(err, "revocationAuthority.Sign failed")
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
