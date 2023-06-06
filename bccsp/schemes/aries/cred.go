/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package aries

import (
	"fmt"

	"github.com/IBM/idemix/bccsp/handlers"
	bccsp "github.com/IBM/idemix/bccsp/schemes"
	math "github.com/IBM/mathlib"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
	"github.com/pkg/errors"
)

type Cred struct {
	Bls *bbs12381g2pub.BBSG2Pub
}

// Sign issues a new credential, which is the last step of the interactive issuance protocol
// All attribute values are added by the issuer at this step and then signed together with a commitment to
// the user's secret key from a credential request
func (c *Cred) Sign(key handlers.IssuerSecretKey, credentialRequest []byte, attributes []bccsp.IdemixAttribute) ([]byte, error) {
	isk, ok := key.(*IssuerSecretKey)
	if !ok {
		return nil, errors.Errorf("invalid issuer public key, expected *IssuerPublicKey, got [%T]", key)
	}

	blindedMsg, err := bbs12381g2pub.ParseBlindedMessages(credentialRequest)
	if err != nil {
		return nil, fmt.Errorf("ParseBlindedMessages failed [%w]", err)
	}

	msgs := make([][]byte, len(attributes)+1)
	for i, msg := range attributes {
		if msg.Type != bccsp.IdemixBytesAttribute {
			return nil, errors.Errorf("invalid attribute type [%T]", msg.Type)
		}

		msgs[i+1] = msg.Value.([]byte)
	}

	sig, err := c.Bls.BlindSign(msgs, blindedMsg.C, isk.SK.FR.Bytes())
	if err != nil {
		return nil, fmt.Errorf("ParseBlindedMessages failed [%w]", err)
	}

	return sig, nil
}

// Verify cryptographically verifies the credential by verifying the signature
// on the attribute values and user's secret key
func (c *Cred) Verify(sk *math.Zr, key handlers.IssuerPublicKey, credential []byte, attributes []bccsp.IdemixAttribute) error {
	ipk, ok := key.(*IssuerPublicKey)
	if !ok {
		return errors.Errorf("invalid issuer public key, expected *IssuerPublicKey, got [%T]", ipk)
	}

	sigma, err := bbs12381g2pub.ParseSignature(credential)
	if err != nil {
		return fmt.Errorf("ParseSignature failed [%w]", err)
	}

	msgsZr := make([]*bbs12381g2pub.SignatureMessage, len(attributes)+1)
	msgsZr[UserSecretKeyIndex] = &bbs12381g2pub.SignatureMessage{
		FR:  sk,
		Idx: UserSecretKeyIndex,
	}

	for i, msg := range attributes {
		if msg.Type != bccsp.IdemixBytesAttribute {
			return errors.Errorf("invalid attribute type [%T]", msg.Type)
		}

		msgsZr[i+1] = &bbs12381g2pub.SignatureMessage{
			FR:  bbs12381g2pub.FrFromOKM(msg.Value.([]byte)),
			Idx: i + 1,
		}
	}

	return sigma.Verify(msgsZr, ipk.PKwG)
}
