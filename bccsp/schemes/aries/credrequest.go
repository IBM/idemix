/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package aries

import (
	"fmt"

	"github.com/IBM/idemix/bccsp/handlers"
	math "github.com/IBM/mathlib"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
	"github.com/pkg/errors"
)

type CredRequest struct {
	Curve *math.Curve
}

// Sign creates a new Credential Request, the first message of the interactive credential issuance protocol
// (from user to issuer)
func (c *CredRequest) Blind(sk *math.Zr, key handlers.IssuerPublicKey, nonce []byte) ([]byte, []byte, error) {
	ipk, ok := key.(*IssuerPublicKey)
	if !ok {
		return nil, nil, errors.Errorf("invalid issuer public key, expected *IssuerPublicKey, got [%T]", ipk)
	}

	zrs := make([]*math.Zr, ipk.N+1)
	zrs[UserSecretKeyIndex] = sk

	blindedMsg, err := bbs12381g2pub.BlindMessagesZr(zrs, ipk.PK, 1, nonce)
	if err != nil {
		return nil, nil, fmt.Errorf("BlindMessagesZr failed [%w]", err)
	}

	return blindedMsg.Bytes(), blindedMsg.S.Bytes(), nil
}

// Verify verifies the credential request
func (c *CredRequest) BlindVerify(credRequest []byte, key handlers.IssuerPublicKey, nonce []byte) error {
	ipk, ok := key.(*IssuerPublicKey)
	if !ok {
		return errors.Errorf("invalid issuer public key, expected *IssuerPublicKey, got [%T]", ipk)
	}

	bitmap := make([]bool, ipk.N+1)
	bitmap[UserSecretKeyIndex] = true

	blindedMsg, err := bbs12381g2pub.ParseBlindedMessages(credRequest)
	if err != nil {
		return fmt.Errorf("ParseBlindedMessages failed [%w]", err)
	}

	return bbs12381g2pub.VerifyBlinding(bitmap, blindedMsg.C, blindedMsg.PoK, ipk.PK, nonce)
}

// Unblind takes a blinded signature and a blinding and produces a standard signature
func (c *CredRequest) Unblind(signature, blinding []byte) ([]byte, error) {
	bls := bbs12381g2pub.New()

	S := c.Curve.NewZrFromBytes(blinding)

	return bls.UnblindSign(signature, S)
}
