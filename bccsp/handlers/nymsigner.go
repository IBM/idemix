/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package handlers

import (
	"errors"
	"fmt"

	"github.com/IBM/idemix/bccsp/types"
)

type NymSigner struct {
	NymSignatureScheme          types.NymSignatureScheme
	SmartcardNymSignatureScheme types.SmartcardNymSignatureScheme
}

func (s *NymSigner) Sign(k types.Key, digest []byte, opts types.SignerOpts) ([]byte, error) {
	signerOpts, ok := opts.(*types.IdemixNymSignerOpts)
	if !ok || signerOpts == nil {
		return nil, errors.New("invalid options, expected *IdemixNymSignerOpts")
	}

	// Issuer public key
	if signerOpts.IssuerPK == nil {
		return nil, errors.New("invalid options, missing issuer public key")
	}
	ipk, ok := signerOpts.IssuerPK.(*issuerPublicKey)
	if !ok || !ipk.valid() {
		return nil, errors.New("invalid issuer public key, expected *issuerPublicKey")
	}

	// handle the smartcard case
	if signerOpts.IsSmartcard {
		if s.SmartcardNymSignatureScheme == nil {
			return nil, errors.New("smartcard mode is unsupported")
		}

		if signerOpts.Smartcard == nil {
			return nil, errors.New("no s/w smartcard supplied in opts")
		}

		sigma, nym, rNym, err := s.SmartcardNymSignatureScheme.Sign(signerOpts.Smartcard, ipk.pk, digest)
		if err != nil {
			return nil, err
		}

		signerOpts.NymG1 = nym
		signerOpts.RNym = rNym

		return sigma, nil
	}

	userSecretKey, ok := k.(*UserSecretKey)
	if !ok || !userSecretKey.valid() {
		return nil, errors.New("invalid key, expected *userSecretKey")
	}

	// Nym
	if signerOpts.Nym == nil {
		return nil, errors.New("invalid options, missing nym key")
	}
	nymSk, ok := signerOpts.Nym.(*NymSecretKey)
	if !ok || !nymSk.valid() {
		return nil, errors.New("invalid nym key, expected *nymSecretKey")
	}

	if s.NymSignatureScheme == nil {
		return nil, errors.New("nym signature scheme is unsupported")
	}

	sigma, err := s.NymSignatureScheme.Sign(
		userSecretKey.Sk,
		nymSk.Pk, nymSk.Sk,
		ipk.pk,
		digest)
	if err != nil {
		return nil, err
	}

	return sigma, nil
}

type NymVerifier struct {
	NymSignatureScheme          types.NymSignatureScheme
	SmartcardNymSignatureScheme types.SmartcardNymSignatureScheme
}

func (v *NymVerifier) Verify(k types.Key, signature, digest []byte, opts types.SignerOpts) (valid bool, err error) {
	// the underlying schemes operate on attacker-controlled signatures and keys;
	// a malformed input must surface as an error, never as a panic.
	defer func() {
		if r := recover(); r != nil {
			valid = false
			err = fmt.Errorf("failed verifying nym signature: %v", r)
		}
	}()

	nymPublicKey, ok := k.(*nymPublicKey)
	if !ok || !nymPublicKey.valid() {
		return false, errors.New("invalid key, expected *nymPublicKey")
	}

	signerOpts, ok := opts.(*types.IdemixNymSignerOpts)
	if !ok || signerOpts == nil {
		return false, errors.New("invalid options, expected *IdemixNymSignerOpts")
	}

	if signerOpts.IssuerPK == nil {
		return false, errors.New("invalid options, missing issuer public key")
	}
	ipk, ok := signerOpts.IssuerPK.(*issuerPublicKey)
	if !ok || !ipk.valid() {
		return false, errors.New("invalid issuer public key, expected *issuerPublicKey")
	}

	if len(signature) == 0 {
		return false, errors.New("invalid signature, it must not be empty")
	}

	// handle the smartcard case
	if signerOpts.IsSmartcard {
		if v.SmartcardNymSignatureScheme == nil {
			return false, errors.New("smartcard mode is unsupported")
		}
		if signerOpts.NymEid == nil {
			return false, errors.New("nym eid missing")
		}

		err = v.SmartcardNymSignatureScheme.Verify(
			ipk.pk,
			signerOpts.NymEid,
			signature,
			digest)
		if err != nil {
			return false, err
		}

		return true, nil
	}

	if v.NymSignatureScheme == nil {
		return false, errors.New("nym signature scheme is unsupported")
	}
	if signerOpts.SKIndex < 0 {
		return false, fmt.Errorf("invalid options, SKIndex must not be negative, got %d", signerOpts.SKIndex)
	}

	err = v.NymSignatureScheme.Verify(
		ipk.pk,
		nymPublicKey.pk,
		signature,
		digest,
		signerOpts.SKIndex)
	if err != nil {
		return false, err
	}

	return true, nil
}
