/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package aries

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/IBM/idemix/bccsp/handlers"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
)

// IssuerPublicKey is the issuer public key
type IssuerPublicKey struct {
	PK   *bbs12381g2pub.PublicKey
	PKwG *bbs12381g2pub.PublicKeyWithGenerators
}

// Bytes returns the byte representation of this key
func (i *IssuerPublicKey) Bytes() ([]byte, error) {
	return i.PK.Marshal()
}

// Hash returns the hash representation of this key.
// The output is supposed to be collision-resistant
func (i *IssuerPublicKey) Hash() []byte {
	return i.PK.PointG2.Compressed()
}

// IssuerPublicKey is the issuer secret key
type IssuerSecretKey struct {
	SK   *bbs12381g2pub.PrivateKey
	PK   *bbs12381g2pub.PublicKey
	PKwG *bbs12381g2pub.PublicKeyWithGenerators
}

// Bytes returns the byte representation of this key
func (i *IssuerSecretKey) Bytes() ([]byte, error) {
	return i.SK.Marshal()
}

// Public returns the corresponding public key
func (i *IssuerSecretKey) Public() handlers.IssuerPublicKey {
	return &IssuerPublicKey{
		PK:   i.PK,
		PKwG: i.PKwG,
	}
}

// Issuer is a local interface to decouple from the idemix implementation
type Issuer struct {
}

// NewKey generates a new idemix issuer key w.r.t the passed attribute names.
func (i *Issuer) NewKey(AttributeNames []string) (handlers.IssuerSecretKey, error) {
	seed := make([]byte, 32)

	_, err := rand.Read(seed)
	if err != nil {
		return nil, fmt.Errorf("rand.Read failed [%w]", err)
	}

	PK, SK, err := bbs12381g2pub.GenerateKeyPair(sha256.New, seed)
	if err != nil {
		return nil, fmt.Errorf("GenerateKeyPair failed [%w]", err)
	}

	PKwG, err := PK.ToPublicKeyWithGenerators(len(AttributeNames))
	if err != nil {
		return nil, fmt.Errorf("ToPublicKeyWithGenerators failed [%w]", err)
	}

	return &IssuerSecretKey{
		SK:   SK,
		PK:   PK,
		PKwG: PKwG,
	}, nil
}

// NewPublicKeyFromBytes converts the passed bytes to an Issuer key
// It makes sure that the so obtained  key has the passed attributes, if specified
func (i *Issuer) NewKeyFromBytes(raw []byte, attributes []string) (handlers.IssuerSecretKey, error) {
	SK, err := bbs12381g2pub.UnmarshalPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("UnmarshalPrivateKey failed [%w]", err)
	}

	PK := SK.PublicKey()

	PKwG, err := PK.ToPublicKeyWithGenerators(len(attributes))
	if err != nil {
		return nil, fmt.Errorf("ToPublicKeyWithGenerators failed [%w]", err)
	}

	return &IssuerSecretKey{
		SK:   SK,
		PK:   PK,
		PKwG: PKwG,
	}, nil
}

// NewPublicKeyFromBytes converts the passed bytes to an Issuer public key
// It makes sure that the so obtained public key has the passed attributes, if specified
func (i *Issuer) NewPublicKeyFromBytes(raw []byte, attributes []string) (handlers.IssuerPublicKey, error) {
	PK, err := bbs12381g2pub.UnmarshalPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("UnmarshalPublicKey failed [%w]", err)
	}

	PKwG, err := PK.ToPublicKeyWithGenerators(len(attributes))
	if err != nil {
		return nil, fmt.Errorf("ToPublicKeyWithGenerators failed [%w]", err)
	}

	return &IssuerPublicKey{
		PK:   PK,
		PKwG: PKwG,
	}, nil
}