/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keystore

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/IBM/idemix/bccsp/handlers"
	idemix "github.com/IBM/idemix/bccsp/schemes/dlog/crypto"
	"github.com/IBM/idemix/bccsp/schemes/dlog/crypto/translator/amcl"
	bccsp "github.com/IBM/idemix/bccsp/types"
	math "github.com/IBM/mathlib"
)

type KVS interface {
	Put(id string, state any) error
	Get(id string, state any) error
}

type NymSecretKey struct {
	Ski        []byte
	Sk         []byte
	Pk         *amcl.ECP
	Exportable bool
}

type UserSecretKey struct {
	Sk         []byte
	Exportable bool
}

type entry struct {
	NymSecretKey  *NymSecretKey  `json:",omitempty"`
	UserSecretKey *UserSecretKey `json:",omitempty"`
}

// KVSStore is a read-only KeyStore that neither loads nor stores keys.
type KVSStore struct {
	KVS
	Translator idemix.Translator
	Curve      *math.Curve
}

// NewKVSStore returns a KVSStore backed by the passed KVS. It fails if the
// translator is bound to a curve other than the passed one.
func NewKVSStore(kvs KVS, curve *math.Curve, translator idemix.Translator) (*KVSStore, error) {
	if err := idemix.CheckTranslatorCurve(curve, translator); err != nil {
		return nil, fmt.Errorf("invalid curve/translator pair: %w", err)
	}

	return &KVSStore{KVS: kvs, Translator: translator, Curve: curve}, nil
}

// check validates that, when both are set, the translator and the curve of
// the store agree.
func (ks *KVSStore) check() error {
	if ks.Translator == nil || ks.Curve == nil {
		return nil
	}

	if err := idemix.CheckTranslatorCurve(ks.Curve, ks.Translator); err != nil {
		return fmt.Errorf("invalid curve/translator pair: %w", err)
	}

	return nil
}

// ReadOnly returns true if this KeyStore is read only, false otherwise.
// If ReadOnly is true then StoreKey will fail.
func (ks *KVSStore) ReadOnly() bool {
	return false
}

// GetKey returns a key object whose SKI is the one passed.
func (ks *KVSStore) GetKey(ski []byte) (_ bccsp.Key, err error) {
	if err := ks.check(); err != nil {
		return nil, err
	}

	id := hex.EncodeToString(ski)

	// a corrupted entry must not take down the caller
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("could not decode key [%s]: %v", id, r)
		}
	}()

	entry := &entry{}
	err = ks.Get(id, entry)
	if err != nil {
		return nil, fmt.Errorf("could not get key [%s] from kvs: %w", id, err)
	}

	switch {
	case entry.NymSecretKey != nil:
		if ks.Translator == nil || ks.Curve == nil {
			return nil, fmt.Errorf("could not decode key [%s]: store has no translator or curve", id)
		}

		if len(entry.NymSecretKey.Sk) != ks.Curve.ScalarByteSize {
			return nil, fmt.Errorf("could not decode key [%s]: invalid secret key length %d, expected %d", id, len(entry.NymSecretKey.Sk), ks.Curve.ScalarByteSize)
		}
		if entry.NymSecretKey.Pk == nil {
			return nil, fmt.Errorf("could not decode key [%s]: missing public key", id)
		}

		pk, err := ks.Translator.G1FromProto(entry.NymSecretKey.Pk)
		if err != nil {
			return nil, err
		}

		nymSk, err := ks.Curve.NewZrFromBytesCanonical(entry.NymSecretKey.Sk)
		if err != nil {
			return nil, fmt.Errorf("could not decode key [%s]: %w", id, err)
		}

		key := &handlers.NymSecretKey{
			Exportable: entry.NymSecretKey.Exportable,
			Sk:         nymSk,
			Ski:        entry.NymSecretKey.Ski,
			Pk:         pk,
			Translator: ks.Translator,
		}

		// nym keys are stored under the SKI of their public part (see StoreKey)
		pub, err := key.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("could not decode key [%s]: %w", id, err)
		}
		if !bytes.Equal(pub.SKI(), ski) {
			return nil, fmt.Errorf("could not decode key [%s]: SKI mismatch", id)
		}

		return key, nil
	case entry.UserSecretKey != nil:
		if ks.Curve == nil {
			return nil, fmt.Errorf("could not decode key [%s]: store has no curve", id)
		}

		if len(entry.UserSecretKey.Sk) != ks.Curve.ScalarByteSize {
			return nil, fmt.Errorf("could not decode key [%s]: invalid secret key length %d, expected %d", id, len(entry.UserSecretKey.Sk), ks.Curve.ScalarByteSize)
		}

		userSk, err := ks.Curve.NewZrFromBytesCanonical(entry.UserSecretKey.Sk)
		if err != nil {
			return nil, fmt.Errorf("could not decode key [%s]: %w", id, err)
		}

		key := &handlers.UserSecretKey{
			Exportable: entry.UserSecretKey.Exportable,
			Sk:         userSk,
		}
		if !bytes.Equal(key.SKI(), ski) {
			return nil, fmt.Errorf("could not decode key [%s]: SKI mismatch", id)
		}

		return key, nil
	default:
		return nil, fmt.Errorf("key not found for [%s]", id)
	}
}

// StoreKey stores the key k in this KeyStore.
// If this KeyStore is read only then the method will fail.
func (ks *KVSStore) StoreKey(k bccsp.Key) error {
	if err := ks.check(); err != nil {
		return err
	}

	entry := &entry{}
	var id string

	switch key := k.(type) {
	case *handlers.NymSecretKey:
		if key == nil || key.Sk == nil || key.Pk == nil {
			return errors.New("invalid nym secret key: missing secret or public part")
		}
		if ks.Translator == nil {
			return errors.New("could not store key: store has no translator")
		}
		entry.NymSecretKey = &NymSecretKey{
			Ski:        key.Ski,
			Sk:         key.Sk.Bytes(),
			Pk:         ks.Translator.G1ToProto(key.Pk),
			Exportable: key.Exportable,
		}

		pk, err := k.PublicKey()
		if err != nil {
			return fmt.Errorf("could not get public version for key [%s]", k.SKI())
		}

		id = hex.EncodeToString(pk.SKI())
	case *handlers.UserSecretKey:
		if key == nil || key.Sk == nil {
			return errors.New("invalid user secret key: missing secret")
		}
		entry.UserSecretKey = &UserSecretKey{
			Sk:         key.Sk.Bytes(),
			Exportable: key.Exportable,
		}
		id = hex.EncodeToString(k.SKI())
	default:
		return fmt.Errorf("unknown type [%T] for the supplied key", key)
	}

	return ks.Put(id, entry)
}
