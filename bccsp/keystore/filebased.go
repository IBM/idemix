/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keystore

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"os"
	"path"

	bccsp "github.com/IBM/idemix/bccsp/schemes"
	idemix "github.com/IBM/idemix/bccsp/schemes/dlog/crypto"
	"github.com/IBM/idemix/bccsp/schemes/dlog/crypto/translator/amcl"
	"github.com/IBM/idemix/bccsp/schemes/dlog/handlers"
	math "github.com/IBM/mathlib"
	"github.com/pkg/errors"
)

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

func NewFileBased(path string, curve *math.Curve, translator idemix.Translator) (*fileBased, error) {
	f, err := os.Stat(path)

	if !os.IsNotExist(err) && f.Mode().IsRegular() {
		return nil, errors.Errorf("invalid path [%s]: it's a file", path)
	}

	if os.IsNotExist(err) {
		err = os.MkdirAll(path, 0770)
		if err != nil {
			return nil, errors.Wrapf(err, "could not create path [%s]", path)
		}
	}

	return &fileBased{
		path:       path,
		translator: translator,
		curve:      curve,
	}, nil
}

// fileBased is a read-only KeyStore that neither loads nor stores keys.
type fileBased struct {
	path       string
	translator idemix.Translator
	curve      *math.Curve
}

// ReadOnly returns true if this KeyStore is read only, false otherwise.
// If ReadOnly is true then StoreKey will fail.
func (ks *fileBased) ReadOnly() bool {
	return false
}

// GetKey returns a key object whose SKI is the one passed.
func (ks *fileBased) GetKey(ski []byte) (bccsp.Key, error) {
	fname := path.Join(ks.path, hex.EncodeToString(ski))
	bytes, err := ioutil.ReadFile(fname)
	if err != nil {
		return nil, errors.Wrapf(err, "could not read file [%s]", fname)
	}

	entry := &entry{}
	err = json.Unmarshal(bytes, entry)
	if err != nil {
		return nil, errors.Wrapf(err, "could not unmarshal bytes for file [%s]", fname)
	}

	switch {
	case entry.NymSecretKey != nil:
		pk, err := ks.translator.G1FromProto(entry.NymSecretKey.Pk)
		if err != nil {
			return nil, err
		}

		return &handlers.NymSecretKey{
			Exportable: entry.NymSecretKey.Exportable,
			Sk:         ks.curve.NewZrFromBytes(entry.NymSecretKey.Sk),
			Ski:        entry.NymSecretKey.Ski,
			Pk:         pk,
			Translator: ks.translator,
		}, nil
	case entry.UserSecretKey != nil:
		return &handlers.UserSecretKey{
			Exportable: entry.UserSecretKey.Exportable,
			Sk:         ks.curve.NewZrFromBytes(entry.UserSecretKey.Sk),
		}, nil
	default:
		return nil, errors.Errorf("key not found for file [%s]", fname)
	}
}

// StoreKey stores the key k in this KeyStore.
// If this KeyStore is read only then the method will fail.
func (ks *fileBased) StoreKey(k bccsp.Key) error {
	entry := &entry{}

	switch key := k.(type) {
	case *handlers.NymSecretKey:
		entry.NymSecretKey = &NymSecretKey{
			Ski:        key.Ski,
			Sk:         key.Sk.Bytes(),
			Pk:         ks.translator.G1ToProto(key.Pk),
			Exportable: key.Exportable,
		}
	case *handlers.UserSecretKey:
		entry.UserSecretKey = &UserSecretKey{
			Sk:         key.Sk.Bytes(),
			Exportable: key.Exportable,
		}
	default:
		return errors.Errorf("unknown type [%T] for the supplied key", key)
	}

	bytes, err := json.Marshal(entry)
	if err != nil {
		return errors.Wrapf(err, "marshalling key [%s] failed", string(k.SKI()))
	}

	fname := path.Join(ks.path, hex.EncodeToString(k.SKI()))
	err = ioutil.WriteFile(fname, bytes, 0660)
	if err != nil {
		return errors.Wrapf(err, "writing [%s] failed", fname)
	}

	return nil
}
