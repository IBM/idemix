/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kvs

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path"

	"github.com/pkg/errors"
)

type FileBasedKVS struct {
	path string
}

func NewFileBased(path string) (*FileBasedKVS, error) {
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

	return &FileBasedKVS{
		path: path,
	}, nil
}

func (f *FileBasedKVS) Put(id string, entry interface{}) error {
	bytes, err := json.Marshal(entry)
	if err != nil {
		return errors.Wrapf(err, "marshalling key [%s] failed", id)
	}

	fname := path.Join(f.path, id)
	err = ioutil.WriteFile(fname, bytes, 0660)
	if err != nil {
		return errors.Wrapf(err, "writing [%s] failed", fname)
	}

	return nil
}

func (f *FileBasedKVS) Get(id string, entry interface{}) error {
	fname := path.Join(f.path, id)
	bytes, err := ioutil.ReadFile(fname)
	if err != nil {
		return errors.Wrapf(err, "could not read file [%s]", fname)
	}

	err = json.Unmarshal(bytes, entry)
	if err != nil {
		return errors.Wrapf(err, "could not unmarshal bytes for file [%s]", fname)
	}

	return nil
}
