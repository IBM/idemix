/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kvs

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
)

type FileBasedKVS struct {
	path string
}

func NewFileBased(path string) (*FileBasedKVS, error) {
	f, err := os.Stat(path)

	if !os.IsNotExist(err) && f.Mode().IsRegular() {
		return nil, fmt.Errorf("invalid path [%s]: it's a file", path)
	}

	if os.IsNotExist(err) {
		err = os.MkdirAll(path, 0750)
		if err != nil {
			return nil, fmt.Errorf("could not create path [%s]: [%w]", path, err)
		}
	}

	return &FileBasedKVS{
		path: path,
	}, nil
}

func (f *FileBasedKVS) Put(id string, entry any) error {
	bytes, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshalling key [%s] failed: [%w]", id, err)
	}

	fname := path.Join(f.path, id)
	err = os.WriteFile(fname, bytes, 0660)
	if err != nil {
		return fmt.Errorf("writing [%s] failed: [%w]", fname, err)
	}

	return nil
}

func (f *FileBasedKVS) Get(id string, entry any) error {
	fname := path.Join(f.path, id)
	bytes, err := os.ReadFile(fname)
	if err != nil {
		return fmt.Errorf("could not read file [%s]: [%w]", fname, err)
	}

	err = json.Unmarshal(bytes, entry)
	if err != nil {
		return fmt.Errorf("could not unmarshal bytes for file [%s]: [%w]", fname, err)
	}

	return nil
}
