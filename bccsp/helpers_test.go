/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package idemix_test

import (
	"github.com/IBM/idemix/bccsp/keystore"
	bccsp "github.com/IBM/idemix/bccsp/types"
)

func NewDummyKeyStore() bccsp.KeyStore {
	return &keystore.Dummy{}
}
