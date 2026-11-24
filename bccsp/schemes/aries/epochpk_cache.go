/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	"crypto/ecdsa"

	"github.com/IBM/idemix/bccsp/schemes/internal/epochcache"
	"github.com/IBM/idemix/bccsp/types"
)

// epochPKCache remembers successful epoch PK signature verifications.
// Only successes are cached; the zero value is ready to use.
type epochPKCache struct {
	c epochcache.Cache[struct{}]
}

// verify behaves like verifyEpochPK, using the cache.
func (c *epochPKCache) verify(pk *ecdsa.PublicKey, epochPK, epochPkSig []byte, epoch int, alg types.RevocationAlgorithm) error {
	digest, err := epochPKDigest(pk, epochPK, epoch, alg)
	if err != nil {
		return err
	}

	pkBytes, err := pk.Bytes()
	if err != nil {
		// the key cannot be encoded (e.g. not on a NIST curve): do not cache
		return verifyEpochPKDigest(pk, digest, epochPkSig)
	}

	k := epochcache.NewKey(pkBytes, digest[:], epochPkSig)
	if _, hit := c.c.Get(k); hit {
		return nil
	}

	if err := verifyEpochPKDigest(pk, digest, epochPkSig); err != nil {
		return err
	}
	c.c.Add(k, struct{}{})

	return nil
}

// len returns the number of cached entries.
func (c *epochPKCache) len() int {
	return c.c.Len()
}
