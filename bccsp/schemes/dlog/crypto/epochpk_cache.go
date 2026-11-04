/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"crypto/ecdsa"

	"github.com/IBM/idemix/bccsp/schemes/dlog/crypto/translator/amcl"
	"github.com/IBM/idemix/bccsp/schemes/internal/epochcache"
	math "github.com/IBM/mathlib"
)

// EpochPKCache remembers verified revocation epoch public keys together with
// their decoded G2 point. Only successes are cached. The zero value is ready to
// use; it must be used with a single translator.
type EpochPKCache struct {
	c epochcache.Cache[*math.G2]
}

// Len returns the number of cached entries.
func (c *EpochPKCache) Len() int {
	if c == nil {
		return 0
	}

	return c.c.Len()
}

// verify behaves like verifyEpochPK. On a hit it returns a copy of the decoded
// point; otherwise it returns the key under which to add the decoded point.
func (c *EpochPKCache) verify(pk *ecdsa.PublicKey, epochPK *amcl.ECP2, epochPkSig []byte, epoch int, alg RevocationAlgorithm) (*math.G2, *epochcache.Key, error) {
	if c == nil {
		return nil, nil, verifyEpochPK(pk, epochPK, epochPkSig, epoch, alg)
	}

	digest, err := epochPKDigest(pk, epochPK, epoch, alg)
	if err != nil {
		return nil, nil, err
	}

	pkBytes, err := pk.Bytes()
	if err != nil {
		// the key cannot be encoded (e.g. not on a NIST curve): do not cache
		return nil, nil, verifyEpochPKDigest(pk, digest, epochPkSig)
	}

	k := epochcache.NewKey(pkBytes, digest[:], epochPkSig)
	if p, hit := c.c.Get(k); hit {
		return p.Copy(), nil, nil
	}

	if err := verifyEpochPKDigest(pk, digest, epochPkSig); err != nil {
		return nil, nil, err
	}

	return nil, &k, nil
}

// add stores a copy of epochPK under k.
func (c *EpochPKCache) add(k *epochcache.Key, epochPK *math.G2) {
	if c == nil || k == nil || epochPK == nil {
		return
	}
	c.c.Add(*k, epochPK.Copy())
}
