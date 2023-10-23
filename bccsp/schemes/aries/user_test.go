/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries_test

import (
	"testing"

	"github.com/IBM/idemix/bccsp/schemes/aries"
	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/assert"
)

func TestUser(t *testing.T) {
	issuer := &aries.Issuer{math.Curves[math.BLS12_381_BBS]}

	attrs := []string{
		"attr1",
		"attr2",
		"attr3",
		"attr4",
	}

	isk, err := issuer.NewKey(attrs)
	assert.NoError(t, err)
	assert.NotNil(t, isk)

	ipk := isk.Public()

	rand, err := math.Curves[math.BLS12_381_BBS].Rand()
	assert.NoError(t, err)

	user := &aries.User{
		Curve: math.Curves[math.BLS12_381_BBS],
		Rng:   rand,
	}

	sk, err := user.NewKey()
	assert.NoError(t, err)
	assert.NotNil(t, sk)

	sk1, err := user.NewKeyFromBytes(sk.Bytes())
	assert.NoError(t, err)
	assert.NotNil(t, sk1)
	assert.Equal(t, sk, sk1)

	nym, r, err := user.MakeNym(sk, ipk)
	assert.NoError(t, err)

	nymBytes := nym.Bytes()
	rBytes := r.Bytes()
	bothBytes := []byte{}
	bothBytes = append(bothBytes, rBytes...)
	bothBytes = append(bothBytes, nymBytes...)

	nym1, err := user.NewPublicNymFromBytes(nymBytes)
	assert.NoError(t, err)
	assert.NotNil(t, nym)
	assert.True(t, nym.Equals(nym1))

	nym1, r1, err := user.NewNymFromBytes(bothBytes)
	assert.NoError(t, err)
	assert.NotNil(t, nym)
	assert.True(t, nym.Equals(nym1))
	assert.NotNil(t, r1)
	assert.Equal(t, r, r1)

	nymBytes[len(nymBytes)-1] = 0
	_, err = user.NewPublicNymFromBytes(nymBytes)
	assert.EqualError(t, err, "failure [set bytes failed [point is not on curve]]")

	bothBytes[len(bothBytes)-1] = 0
	_, _, err = user.NewNymFromBytes(bothBytes)
	assert.EqualError(t, err, "failure [set bytes failed [point is not on curve]]")

	_, err = user.NewKeyFromBytes([]byte("yän-dər"))
	assert.EqualError(t, err, "invalid length, expected [32], got [9]")

	_, err = user.NewPublicNymFromBytes([]byte("yän-dər"))
	assert.EqualError(t, err, "invalid length, expected [96], got [9]")

	_, _, err = user.NewNymFromBytes([]byte("yän-dər"))
	assert.EqualError(t, err, "invalid length, expected [128], got [9]")
}
