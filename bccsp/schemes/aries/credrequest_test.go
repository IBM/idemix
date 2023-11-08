/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries_test

import (
	"testing"

	"github.com/IBM/idemix/bccsp/schemes/aries"
	"github.com/IBM/idemix/bccsp/types"
	math "github.com/IBM/mathlib"
	"github.com/ale-linux/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
	"github.com/stretchr/testify/assert"
)

func TestCredRequest(t *testing.T) {
	credProto := &aries.Cred{
		Bls:   bbs12381g2pub.New(),
		Curve: math.Curves[math.BLS12_381_BBS],
	}
	issuerProto := &aries.Issuer{}

	attrs := []string{
		"attr1",
		"attr2",
		"attr3",
		"attr4",
	}

	isk, err := issuerProto.NewKey(attrs)
	assert.NoError(t, err)
	assert.NotNil(t, isk)

	ipk := isk.Public()

	cr := &aries.CredRequest{
		Curve: math.Curves[math.BLS12_381_BBS],
	}

	rand, err := math.Curves[math.BLS12_381_BBS].Rand()
	assert.NoError(t, err)

	userProto := &aries.User{
		Curve: math.Curves[math.BLS12_381_BBS],
		Rng:   rand,
	}

	sk, err := userProto.NewKey()
	assert.NoError(t, err)

	credReq, blinding, err := cr.Blind(sk, ipk, []byte("la la land"))
	assert.NoError(t, err)

	err = cr.BlindVerify(credReq, ipk, []byte("la la land"))
	assert.NoError(t, err)

	idemixAttrs := []types.IdemixAttribute{
		{
			Type:  types.IdemixBytesAttribute,
			Value: []byte("msg1"),
		},
		{
			Type:  types.IdemixIntAttribute,
			Value: 3,
		},
		{
			Type:  types.IdemixBytesAttribute,
			Value: []byte("msg3"),
		},
		{
			Type:  types.IdemixBytesAttribute,
			Value: []byte("msg4"),
		},
	}

	cred, err := credProto.Sign(isk, credReq, idemixAttrs)
	assert.NoError(t, err)

	cred, err = cr.Unblind(cred, blinding)
	assert.NoError(t, err)

	err = credProto.Verify(sk, ipk, cred, idemixAttrs)
	assert.NoError(t, err)

	idemixAttrs = []types.IdemixAttribute{
		{
			Type:  types.IdemixBytesAttribute,
			Value: []byte("msg1"),
		},
		{
			Type:  types.IdemixIntAttribute,
			Value: 3,
		},
		{
			Type:  types.IdemixBytesAttribute,
			Value: []byte("msg3"),
		},
		{
			Type: types.IdemixHiddenAttribute,
		},
	}

	// verify succeeds when supplying hidden attrs
	err = credProto.Verify(sk, ipk, cred, idemixAttrs)
	assert.NoError(t, err)

	idemixAttrs = []types.IdemixAttribute{
		{
			Type:  types.IdemixBytesAttribute,
			Value: []byte("msg2"),
		},
		{
			Type:  types.IdemixIntAttribute,
			Value: 3,
		},
		{
			Type:  types.IdemixBytesAttribute,
			Value: []byte("msg3"),
		},
		{
			Type: types.IdemixHiddenAttribute,
		},
	}

	// verify fails when supplying wrong attrs
	err = credProto.Verify(sk, ipk, cred, idemixAttrs)
	assert.EqualError(t, err, "credential does not contain the correct attribute value at position [0]")

	idemixAttrs = []types.IdemixAttribute{
		{
			Type:  types.IdemixBytesAttribute,
			Value: []byte("msg1"),
		},
		{
			Type:  types.IdemixIntAttribute,
			Value: 2,
		},
		{
			Type:  types.IdemixBytesAttribute,
			Value: []byte("msg3"),
		},
		{
			Type: types.IdemixHiddenAttribute,
		},
	}

	// verify fails when supplying wrong attrs
	err = credProto.Verify(sk, ipk, cred, idemixAttrs)
	assert.EqualError(t, err, "credential does not contain the correct attribute value at position [1]")
}
