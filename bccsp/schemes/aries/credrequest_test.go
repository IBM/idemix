/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries_test

import (
	"testing"

	"github.com/IBM/idemix/bbs"
	"github.com/IBM/idemix/bccsp/schemes/aries"
	"github.com/IBM/idemix/bccsp/types"
	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCredRequest(t *testing.T) {
	curve := math.Curves[math.BLS12_381_BBS]

	credProto := &aries.Cred{
		BBS:   bbs.New(curve),
		Curve: curve,
	}
	issuerProto := &aries.Issuer{Curve: curve}

	attrs := []string{
		"attr1",
		"attr2",
		"attr3",
		"attr4",
	}

	isk, err := issuerProto.NewKey(attrs)
	require.NoError(t, err)

	ipk := isk.Public()

	cr := &aries.CredRequest{Curve: curve}

	rand, err := curve.Rand()
	require.NoError(t, err)

	userProto := &aries.User{
		Curve: curve,
		Rng:   rand,
	}

	sk, err := userProto.NewKey()
	require.NoError(t, err)

	credReq, blinding, err := cr.Blind(sk, ipk, []byte("la la land"))
	require.NoError(t, err)

	err = cr.BlindVerify(credReq, ipk, []byte("la la land"))
	require.NoError(t, err)

	allAttrs := []types.IdemixAttribute{
		{Type: types.IdemixBytesAttribute, Value: []byte("msg1")},
		{Type: types.IdemixIntAttribute, Value: 3},
		{Type: types.IdemixBytesAttribute, Value: []byte("msg3")},
		{Type: types.IdemixBytesAttribute, Value: []byte("msg4")},
	}

	cred, err := credProto.Sign(isk, credReq, allAttrs)
	require.NoError(t, err)

	cred, err = cr.Unblind(cred, blinding)
	require.NoError(t, err)

	t.Run("full_lifecycle", func(t *testing.T) {
		err := credProto.Verify(sk, ipk, cred, allAttrs)
		assert.NoError(t, err)
	})

	t.Run("verify_with_hidden_last_attr", func(t *testing.T) {
		attrs := []types.IdemixAttribute{
			{Type: types.IdemixBytesAttribute, Value: []byte("msg1")},
			{Type: types.IdemixIntAttribute, Value: 3},
			{Type: types.IdemixBytesAttribute, Value: []byte("msg3")},
			{Type: types.IdemixHiddenAttribute},
		}
		err := credProto.Verify(sk, ipk, cred, attrs)
		assert.NoError(t, err)
	})

	t.Run("verify_with_hidden_first_and_last_attr", func(t *testing.T) {
		attrs := []types.IdemixAttribute{
			{Type: types.IdemixHiddenAttribute},
			{Type: types.IdemixIntAttribute, Value: 3},
			{Type: types.IdemixBytesAttribute, Value: []byte("msg3")},
			{Type: types.IdemixHiddenAttribute},
		}
		err := credProto.Verify(sk, ipk, cred, attrs)
		assert.NoError(t, err)
	})

	t.Run("wrong_attr_at_position_0", func(t *testing.T) {
		attrs := []types.IdemixAttribute{
			{Type: types.IdemixBytesAttribute, Value: []byte("msg2")},
			{Type: types.IdemixIntAttribute, Value: 3},
			{Type: types.IdemixBytesAttribute, Value: []byte("msg3")},
			{Type: types.IdemixHiddenAttribute},
		}
		err := credProto.Verify(sk, ipk, cred, attrs)
		assert.EqualError(t, err, "credential does not contain the correct attribute value at position [0]")
	})

	t.Run("wrong_attr_at_position_1", func(t *testing.T) {
		attrs := []types.IdemixAttribute{
			{Type: types.IdemixBytesAttribute, Value: []byte("msg1")},
			{Type: types.IdemixIntAttribute, Value: 2},
			{Type: types.IdemixBytesAttribute, Value: []byte("msg3")},
			{Type: types.IdemixHiddenAttribute},
		}
		err := credProto.Verify(sk, ipk, cred, attrs)
		assert.EqualError(t, err, "credential does not contain the correct attribute value at position [1]")
	})
}
