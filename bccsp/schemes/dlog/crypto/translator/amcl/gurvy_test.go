/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package amcl

import (
	"testing"

	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/assert"
)

func TestGurvyTranslatorGen(t *testing.T) {
	curve := math.Curves[math.BN256]
	tr := &Gurvy{
		C: curve,
	}

	genG1 := curve.GenG1
	ecp := tr.G1ToProto(genG1)
	p, err := tr.G1FromProto(ecp)
	assert.NoError(t, err)
	assert.True(t, p.Equals(genG1))

	genG2 := curve.GenG2
	ecp2 := tr.G2ToProto(genG2)
	p2, err := tr.G2FromProto(ecp2)
	assert.True(t, p2.Equals(genG2))
	assert.NoError(t, err)
}

func TestGurvyTranslatorRndG1(t *testing.T) {
	curve := math.Curves[math.BN256]
	tr := &Gurvy{
		C: curve,
	}

	rnd, err := curve.Rand()
	assert.NoError(t, err)

	g := curve.GenG1
	r := curve.NewRandomZr(rnd)
	h := g.Mul(r)

	ecp := tr.G1ToProto(h)
	assert.NotNil(t, ecp)

	h1, err := tr.G1FromProto(ecp)
	assert.True(t, h.Equals(h1))
	assert.NoError(t, err)
}

func TestGurvyTranslatorRndG2(t *testing.T) {
	curve := math.Curves[math.BN256]
	tr := &Gurvy{
		C: curve,
	}

	rnd, err := curve.Rand()
	assert.NoError(t, err)

	g := curve.GenG2
	r := curve.NewRandomZr(rnd)
	h := g.Mul(r)

	ecp := tr.G2ToProto(h)
	assert.NotNil(t, ecp)

	h1, err := tr.G2FromProto(ecp)
	assert.True(t, h.Equals(h1))
	assert.NoError(t, err)
}
