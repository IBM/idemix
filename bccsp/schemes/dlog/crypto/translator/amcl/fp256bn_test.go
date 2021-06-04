/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package amcl

import (
	"io/ioutil"
	"testing"

	math "github.com/IBM/mathlib"
	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/assert"
)

func TestFp256bnTranslatorGen(t *testing.T) {
	curve := math.Curves[math.FP256BN_AMCL]
	tr := &Fp256bn{
		C: curve,
	}

	genG1 := curve.GenG1
	ecp := tr.G1ToProto(genG1)
	p, err := tr.G1FromProto(ecp)
	assert.True(t, p.Equals(genG1))
	assert.NoError(t, err)

	genG2 := curve.GenG2
	ecp2 := tr.G2ToProto(genG2)
	p2, err := tr.G2FromProto(ecp2)
	assert.True(t, p2.Equals(genG2))
	assert.NoError(t, err)
}

func TestFp256bnTranslatorRndG1(t *testing.T) {
	curve := math.Curves[math.FP256BN_AMCL]
	tr := &Fp256bn{
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

func TestFp256bnTranslatorRndG2(t *testing.T) {
	curve := math.Curves[math.FP256BN_AMCL]
	tr := &Fp256bn{
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

func TestFp256bnMiraclTranslatorGen(t *testing.T) {
	curve := math.Curves[math.FP256BN_AMCL_MIRACL]
	tr := &Fp256bnMiracl{
		C: curve,
	}

	genG1 := curve.GenG1
	ecp := tr.G1ToProto(genG1)
	p, err := tr.G1FromProto(ecp)
	assert.True(t, p.Equals(genG1))
	assert.NoError(t, err)

	genG2 := curve.GenG2
	ecp2 := tr.G2ToProto(genG2)
	p2, err := tr.G2FromProto(ecp2)
	assert.True(t, p2.Equals(genG2))
	assert.NoError(t, err)
}

func TestFp256bnMiraclTranslatorRndG1(t *testing.T) {
	curve := math.Curves[math.FP256BN_AMCL_MIRACL]
	tr := &Fp256bnMiracl{
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

func TestFp256bnMiraclTranslatorRndG2(t *testing.T) {
	curve := math.Curves[math.FP256BN_AMCL_MIRACL]
	tr := &Fp256bnMiracl{
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

func TestFp256bnTranslatorG2FromFile(t *testing.T) {
	curve := math.Curves[math.FP256BN_AMCL]
	tr := &Fp256bn{
		C: curve,
	}

	wBytes, err := ioutil.ReadFile("./testdata/old/g2.bytes")
	assert.NoError(t, err)
	wProtoBytes, err := ioutil.ReadFile("./testdata/old/g2.proto.bytes")
	assert.NoError(t, err)

	ecp := &ECP2{}
	err = proto.Unmarshal(wProtoBytes, ecp)
	assert.NoError(t, err)

	h1, err := tr.G2FromProto(ecp)
	assert.Equal(t, wBytes, h1.Bytes())
	assert.NoError(t, err)
}
