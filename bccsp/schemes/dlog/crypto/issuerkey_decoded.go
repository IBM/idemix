/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"errors"
	"fmt"
	"slices"

	math "github.com/IBM/mathlib"
)

// DecodedIssuerPublicKey is an immutable issuer public key with its group
// elements already decoded; it is independent of the protobuf it came from.
type DecodedIssuerPublicKey struct {
	curveID   math.CurveID
	attrNames []string
	ipkHash   []byte
	hSk       *math.G1
	hRand     *math.G1
	hAttrs    []*math.G1
	w         *math.G2
}

// CheckAndDecode is like Check and also returns the decoded key.
func (IPk *IssuerPublicKey) CheckAndDecode(curve *math.Curve, t Translator) (*DecodedIssuerPublicKey, error) {
	return IPk.checkAndDecode(curve, t)
}

// checkCurve returns an error if d was not decoded on the passed curve.
func (d *DecodedIssuerPublicKey) checkCurve(curve *math.Curve) error {
	if curve == nil {
		return errors.New("nil curve")
	}
	if d.curveID != curve.ID() {
		return fmt.Errorf("issuer public key was decoded on curve [%d], not on curve [%d]", d.curveID, curve.ID())
	}

	return nil
}

// Hash returns a copy of the hash of the issuer public key.
func (d *DecodedIssuerPublicKey) Hash() []byte {
	return slices.Clone(d.ipkHash)
}

// AttributeNames returns a copy of the attribute names of the issuer public key.
func (d *DecodedIssuerPublicKey) AttributeNames() []string {
	return slices.Clone(d.attrNames)
}

// issuerBases holds copies of the issuer key elements.
type issuerBases struct {
	W      *math.G2
	HRand  *math.G1
	HSk    *math.G1
	HAttrs []*math.G1
}

// issuerKeyView abstracts over the protobuf and decoded issuer keys.
type issuerKeyView interface {
	attributeNames() []string
	baseCount() int
	hash() []byte
	// bases returns fresh copies of HRand, HSk and optionally W, HAttrs.
	bases(t Translator, withW, withHAttrs bool) (*issuerBases, error)
	// g2W returns a fresh copy of W.
	g2W(t Translator) (*math.G2, error)
}

type protoIssuerKey struct {
	ipk *IssuerPublicKey
}

func (p protoIssuerKey) attributeNames() []string { return p.ipk.GetAttributeNames() }

func (p protoIssuerKey) baseCount() int { return len(p.ipk.GetHAttrs()) }

func (p protoIssuerKey) hash() []byte { return p.ipk.GetHash() }

func (p protoIssuerKey) bases(t Translator, withW, withHAttrs bool) (*issuerBases, error) {
	b := &issuerBases{}

	var err error
	if withW {
		if b.W, err = t.G2FromProto(p.ipk.GetW()); err != nil {
			return nil, err
		}
	}
	if b.HRand, err = t.G1FromProto(p.ipk.GetHRand()); err != nil {
		return nil, err
	}
	if b.HSk, err = t.G1FromProto(p.ipk.GetHSk()); err != nil {
		return nil, err
	}
	if withHAttrs {
		b.HAttrs = make([]*math.G1, len(p.ipk.GetHAttrs()))
		for i, h := range p.ipk.GetHAttrs() {
			if b.HAttrs[i], err = t.G1FromProto(h); err != nil {
				return nil, err
			}
		}
	}

	return b, nil
}

func (p protoIssuerKey) g2W(t Translator) (*math.G2, error) { return t.G2FromProto(p.ipk.GetW()) }

func (d *DecodedIssuerPublicKey) g2W(Translator) (*math.G2, error) { return d.w.Copy(), nil }

func (d *DecodedIssuerPublicKey) attributeNames() []string { return d.attrNames }

func (d *DecodedIssuerPublicKey) baseCount() int { return len(d.hAttrs) }

func (d *DecodedIssuerPublicKey) hash() []byte { return d.ipkHash }

func (d *DecodedIssuerPublicKey) bases(_ Translator, withW, withHAttrs bool) (*issuerBases, error) {
	b := &issuerBases{
		HRand: d.hRand.Copy(),
		HSk:   d.hSk.Copy(),
	}
	if withW {
		b.W = d.w.Copy()
	}
	if withHAttrs {
		b.HAttrs = make([]*math.G1, len(d.hAttrs))
		for i, h := range d.hAttrs {
			b.HAttrs[i] = h.Copy()
		}
	}

	return b, nil
}
