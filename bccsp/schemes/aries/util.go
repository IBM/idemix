/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	"github.com/IBM/idemix/bccsp/types"
	math "github.com/IBM/mathlib"
	"github.com/ale-linux/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
)

func attributesToSignatureMessage(attributes []types.IdemixAttribute, curve *math.Curve, skPos int) []*bbs12381g2pub.SignatureMessage {
	attributes = append(append(append([]types.IdemixAttribute{}, attributes[:skPos]...), types.IdemixAttribute{Type: types.IdemixHiddenAttribute}), attributes[skPos:]...)
	var msgsZr = make([]*bbs12381g2pub.SignatureMessage, 0, len(attributes))

	for i, msg := range attributes {
		switch msg.Type {
		case types.IdemixBytesAttribute:
			msgsZr = append(msgsZr, &bbs12381g2pub.SignatureMessage{
				FR:  bbs12381g2pub.FrFromOKM(msg.Value.([]byte), curve),
				Idx: i,
			})
		case types.IdemixIntAttribute:
			msgsZr = append(msgsZr, &bbs12381g2pub.SignatureMessage{
				FR:  curve.NewZrFromInt(int64(msg.Value.(int))),
				Idx: i,
			})
		case types.IdemixHiddenAttribute:
			continue
		}
	}

	return msgsZr
}

func revealedAttributesIndexNoSk(attributes []types.IdemixAttribute) []int {
	revealed := make([]int, 0, len(attributes))

	for i, msg := range attributes {
		if msg.Type != types.IdemixHiddenAttribute {
			revealed = append(revealed, i)
		}
	}

	return revealed
}

func revealedAttributesIndex(attributes []types.IdemixAttribute) []int {
	revealed := make([]int, 0, len(attributes))

	for i, msg := range attributes {
		if msg.Type != types.IdemixHiddenAttribute {
			revealed = append(revealed, i+1)
		}
	}

	return revealed
}

func (c *Credential) toSignatureMessage(sk *math.Zr, curve *math.Curve) []*bbs12381g2pub.SignatureMessage {
	msgsZr := make([]*bbs12381g2pub.SignatureMessage, 0, len(c.Attrs)+1)

	j := 0
	for i := 0; i < len(c.Attrs)+1; i++ {
		msg := &bbs12381g2pub.SignatureMessage{}
		msgsZr = append(msgsZr, msg)

		if i == int(c.SkPos) {
			msg.FR = sk
		} else {
			msg.FR = curve.NewZrFromBytes(c.Attrs[j])
			j++
		}

		msg.Idx = i
	}

	return msgsZr
}
