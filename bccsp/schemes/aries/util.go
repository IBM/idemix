/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	"fmt"

	"github.com/IBM/idemix/bbs"
	"github.com/IBM/idemix/bccsp/types"
	math "github.com/IBM/mathlib"
)

func attributesToSignatureMessage(attributes []types.IdemixAttribute, curve *math.Curve, skPos int) []*bbs.SignatureMessage {
	withSk := make([]types.IdemixAttribute, len(attributes)+1)
	copy(withSk, attributes[:skPos])
	withSk[skPos] = types.IdemixAttribute{Type: types.IdemixHiddenAttribute}
	copy(withSk[skPos+1:], attributes[skPos:])
	attributes = withSk

	var msgsZr = make([]*bbs.SignatureMessage, 0, len(attributes))

	for i, msg := range attributes {
		switch msg.Type {
		case types.IdemixBytesAttribute:
			msgsZr = append(msgsZr, &bbs.SignatureMessage{
				FR:  bbs.FrFromOKM(msg.Value.([]byte), curve),
				Idx: i,
			})
		case types.IdemixIntAttribute:
			msgsZr = append(msgsZr, &bbs.SignatureMessage{
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

// revealedAttributesIndex returns the indices, in the BBS+ message vector (which
// includes the user secret key at position skPos), of the disclosed attributes.
func revealedAttributesIndex(attributes []types.IdemixAttribute, skPos int) []int {
	revealed := make([]int, 0, len(attributes))

	for i, msg := range attributes {
		if msg.Type != types.IdemixHiddenAttribute {
			if i < skPos {
				revealed = append(revealed, i)
			} else {
				revealed = append(revealed, i+1)
			}
		}
	}

	return revealed
}

func (c *Credential) toSignatureMessage(sk *math.Zr, curve *math.Curve) ([]*bbs.SignatureMessage, error) {
	msgsZr := make([]*bbs.SignatureMessage, 0, len(c.Attrs)+1)

	j := 0
	for i := range len(c.Attrs) + 1 {
		msg := &bbs.SignatureMessage{}
		msgsZr = append(msgsZr, msg)

		if i == int(c.SkPos) {
			msg.FR = sk
		} else {
			fr, err := curve.NewZrFromBytesCanonical(c.Attrs[j])
			if err != nil {
				return nil, fmt.Errorf("invalid credential attribute [%d]: %w", j, err)
			}
			msg.FR = fr
			j++
		}

		msg.Idx = i
	}

	return msgsZr, nil
}

// hiddenPosition returns the position of message idx among the hidden messages,
// i.e. idx minus the number of revealed indices smaller than idx.
func hiddenPosition(idx int, revealed []int) int {
	pos := idx
	for _, r := range revealed {
		if r < idx {
			pos--
		}
	}

	return pos
}
