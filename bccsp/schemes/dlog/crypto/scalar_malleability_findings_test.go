/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"math/big"
	"testing"

	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	opts "github.com/IBM/idemix/bccsp/types"
)

// malleatedScalars returns non-canonical encodings of the scalar encoded by b
// that the reducing decoder NewZrFromBytes maps to the same scalar:
//   - "zero-padded": 0x00 || b (ScalarByteSize+1 bytes);
//   - "plus-order": b + q, if it still fits in ScalarByteSize bytes (true for
//     the BN254 and BLS12 curves, whose group order is below 2^255).
func malleatedScalars(t *testing.T, curve *math.Curve, b []byte) map[string][]byte {
	t.Helper()
	res := map[string][]byte{"zero-padded": append([]byte{0}, b...)}
	v := new(big.Int).Add(new(big.Int).SetBytes(b), curve.GroupOrder.BigInt())
	if len(v.Bytes()) <= curve.ScalarByteSize {
		res["plus-order"] = v.FillBytes(make([]byte, curve.ScalarByteSize))
	}
	for name, m := range res {
		// these encodings were accepted before the canonical decoding fix
		require.True(t, curve.NewZrFromBytes(m).Equals(curve.NewZrFromBytes(b)), name)
	}

	return res
}

// FINDING-F7 (scalar malleability): Signature.Ver decoded the challenge, the
// responses and the nonce with the reducing NewZrFromBytes, so an honest
// signature could be re-encoded into distinct byte strings (e.g. s+q or a
// zero-padded s) that still verified. Every serialized scalar must now be
// canonical.
func TestFindingSignatureVerScalarMalleability(t *testing.T) {
	fields := map[string]func(*Signature) *[]byte{
		"ProofC":       func(s *Signature) *[]byte { return &s.ProofC },
		"ProofSSk":     func(s *Signature) *[]byte { return &s.ProofSSk },
		"ProofSE":      func(s *Signature) *[]byte { return &s.ProofSE },
		"ProofSR2":     func(s *Signature) *[]byte { return &s.ProofSR2 },
		"ProofSR3":     func(s *Signature) *[]byte { return &s.ProofSR3 },
		"ProofSSPrime": func(s *Signature) *[]byte { return &s.ProofSSPrime },
		"ProofSRNym":   func(s *Signature) *[]byte { return &s.ProofSRNym },
		"Nonce":        func(s *Signature) *[]byte { return &s.Nonce },
		"ProofSAttrs0": func(s *Signature) *[]byte { return &s.ProofSAttrs[0] },
		"ProofSEid":    func(s *Signature) *[]byte { return &s.EidNym.ProofSEid },
		"ProofSRh":     func(s *Signature) *[]byte { return &s.RhNym.ProofSRh },
	}
	for _, e := range envs {
		f := newFindingFx(t, e)
		honest := f.sign(t, allHidden, opts.EidNymRhNym)
		vals := f.values(allHidden)
		require.NoError(t, f.ver(t, honest, allHidden, vals, fxEidIndex, opts.ExpectEidNymRhNym))

		for field, get := range fields {
			for name, m := range malleatedScalars(t, f.curve, *get(honest)) {
				sig := proto.Clone(honest).(*Signature)
				*get(sig) = m
				require.Error(t, f.ver(t, sig, allHidden, vals, fxEidIndex, opts.ExpectEidNymRhNym),
					"curve %d: %s %s encoding must be rejected", f.curve.ID(), field, name)
			}
		}
	}
}

// FINDING-F7: same as above for the pseudonym signature (NymSignature.Ver).
func TestFindingNymSignatureVerScalarMalleability(t *testing.T) {
	fields := map[string]func(*NymSignature) *[]byte{
		"ProofC":     func(s *NymSignature) *[]byte { return &s.ProofC },
		"ProofSSk":   func(s *NymSignature) *[]byte { return &s.ProofSSk },
		"ProofSRNym": func(s *NymSignature) *[]byte { return &s.ProofSRNym },
		"Nonce":      func(s *NymSignature) *[]byte { return &s.Nonce },
	}
	for _, e := range envs {
		f := newFindingFx(t, e)
		rng, err := f.curve.Rand()
		require.NoError(t, err)
		honest, err := f.idmx.NewNymSignature(f.sk, f.nym, f.rnym, f.key.Ipk, fxMsg, rng, f.tr)
		require.NoError(t, err)
		require.NoError(t, honest.Ver(f.nym, f.key.Ipk, fxMsg, f.curve, f.tr))

		for field, get := range fields {
			for name, m := range malleatedScalars(t, f.curve, *get(honest)) {
				sig := proto.Clone(honest).(*NymSignature)
				*get(sig) = m
				require.Error(t, sig.Ver(f.nym, f.key.Ipk, fxMsg, f.curve, f.tr),
					"curve %d: %s %s encoding must be rejected", f.curve.ID(), field, name)
			}
		}
	}
}

// FINDING-F7: the credential (E, S, attributes), the credential request proof
// and the issuer public key proof must also reject non-canonical scalars.
func TestFindingCredentialAndKeyProofsScalarMalleability(t *testing.T) {
	for _, e := range envs {
		f := newFindingFx(t, e)
		require.NoError(t, f.cred.Ver(f.sk, f.key.Ipk, f.curve, f.tr))
		credFields := map[string]func(*Credential) *[]byte{
			"E":     func(c *Credential) *[]byte { return &c.E },
			"S":     func(c *Credential) *[]byte { return &c.S },
			"Attr0": func(c *Credential) *[]byte { return &c.Attrs[0] },
		}
		for field, get := range credFields {
			for name, m := range malleatedScalars(t, f.curve, *get(f.cred)) {
				cred := proto.Clone(f.cred).(*Credential)
				*get(cred) = m
				require.Error(t, cred.Ver(f.sk, f.key.Ipk, f.curve, f.tr), "curve %d: credential %s %s", f.curve.ID(), field, name)
			}
		}

		rng, err := f.curve.Rand()
		require.NoError(t, err)
		nonce := f.curve.NewRandomZr(rng).Bytes()
		req, err := f.idmx.NewCredRequest(f.sk, nonce, f.key.Ipk, rng, f.tr)
		require.NoError(t, err)
		require.NoError(t, req.Check(f.key.Ipk, f.curve, f.tr))
		reqFields := map[string]func(*CredRequest) *[]byte{
			"ProofC": func(c *CredRequest) *[]byte { return &c.ProofC },
			"ProofS": func(c *CredRequest) *[]byte { return &c.ProofS },
		}
		for field, get := range reqFields {
			for name, m := range malleatedScalars(t, f.curve, *get(req)) {
				r := proto.Clone(req).(*CredRequest)
				*get(r) = m
				require.Error(t, r.Check(f.key.Ipk, f.curve, f.tr), "curve %d: cred request %s %s", f.curve.ID(), field, name)
			}
		}

		require.NoError(t, f.key.Ipk.Check(f.curve, f.tr))
		ipkFields := map[string]func(*IssuerPublicKey) *[]byte{
			"ProofC": func(c *IssuerPublicKey) *[]byte { return &c.ProofC },
			"ProofS": func(c *IssuerPublicKey) *[]byte { return &c.ProofS },
		}
		for field, get := range ipkFields {
			for name, m := range malleatedScalars(t, f.curve, *get(f.key.Ipk)) {
				ipk := proto.Clone(f.key.Ipk).(*IssuerPublicKey)
				*get(ipk) = m
				require.Error(t, ipk.Check(f.curve, f.tr), "curve %d: issuer public key %s %s", f.curve.ID(), field, name)
			}
		}
	}
}

// FINDING-F7: MakeNymFromBytes rejects a non-canonical nym randomness.
func TestFindingMakeNymFromBytesNonCanonicalRandomness(t *testing.T) {
	for _, e := range envs {
		f := newFindingFx(t, e)
		pk := f.tr.G1ToProto(f.nym)
		raw := append(append(make([]byte, f.curve.ScalarByteSize), pk.X...), pk.Y...)
		for i := range f.curve.ScalarByteSize {
			raw[i] = 0xff
		}
		_, _, err := f.idmx.MakeNymFromBytes(raw)
		require.Error(t, err, "curve %d", f.curve.ID())

		copy(raw, f.rnym.Bytes())
		_, rnym, err := f.idmx.MakeNymFromBytes(raw)
		require.NoError(t, err, "curve %d", f.curve.ID())
		require.True(t, rnym.Equals(f.rnym))
	}
}
