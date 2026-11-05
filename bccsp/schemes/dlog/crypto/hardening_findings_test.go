/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	opts "github.com/IBM/idemix/bccsp/types"
)

// FINDING-DLOG-12: NymEID/NymRH audits decode the nym with curve.NewG1FromBytes, which
// bypasses the translator checks (and, for FP256BN, maps garbage to the identity). Auditing
// the identity (or garbage) against attribute 0 and randomness 0 used to succeed.
func TestFindingAuditNymAcceptsIdentity(t *testing.T) {
	for _, e := range envs {
		f := newFindingFx(t, e)
		zero := f.curve.NewZrFromInt(0)
		for _, raw := range [][]byte{f.curve.NewG1().Bytes(), make([]byte, len(f.nym.Bytes()))} {
			var err error
			require.NotPanics(t, func() { err = NymEID(raw).AuditNymEid(f.key.Ipk, zero, fxEidIndex, zero, f.curve, f.tr) })
			require.Error(t, err)
			require.NotPanics(t, func() { err = NymRH(raw).AuditNymRh(f.key.Ipk, zero, fxRhIndex, zero, f.curve, f.tr) })
			require.Error(t, err)
		}

		// same for the nyms carried by a Signature
		id := f.tr.G1ToProto(f.curve.NewG1())
		sig := &Signature{EidNym: &EIDNym{Nym: id}, RhNym: &RHNym{Nym: id}}
		var err error
		require.NotPanics(t, func() { err = sig.AuditNymEid(f.key.Ipk, zero, fxEidIndex, zero, f.curve, f.tr) })
		require.Error(t, err, "signature eid nym")
		require.NotPanics(t, func() { err = sig.AuditNymRh(f.key.Ipk, zero, fxRhIndex, zero, f.curve, f.tr) })
		require.Error(t, err, "signature rh nym")
	}
}

// FINDING-DLOG-13: Signature.Ver never verified the revocation authority's signature on the
// epoch public key nor the epoch carried by the signature.
func TestFindingSignatureVerRevocationFieldsUnchecked(t *testing.T) {
	for _, e := range envs {
		f := newFindingFx(t, e)
		sig := f.sign(t, allHidden, opts.Standard)
		vals := f.values(allHidden)
		require.NoError(t, f.ver(t, sig, allHidden, vals, fxEidIndex, opts.Basic))

		s := proto.Clone(sig).(*Signature)
		s.Epoch = 123456
		require.Error(t, f.ver(t, s, allHidden, vals, fxEidIndex, opts.Basic), "forged epoch")

		s = proto.Clone(sig).(*Signature)
		s.RevocationPkSig = []byte("not a signature")
		require.Error(t, f.ver(t, s, allHidden, vals, fxEidIndex, opts.Basic), "forged epoch pk signature")

		// expected epoch differs from the one the signature was produced for
		var err error
		require.NotPanics(t, func() {
			err = sig.Ver(allHidden, f.key.Ipk, fxMsg, f.nym, vals, fxRhIndex, fxEidIndex, &f.rk.PublicKey, 1, f.curve, f.tr, opts.Basic, nil)
		})
		require.Error(t, err, "wrong expected epoch")

		// signed by another revocation authority
		other, err := f.idmx.GenerateLongTermRevocationKey()
		require.NoError(t, err)
		require.NotPanics(t, func() {
			err = sig.Ver(allHidden, f.key.Ipk, fxMsg, f.nym, vals, fxRhIndex, fxEidIndex, &other.PublicKey, 0, f.curve, f.tr, opts.Basic, nil)
		})
		require.Error(t, err, "other revocation authority")
	}
}

// A CRI for a non-zero epoch (fabric-ca starts at epoch 1) verifies when no
// epoch is configured (0) or the configured epoch matches, and fails otherwise.
func TestSignatureVerNonZeroEpoch(t *testing.T) {
	for _, e := range envs {
		f := newFindingFx(t, e)
		rng, err := f.curve.Rand()
		require.NoError(t, err)
		f.cri, err = f.idmx.CreateCRI(f.rk, nil, 1, ALG_NO_REVOCATION, rng, f.tr)
		require.NoError(t, err)
		sig := f.sign(t, allHidden, opts.Standard)
		vals := f.values(allHidden)

		ver := func(epoch int) error {
			return sig.Ver(allHidden, f.key.Ipk, fxMsg, f.nym, vals, fxRhIndex, fxEidIndex, &f.rk.PublicKey, epoch, f.curve, f.tr, opts.Basic, nil)
		}
		require.NoError(t, ver(0), "no configured epoch")
		require.NoError(t, ver(1), "matching epoch")
		require.ErrorContains(t, ver(2), "does not match the expected epoch")

		s := proto.Clone(sig).(*Signature)
		s.Epoch = 2
		require.Error(t, s.Ver(allHidden, f.key.Ipk, fxMsg, f.nym, vals, fxRhIndex, fxEidIndex, &f.rk.PublicKey, 0, f.curve, f.tr, opts.Basic, nil), "epoch not signed by the revocation authority")
	}
}

// FINDING-DLOG-14: the meta EidNym/RhNym in Signature.Ver were decoded with
// curve.NewG1FromBytes without rejecting the identity.
func TestFindingSignatureVerMetaNymIdentity(t *testing.T) {
	for _, e := range envs {
		f := newFindingFx(t, e)
		sig := f.sign(t, allHidden, opts.EidNymRhNym)
		vals := f.values(allHidden)
		require.NoError(t, f.ver(t, sig, allHidden, vals, fxEidIndex, opts.ExpectEidNymRhNym))
		for _, m := range []*opts.IdemixSignerMetadata{
			{EidNym: f.curve.NewG1().Bytes()},
			{RhNym: f.curve.NewG1().Bytes()},
		} {
			var err error
			require.NotPanics(t, func() {
				err = sig.Ver(allHidden, f.key.Ipk, fxMsg, f.nym, vals, fxRhIndex, fxEidIndex, &f.rk.PublicKey, 0, f.curve, f.tr, opts.ExpectEidNymRhNym, m)
			})
			require.Error(t, err)
		}
	}
}

// FINDING-DLOG-15: IssuerPublicKey.Check accepted more HAttrs than attribute names, and
// NewCredRequest accepted issuer nonces of the wrong length.
func TestFindingIssuerKeyAndNonceLengths(t *testing.T) {
	for _, e := range envs {
		f := newFindingFx(t, e)
		k := proto.Clone(f.key.Ipk).(*IssuerPublicKey)
		k.HAttrs = append(k.HAttrs, k.HAttrs[0])
		require.Error(t, k.Check(f.curve, f.tr))

		rng, err := f.curve.Rand()
		require.NoError(t, err)
		for _, n := range [][]byte{nil, {1}, make([]byte, f.curve.ScalarByteSize+1)} {
			_, err = f.idmx.NewCredRequest(f.sk, n, f.key.Ipk, rng, f.tr)
			require.Error(t, err)
		}
	}
}
