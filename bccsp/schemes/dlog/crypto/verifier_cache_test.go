/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"io"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	opts "github.com/IBM/idemix/bccsp/types"
)

func (f *findingFx) decoded(t *testing.T) *DecodedIssuerPublicKey {
	t.Helper()
	d, err := proto.Clone(f.key.Ipk).(*IssuerPublicKey).CheckAndDecode(f.curve, f.tr)
	require.NoError(t, err)

	return d
}

func (f *findingFx) verDecoded(sig *Signature, d *DecodedIssuerPublicKey, c *EpochPKCache, epoch int) error {
	return sig.VerDecoded(allHidden, d, fxMsg, f.nym, f.values(allHidden), fxRhIndex, fxEidIndex,
		&f.rk.PublicKey, epoch, f.curve, f.tr, opts.ExpectStandard, nil, c)
}

// The decoded issuer key verifies exactly what the protobuf key verifies.
func TestDecodedIssuerPublicKeyMatchesProto(t *testing.T) {
	for _, e := range envs {
		f := newFindingFx(t, e)
		d := f.decoded(t)
		require.Equal(t, f.key.Ipk.Hash, d.Hash())
		require.Equal(t, f.key.Ipk.AttributeNames, d.AttributeNames())

		sig := f.sign(t, allHidden, opts.Standard)
		require.NoError(t, f.ver(t, sig, allHidden, f.values(allHidden), fxEidIndex, opts.ExpectStandard))
		require.NoError(t, f.verDecoded(sig, d, nil, 0))

		other := proto.Clone(sig).(*Signature)
		other.ProofSSk = f.curve.NewZrFromInt(7).Bytes()
		require.Error(t, f.ver(t, other, allHidden, f.values(allHidden), fxEidIndex, opts.ExpectStandard))
		require.Error(t, f.verDecoded(other, d, nil, 0))

		nymSig, err := f.idmx.NewNymSignature(f.sk, f.nym, f.rnym, f.key.Ipk, fxMsg, newRng(t, f), f.tr)
		require.NoError(t, err)
		require.NoError(t, nymSig.Ver(f.nym, f.key.Ipk, fxMsg, f.curve, f.tr))
		require.NoError(t, nymSig.VerDecoded(f.nym, d, fxMsg, f.curve, f.tr))
		require.Error(t, nymSig.VerDecoded(f.nym, d, []byte("other"), f.curve, f.tr))

		require.NoError(t, f.cred.Ver(f.sk, f.key.Ipk, f.curve, f.tr))
		require.NoError(t, f.cred.VerDecoded(f.sk, d, f.curve, f.tr))
		require.Error(t, f.cred.VerDecoded(f.curve.NewZrFromInt(5), d, f.curve, f.tr))

		require.Error(t, sig.VerDecoded(allHidden, nil, fxMsg, f.nym, f.values(allHidden), fxRhIndex, fxEidIndex,
			nil, 0, f.curve, f.tr, opts.ExpectStandard, nil, nil))
		require.Error(t, nymSig.VerDecoded(f.nym, nil, fxMsg, f.curve, f.tr))
		require.Error(t, f.cred.VerDecoded(f.sk, nil, f.curve, f.tr))
	}
}

// CheckAndDecode rejects exactly what Check rejects.
func TestDecodedIssuerPublicKeyRejectsInvalidKeys(t *testing.T) {
	for _, e := range envs {
		f := newFindingFx(t, e)
		k := proto.Clone(f.key.Ipk).(*IssuerPublicKey)
		k.ProofS = f.curve.NewZrFromInt(1).Bytes()
		require.Error(t, k.Check(f.curve, f.tr))
		d, err := k.CheckAndDecode(f.curve, f.tr)
		require.Error(t, err)
		require.Nil(t, d)

		_, err = (*IssuerPublicKey)(nil).CheckAndDecode(f.curve, f.tr)
		require.Error(t, err)
	}
}

// A decoded key is not affected by later changes to the protobuf message it
// was decoded from, and verifications never modify the decoded points.
func TestDecodedIssuerPublicKeyIsImmutable(t *testing.T) {
	for _, e := range envs {
		f := newFindingFx(t, e)
		src := proto.Clone(f.key.Ipk).(*IssuerPublicKey)
		d, err := src.CheckAndDecode(f.curve, f.tr)
		require.NoError(t, err)

		other := newFindingFx(t, e)
		src.W = other.key.Ipk.W
		src.HSk = other.key.Ipk.HSk
		src.HAttrs[0] = other.key.Ipk.HAttrs[0]
		src.Hash = other.key.Ipk.Hash
		src.AttributeNames[0] = "mutated"
		require.Equal(t, f.key.Ipk.AttributeNames, d.AttributeNames())

		sig := f.sign(t, allHidden, opts.Standard)
		for range 3 {
			require.NoError(t, f.verDecoded(sig, d, nil, 0))
		}
		// mutating the returned copies has no effect either
		d.AttributeNames()[0] = "mutated"
		d.Hash()[0] ^= 0xff
		require.NoError(t, f.verDecoded(sig, d, nil, 0))
	}
}

// A key decoded on one curve is rejected on another.
func TestDecodedIssuerPublicKeyRejectsOtherCurve(t *testing.T) {
	f := newFindingFx(t, envs[0])
	d := f.decoded(t)
	g := newFindingFx(t, envs[1])
	require.NotEqual(t, f.curve.ID(), g.curve.ID())
	sig := f.sign(t, allHidden, opts.Standard)
	require.ErrorContains(t, sig.VerDecoded(allHidden, d, fxMsg, f.nym, f.values(allHidden), fxRhIndex, fxEidIndex,
		nil, 0, g.curve, g.tr, opts.ExpectStandard, nil, nil), "decoded on curve")
}

// The epoch PK cache only stores successful verifications, serves only the
// exact verified inputs, and is bounded.
func TestEpochPKCache(t *testing.T) {
	for _, e := range envs {
		f := newFindingFx(t, e)
		d := f.decoded(t)
		var c EpochPKCache
		sig := f.sign(t, allHidden, opts.Standard)

		// failures are not cached: wrong epoch (in the CRI signature), wrong
		// signature, wrong revocation key, mauled epoch PK
		cri1, err := f.idmx.CreateCRI(f.rk, nil, 1, ALG_NO_REVOCATION, newRng(t, f), f.tr)
		require.NoError(t, err)
		wrongEpoch := proto.Clone(sig).(*Signature)
		wrongEpoch.RevocationPkSig = cri1.EpochPkSig
		require.ErrorContains(t, f.verDecoded(wrongEpoch, d, &c, 0), "epochPKSig invalid")
		require.Zero(t, c.Len())

		trailing := proto.Clone(sig).(*Signature)
		trailing.RevocationPkSig = append(append([]byte{}, sig.RevocationPkSig...), 0)
		require.Error(t, f.verDecoded(trailing, d, &c, 0))
		require.Zero(t, c.Len())

		otherRK, err := f.idmx.GenerateLongTermRevocationKey()
		require.NoError(t, err)
		require.Error(t, sig.VerDecoded(allHidden, d, fxMsg, f.nym, f.values(allHidden), fxRhIndex, fxEidIndex,
			&otherRK.PublicKey, 0, f.curve, f.tr, opts.ExpectStandard, nil, &c))
		require.Zero(t, c.Len())

		// a signature valid for the epoch PK, but whose ZK proof is wrong:
		// the epoch PK is cached (it is valid), the signature still fails
		badProof := proto.Clone(sig).(*Signature)
		badProof.ProofSSk = f.curve.NewZrFromInt(7).Bytes()
		require.Error(t, f.verDecoded(badProof, d, &c, 0))
		require.Equal(t, 1, c.Len())

		// hit path: same result, no new entry
		for range 3 {
			require.NoError(t, f.verDecoded(sig, d, &c, 0))
			require.Equal(t, 1, c.Len())
		}
		sig2 := f.sign(t, allHidden, opts.Standard)
		require.NoError(t, f.verDecoded(sig2, d, &c, 0))
		require.Equal(t, 1, c.Len())

		// after caching, the failing variants still fail
		require.Error(t, f.verDecoded(wrongEpoch, d, &c, 0))
		require.Error(t, f.verDecoded(trailing, d, &c, 0))
		require.Error(t, f.verDecoded(badProof, d, &c, 0))
		require.Error(t, sig.VerDecoded(allHidden, d, fxMsg, f.nym, f.values(allHidden), fxRhIndex, fxEidIndex,
			&otherRK.PublicKey, 0, f.curve, f.tr, opts.ExpectStandard, nil, &c))
		// a different expected epoch is not served from the cache
		require.ErrorContains(t, f.verDecoded(sig, d, &c, 1), "does not match the expected epoch")
		// an epoch PK replaced with a different point (but the old signature)
		swapped := proto.Clone(sig).(*Signature)
		swapped.RevocationEpochPk = f.tr.G2ToProto(f.curve.GenG2.Mul(f.curve.NewZrFromInt(2)))
		require.ErrorContains(t, f.verDecoded(swapped, d, &c, 0), "epochPKSig invalid")
		// unknown fields in the epoch PK change the signed digest
		unk := proto.Clone(sig).(*Signature)
		unk.RevocationEpochPk.ProtoReflect().SetUnknown([]byte{0x2a, 0x01, 0x00})
		require.Error(t, f.verDecoded(unk, d, &c, 0))
		require.Equal(t, 1, c.Len())

		// a valid signature for another epoch, with matching expected epoch,
		// adds a new entry
		f.cri = cri1
		sigE1 := f.sign(t, allHidden, opts.Standard)
		require.NoError(t, f.verDecoded(sigE1, d, &c, 1))
		require.Equal(t, 2, c.Len())

		// bounded
		for i := 2; i < 40; i++ {
			cri, err := f.idmx.CreateCRI(f.rk, nil, i, ALG_NO_REVOCATION, newRng(t, f), f.tr)
			require.NoError(t, err)
			_, k, err := c.verify(&f.rk.PublicKey, cri.EpochPk, cri.EpochPkSig, i, ALG_NO_REVOCATION)
			require.NoError(t, err)
			require.NotNil(t, k)
			p, err := f.tr.G2FromProto(cri.EpochPk)
			require.NoError(t, err)
			c.add(k, p)
		}
		require.Equal(t, 16, c.Len())

		// nil cache: plain verification
		var nilCache *EpochPKCache
		require.NoError(t, f.verDecoded(sig, d, nilCache, 0))
		require.Error(t, f.verDecoded(wrongEpoch, d, nilCache, 0))
		require.Zero(t, nilCache.Len())
	}
}

// The cached decoded epoch PK is never handed out by reference.
func TestEpochPKCacheReturnsCopies(t *testing.T) {
	f := newFindingFx(t, envs[0])
	var c EpochPKCache
	_, k, err := c.verify(&f.rk.PublicKey, f.cri.EpochPk, f.cri.EpochPkSig, 0, ALG_NO_REVOCATION)
	require.NoError(t, err)
	p, err := f.tr.G2FromProto(f.cri.EpochPk)
	require.NoError(t, err)
	c.add(k, p)
	p.Add(f.curve.GenG2) // the caller's point is not the cached one

	p1, k1, err := c.verify(&f.rk.PublicKey, f.cri.EpochPk, f.cri.EpochPkSig, 0, ALG_NO_REVOCATION)
	require.NoError(t, err)
	require.Nil(t, k1)
	expected, err := f.tr.G2FromProto(f.cri.EpochPk)
	require.NoError(t, err)
	require.True(t, p1.Equals(expected))
	p1.Add(f.curve.GenG2)
	p2, _, err := c.verify(&f.rk.PublicKey, f.cri.EpochPk, f.cri.EpochPkSig, 0, ALG_NO_REVOCATION)
	require.NoError(t, err)
	require.True(t, p2.Equals(expected))
}

// Decoded keys and the epoch PK cache are safe for concurrent use.
func TestVerifierCachesConcurrentUse(t *testing.T) {
	for _, e := range envs {
		f := newFindingFx(t, e)
		d := f.decoded(t)
		var c EpochPKCache
		good := f.sign(t, allHidden, opts.Standard)
		bad := proto.Clone(good).(*Signature)
		bad.RevocationPkSig = append(append([]byte{}, good.RevocationPkSig...), 0)

		var wg sync.WaitGroup
		for g := range 6 {
			wg.Go(func() {
				for range 3 {
					if g%2 == 0 {
						require.NoError(t, f.verDecoded(good, d, &c, 0))
					} else {
						require.Error(t, f.verDecoded(bad, d, &c, 0))
					}
				}
			})
		}
		wg.Wait()
		require.Equal(t, 1, c.Len())
	}
}

func newRng(t *testing.T, f *findingFx) io.Reader {
	t.Helper()
	rng, err := f.curve.Rand()
	require.NoError(t, err)

	return rng
}
