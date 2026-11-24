/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	"crypto/ecdsa"
	"sync"
	"testing"

	"github.com/IBM/idemix/bccsp/schemes/internal/epochcache"
	"github.com/IBM/idemix/bccsp/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

type epochPKCacheEnv struct {
	*nymIdxEnv
	ra *RevocationAuthority
	rk *ecdsa.PrivateKey
}

func newEpochPKCacheEnv(t *testing.T) *epochPKCacheEnv {
	t.Helper()
	env := newNymIdxEnv(t)
	ra := &RevocationAuthority{Curve: env.curve, Rng: env.signer.Rng}
	rk, err := ra.NewKey()
	require.NoError(t, err)

	return &epochPKCacheEnv{nymIdxEnv: env, ra: ra, rk: rk}
}

func (env *epochPKCacheEnv) signForEpoch(t *testing.T, epoch int) []byte {
	t.Helper()
	cri, err := env.ra.Sign(env.rk, nil, epoch, types.AlgNoRevocation)
	require.NoError(t, err)
	sig, _, err := env.signer.Sign(env.cred, env.sk, env.nym, env.rNym, env.ipk, env.attrs, env.msg, nymIdxRhIndex, nymIdxEidIndex, cri, types.Standard, nil)
	require.NoError(t, err)

	return sig
}

func (env *epochPKCacheEnv) verifyWith(s *Signer, sig []byte, revPk *ecdsa.PublicKey, epoch int) error {
	return s.Verify(env.ipk, sig, env.msg, env.nym, env.attrs, nymIdxRhIndex, nymIdxEidIndex, 0, revPk, epoch, types.ExpectStandard, nil)
}

func TestAriesEpochPKCache(t *testing.T) {
	env := newEpochPKCacheEnv(t)
	s := &Signer{Curve: env.curve, Rng: env.signer.Rng}
	revPk := &env.rk.PublicKey
	sig := env.signForEpoch(t, 0)

	// failures are not cached
	other, err := env.ra.NewKey()
	require.NoError(t, err)
	require.ErrorContains(t, env.verifyWith(s, sig, &other.PublicKey, 0), "epochPKSig invalid")
	require.Zero(t, s.epochPKCache.len())

	trailing := rewrite(t, sig, func(sig *Signature) { sig.RevocationPkSig = append(sig.RevocationPkSig, 0) })
	require.ErrorContains(t, env.verifyWith(s, trailing, revPk, 0), "trailing data")
	require.Zero(t, s.epochPKCache.len())

	sigE1 := env.signForEpoch(t, 1)
	wrongEpoch := rewrite(t, sig, func(sig *Signature) {
		sigE1p := &Signature{}
		require.NoError(t, proto.Unmarshal(sigE1, sigE1p))
		sig.RevocationPkSig = sigE1p.RevocationPkSig
	})
	require.ErrorContains(t, env.verifyWith(s, wrongEpoch, revPk, 0), "epochPKSig invalid")
	require.Zero(t, s.epochPKCache.len())

	// a valid epoch PK signature on a signature whose proof is wrong: the
	// epoch PK is cached (it is valid), the signature still fails
	badProof := rewrite(t, sig, func(sig *Signature) { sig.Nonce = env.curve.NewZrFromInt(7).Bytes() })
	require.Error(t, env.verifyWith(s, badProof, revPk, 0))
	require.Equal(t, 1, s.epochPKCache.len())

	// hit path
	for range 3 {
		require.NoError(t, env.verifyWith(s, sig, revPk, 0))
		require.Equal(t, 1, s.epochPKCache.len())
	}

	// failing inputs still fail after caching
	require.Error(t, env.verifyWith(s, badProof, revPk, 0))
	require.Error(t, env.verifyWith(s, sig, &other.PublicKey, 0))
	require.Error(t, env.verifyWith(s, trailing, revPk, 0))
	require.Error(t, env.verifyWith(s, wrongEpoch, revPk, 0))
	require.ErrorContains(t, env.verifyWith(s, sig, revPk, 1), "does not match the expected epoch")
	swapped := rewrite(t, sig, func(sig *Signature) { sig.RevocationEpochPk = env.curve.GenG1.Bytes() })
	require.ErrorContains(t, env.verifyWith(s, swapped, revPk, 0), "epochPKSig invalid")
	require.Equal(t, 1, s.epochPKCache.len())

	// another epoch is a new entry
	require.NoError(t, env.verifyWith(s, sigE1, revPk, 1))
	require.Equal(t, 2, s.epochPKCache.len())

	// bounded
	for i := 2; i < 40; i++ {
		cri, err := env.ra.Sign(env.rk, nil, i, types.AlgNoRevocation)
		require.NoError(t, err)
		require.NoError(t, env.ra.Verify(revPk, cri, i, types.AlgNoRevocation))
		c := &CredentialRevocationInformation{}
		require.NoError(t, proto.Unmarshal(cri, c))
		require.NoError(t, s.epochPKCache.verify(revPk, c.EpochPk, c.EpochPkSig, i, types.AlgNoRevocation))
	}
	require.Equal(t, epochcache.DefaultSize, s.epochPKCache.len())

	// nil revocation public key: no check, no caching
	fresh := &Signer{Curve: env.curve, Rng: env.signer.Rng}
	require.NoError(t, env.verifyWith(fresh, sig, nil, 0))
	require.Zero(t, fresh.epochPKCache.len())
}

func TestAriesEpochPKCacheConcurrentUse(t *testing.T) {
	env := newEpochPKCacheEnv(t)
	s := &Signer{Curve: env.curve, Rng: env.signer.Rng}
	revPk := &env.rk.PublicKey
	good := env.signForEpoch(t, 0)
	bad := rewrite(t, good, func(sig *Signature) { sig.RevocationPkSig = append(sig.RevocationPkSig, 0) })

	var wg sync.WaitGroup
	for g := range 6 {
		wg.Go(func() {
			for range 3 {
				if g%2 == 0 {
					require.NoError(t, env.verifyWith(s, good, revPk, 0))
				} else {
					require.Error(t, env.verifyWith(s, bad, revPk, 0))
				}
			}
		})
	}
	wg.Wait()
	require.Equal(t, 1, s.epochPKCache.len())
}
