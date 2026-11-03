/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix_test

import (
	"testing"

	idemix "github.com/IBM/idemix/bccsp"
	"github.com/IBM/idemix/bccsp/handlers"
	"github.com/IBM/idemix/bccsp/schemes/dlog/crypto/translator/amcl"
	bccsp "github.com/IBM/idemix/bccsp/types"
	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/require"
)

type findingEnv struct {
	name  string
	csp   bccsp.BCCSP
	ipk   bccsp.Key
	usk   bccsp.Key
	nymSK bccsp.Key
	nymPK bccsp.Key
	tr    *amcl.Gurvy
	curve *math.Curve
}

func newFindingEnvs(t *testing.T) []findingEnv {
	t.Helper()
	c := math.Curves[math.BLS12_381_BBS]
	tr := &amcl.Gurvy{C: c}

	ariesCSP, err := idemix.NewAries(NewDummyKeyStore(), c, tr, true)
	require.NoError(t, err)
	dlogCSP, err := idemix.New(NewDummyKeyStore(), c, tr, true)
	require.NoError(t, err)

	var envs []findingEnv
	for _, e := range []struct {
		name string
		csp  bccsp.BCCSP
	}{{"aries", ariesCSP}, {"dlog", dlogCSP}} {
		isk, err := e.csp.KeyGen(&bccsp.IdemixIssuerKeyGenOpts{Temporary: true, AttributeNames: []string{"a", "b", "c", "d"}})
		require.NoError(t, err)
		ipk, err := isk.PublicKey()
		require.NoError(t, err)
		usk, err := e.csp.KeyGen(&bccsp.IdemixUserSecretKeyGenOpts{Temporary: true})
		require.NoError(t, err)
		nymSK, err := e.csp.KeyDeriv(usk, &bccsp.IdemixNymKeyDerivationOpts{Temporary: true, IssuerPK: ipk})
		require.NoError(t, err)
		nymPK, err := nymSK.PublicKey()
		require.NoError(t, err)
		envs = append(envs, findingEnv{e.name, e.csp, ipk, usk, nymSK, nymPK, tr, c})
	}

	return envs
}

func requireErrNoPanic(t *testing.T, f func() error) {
	t.Helper()
	var err error
	require.NotPanics(t, func() { err = f() })
	require.Error(t, err)
}

// FINDING-BCCSP-1: the userSecreKeySignerMultiplexer / issuerPublicKeyVerifierMultiplexer
// route an opts type to a sub-handler that the scheme never configured (nil pointer):
// NewAries sets credentialRequestSigner/credentialRequestVerifier to nil and New leaves
// blindCredentialRequestSigner/blindcredentialRequestVerifier nil. Passing the
// "other scheme's" credential request opts makes CSP.Sign/Verify panic.
func TestFindingMultiplexerNilSubHandler(t *testing.T) {
	envs := newFindingEnvs(t)
	nonce := make([]byte, 32)

	t.Run("aries/credential request opts", func(t *testing.T) {
		e := envs[0]
		requireErrNoPanic(t, func() error {
			_, err := e.csp.Sign(e.usk, nil, &bccsp.IdemixCredentialRequestSignerOpts{IssuerPK: e.ipk, IssuerNonce: nonce})

			return err
		})
		requireErrNoPanic(t, func() error {
			_, err := e.csp.Verify(e.ipk, []byte{1}, nil, &bccsp.IdemixCredentialRequestSignerOpts{IssuerNonce: nonce})

			return err
		})
	})
	t.Run("dlog/blind credential request opts", func(t *testing.T) {
		e := envs[1]
		requireErrNoPanic(t, func() error {
			_, err := e.csp.Sign(e.usk, nil, &bccsp.IdemixBlindCredentialRequestSignerOpts{IssuerPK: e.ipk, IssuerNonce: nonce})

			return err
		})
		requireErrNoPanic(t, func() error {
			_, err := e.csp.Verify(e.ipk, []byte{1}, nil, &bccsp.IdemixBlindCredentialRequestSignerOpts{IssuerNonce: nonce})

			return err
		})
	})
}

// FINDING-BCCSP-2: typed-nil keys pass the `k == nil` guard in CSP.Sign/KeyDeriv (the
// interface is non-nil) and the handlers then dereference them.
func TestFindingTypedNilKeys(t *testing.T) {
	for _, e := range newFindingEnvs(t) {
		t.Run(e.name, func(t *testing.T) {
			nilUSK := (*handlers.UserSecretKey)(nil)
			requireErrNoPanic(t, func() error {
				_, err := e.csp.Sign(nilUSK, []byte("m"), &bccsp.IdemixNymSignerOpts{Nym: e.nymSK, IssuerPK: e.ipk})

				return err
			})
			requireErrNoPanic(t, func() error {
				_, err := e.csp.KeyDeriv(nilUSK, &bccsp.IdemixNymKeyDerivationOpts{Temporary: true, IssuerPK: e.ipk})

				return err
			})
			requireErrNoPanic(t, func() error {
				_, err := e.csp.Sign(e.usk, []byte("m"), &bccsp.IdemixNymSignerOpts{Nym: (*handlers.NymSecretKey)(nil), IssuerPK: e.ipk})

				return err
			})
		})
	}
}

// FINDING-BCCSP-3: Aries NymVerifier panics (no recover in aries.NymSigner.Verify) when the
// nym public key wraps a nil point, or when IdemixNymSignerOpts.SKIndex is out of range.
// The dlog backend recovers and returns an error (or ignores SKIndex).
func TestFindingAriesNymVerifyPanics(t *testing.T) {
	e := newFindingEnvs(t)[0]
	require.Equal(t, "aries", e.name)

	sig, err := e.csp.Sign(e.usk, []byte("m"), &bccsp.IdemixNymSignerOpts{Nym: e.nymSK, IssuerPK: e.ipk})
	require.NoError(t, err)

	requireErrNoPanic(t, func() error {
		_, err := e.csp.Verify(handlers.NewNymPublicKey(nil, e.tr), sig, []byte("m"), &bccsp.IdemixNymSignerOpts{IssuerPK: e.ipk})

		return err
	})
	for _, idx := range []int{-1, 99} {
		requireErrNoPanic(t, func() error {
			_, err := e.csp.Verify(e.nymPK, sig, []byte("m"), &bccsp.IdemixNymSignerOpts{IssuerPK: e.ipk, SKIndex: idx})

			return err
		})
	}
}

// FINDING-BCCSP-4: Aries smartcard nym verification slices the signature at fixed offsets
// without a length check: any short signature with IsSmartcard=true panics in CSP.Verify.
func TestFindingAriesSmartcardNymVerifyShortSignature(t *testing.T) {
	e := newFindingEnvs(t)[0]
	require.Equal(t, "aries", e.name)

	requireErrNoPanic(t, func() error {
		_, err := e.csp.Verify(handlers.NewNymPublicKey(nil, e.tr), []byte{1}, []byte("m"), &bccsp.IdemixNymSignerOpts{
			IssuerPK:    e.ipk,
			IsSmartcard: true,
			NymEid:      e.curve.GenG1,
		})

		return err
	})
}

// FINDING-BCCSP-5: the dlog IssuerPublicKeyImporter calls bridge.Issuer.Bases whenever
// CommitmentBasesRequest != None, and that method is `panic("not implemented")`.
func TestFindingDlogIssuerPublicKeyImportCommitmentBasesPanics(t *testing.T) {
	e := newFindingEnvs(t)[1]
	require.Equal(t, "dlog", e.name)

	raw, err := e.ipk.Bytes()
	require.NoError(t, err)
	requireErrNoPanic(t, func() error {
		_, err := e.csp.KeyImport(raw, &bccsp.IdemixIssuerPublicKeyImportOpts{
			Temporary:              true,
			AttributeNames:         []string{"a", "b", "c", "d"},
			CommitmentBasesRequest: bccsp.CommitmentBasesRequest(1),
		})

		return err
	})
}
