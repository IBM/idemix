/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bridge_test

import (
	"sync"
	"testing"

	"github.com/IBM/idemix/bccsp/schemes/dlog/bridge"
	idemix "github.com/IBM/idemix/bccsp/schemes/dlog/crypto"
	"github.com/IBM/idemix/bccsp/schemes/dlog/crypto/translator/amcl"
	"github.com/IBM/idemix/bccsp/types"
	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/require"
)

// An issuer public key imported from bytes is decoded once: verification uses
// the decoded form, so it is not affected by later changes to the exposed
// protobuf message, and keeps working (and keeps rejecting) concurrently.
func TestImportedIssuerPublicKeyDecodedOnce(t *testing.T) {
	for _, curveID := range []math.CurveID{math.FP256BN_AMCL, math.BLS12_381_GURVY} {
		curve := math.Curves[curveID]
		var tr idemix.Translator = &amcl.Gurvy{C: curve}
		if curveID == math.FP256BN_AMCL {
			tr = &amcl.Fp256bn{C: curve}
		}
		idmx := &idemix.Idemix{Curve: curve, Translator: tr}
		issuer := &bridge.Issuer{Idemix: idmx, Translator: tr}
		user := &bridge.User{Idemix: idmx, Translator: tr}
		credReq := &bridge.CredRequest{Idemix: idmx, Translator: tr}
		credential := &bridge.Credential{Idemix: idmx, Translator: tr}
		revocation := &bridge.Revocation{Idemix: idmx, Translator: tr}
		scheme := &bridge.SignatureScheme{Idemix: idmx, Translator: tr}
		nymScheme := &bridge.NymSignatureScheme{Idemix: idmx, Translator: tr}

		names := []string{"A", "B", "EID", "RH"}
		isk, err := issuer.NewKey(names)
		require.NoError(t, err)
		raw, err := isk.Public().Bytes()
		require.NoError(t, err)
		ipk, err := issuer.NewPublicKeyFromBytes(raw, names)
		require.NoError(t, err)

		sk, err := user.NewKey()
		require.NoError(t, err)
		req, err := credReq.Sign(sk, ipk, []byte("0123456789012345678901234567890123456789"[:curve.ScalarByteSize]))
		require.NoError(t, err)
		attrs := []types.IdemixAttribute{
			{Type: types.IdemixBytesAttribute, Value: []byte("a")},
			{Type: types.IdemixIntAttribute, Value: 1},
			{Type: types.IdemixBytesAttribute, Value: []byte("eid")},
			{Type: types.IdemixIntAttribute, Value: 2},
		}
		cred, err := credential.Sign(isk, req, attrs)
		require.NoError(t, err)
		require.NoError(t, credential.Verify(sk, ipk, cred, attrs))

		nym, rNym, err := user.MakeNym(sk, ipk)
		require.NoError(t, err)
		rk, err := revocation.NewKey()
		require.NoError(t, err)
		cri, err := revocation.Sign(rk, nil, 0, types.AlgNoRevocation)
		require.NoError(t, err)

		hidden := []types.IdemixAttribute{{Type: types.IdemixHiddenAttribute}, {Type: types.IdemixHiddenAttribute}, {Type: types.IdemixHiddenAttribute}, {Type: types.IdemixHiddenAttribute}}
		sig, _, err := scheme.Sign(cred, sk, nym, rNym, ipk, hidden, []byte("msg"), 3, 2, cri, types.Standard, nil)
		require.NoError(t, err)
		nymSig, err := nymScheme.Sign(sk, nym, rNym, ipk, []byte("msg"))
		require.NoError(t, err)

		verify := func(msg string) error {
			return scheme.Verify(ipk, sig, []byte(msg), nym, hidden, 3, 2, 0, &rk.PublicKey, 0, types.ExpectStandard, nil)
		}
		require.NoError(t, verify("msg"))
		require.Error(t, verify("other"))

		// mutate the protobuf exposed by the imported key: verification is
		// unaffected because it uses the key decoded at import time
		other, err := issuer.NewKey(names)
		require.NoError(t, err)
		pk := ipk.(*bridge.IssuerPublicKey).PK
		otherPK := other.Public().(*bridge.IssuerPublicKey).PK
		pk.W, pk.HSk, pk.HRand = otherPK.W, otherPK.HSk, otherPK.HRand
		require.NoError(t, verify("msg"))
		require.NoError(t, nymScheme.Verify(ipk, nym, nymSig, []byte("msg"), 0))
		require.NoError(t, credential.Verify(sk, ipk, cred, attrs))

		// a key that was not imported (e.g. the public part of a secret key)
		// is still decoded on every call
		direct := isk.Public()
		require.NoError(t, scheme.Verify(direct, sig, []byte("msg"), nym, hidden, 3, 2, 0, &rk.PublicKey, 0, types.ExpectStandard, nil))

		var wg sync.WaitGroup
		for g := range 4 {
			wg.Go(func() {
				if g%2 == 0 {
					require.NoError(t, verify("msg"))
				} else {
					require.Error(t, verify("other"))
				}
				require.Error(t, scheme.Verify(ipk, sig, []byte("msg"), nym, hidden, 3, 2, 0, &rk.PublicKey, 1, types.ExpectStandard, nil))
			})
		}
		wg.Wait()
	}
}
