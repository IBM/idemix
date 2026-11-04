/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries_test

import (
	"fmt"
	"testing"

	"github.com/IBM/idemix/bbs"
	"github.com/IBM/idemix/bccsp/schemes/aries"
	"github.com/IBM/idemix/bccsp/types"
	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// TestFindingSignerSkPosWithDisclosedAttributes: with the user secret key at position
// SkPos > 0 in the BBS+ message vector, the disclosed attribute indices, the VC2 position of
// sk and the VC2 positions of eid / rh all depend on SkPos and on the disclosed attributes
// preceding it. Exercise credentials issued with sk in the middle and at the end of the
// message vector, with attributes disclosed both before and after sk, and eid / rh on
// either side of sk.
func TestFindingSignerSkPosWithDisclosedAttributes(t *testing.T) {
	curve := math.Curves[math.BLS12_381_BBS]
	rng, err := curve.Rand()
	require.NoError(t, err)

	attrNames := []string{"a0", "a1", "a2", "a3", "a4", "a5"}
	values := [][]byte{[]byte("v0"), []byte("v1"), []byte("v2"), []byte("v3"), []byte("v4"), []byte("v5")}

	isk, err := (&aries.Issuer{Curve: curve}).NewKey(attrNames)
	require.NoError(t, err)
	ipk := isk.Public()

	credAttrs := make([]types.IdemixAttribute, len(values))
	for i, v := range values {
		credAttrs[i] = types.IdemixAttribute{Type: types.IdemixBytesAttribute, Value: v}
	}

	// disclose a0, a2, a4; hide a1, a3, a5
	disclosed := map[int]bool{0: true, 2: true, 4: true}
	sigAttrs := func(disclosed map[int]bool) []types.IdemixAttribute {
		attrs := make([]types.IdemixAttribute, len(values))
		for i, v := range values {
			if disclosed[i] {
				attrs[i] = types.IdemixAttribute{Type: types.IdemixBytesAttribute, Value: v}
			} else {
				attrs[i] = types.IdemixAttribute{Type: types.IdemixHiddenAttribute}
			}
		}

		return attrs
	}

	for _, tc := range []struct {
		skPos, eidIndex, rhIndex int
	}{
		{skPos: 1, eidIndex: 1, rhIndex: 5},
		{skPos: 3, eidIndex: 1, rhIndex: 5}, // eid before sk, rh after sk
		{skPos: 3, eidIndex: 5, rhIndex: 1}, // eid after sk, rh before sk
		{skPos: 3, eidIndex: 3, rhIndex: 1}, // eid right after sk
		{skPos: 4, eidIndex: 3, rhIndex: 5},
		{skPos: 6, eidIndex: 3, rhIndex: 5}, // sk is the last message
	} {
		t.Run(fmt.Sprintf("skPos=%d,eid=%d,rh=%d", tc.skPos, tc.eidIndex, tc.rhIndex), func(t *testing.T) {
			// issuance
			user := &aries.User{Curve: curve, Rng: rng, UserSecretKeyIndex: tc.skPos}
			sk, err := user.NewKey()
			require.NoError(t, err)

			cr := &aries.CredRequest{Curve: curve, UserSecretKeyIndex: tc.skPos}
			credReq, blinding, err := cr.Blind(sk, ipk, []byte("nonce"))
			require.NoError(t, err)
			require.NoError(t, cr.BlindVerify(credReq, ipk, []byte("nonce")))

			credProto := &aries.Cred{BBS: bbs.New(curve), Curve: curve, UserSecretKeyIndex: tc.skPos}
			cred, err := credProto.Sign(isk, credReq, credAttrs)
			require.NoError(t, err)
			cred, err = cr.Unblind(cred, blinding)
			require.NoError(t, err)

			credential := &aries.Credential{}
			require.NoError(t, proto.Unmarshal(cred, credential))
			require.Equal(t, int32(tc.skPos), credential.SkPos) // #nosec G115 -- small test constant
			require.NoError(t, credProto.Verify(sk, ipk, cred, credAttrs))

			nym, rNym, err := user.MakeNym(sk, ipk)
			require.NoError(t, err)

			// a hidden attribute that is neither eid nor rh
			extra := -1
			for _, i := range []int{1, 3, 5} {
				if i != tc.eidIndex && i != tc.rhIndex {
					extra = i

					break
				}
			}
			require.NotEqual(t, -1, extra)

			signer := &aries.Signer{Curve: curve, Rng: rng}
			attrs := sigAttrs(disclosed)
			msg := []byte("msg")

			verify := func(sig []byte, attrs []types.IdemixAttribute, skIndex int, verType types.VerificationType) error {
				return signer.Verify(ipk, sig, msg, nym, attrs, tc.rhIndex, tc.eidIndex, skIndex, nil, 0, verType, nil)
			}

			for _, st := range []struct {
				sigType types.SignatureType
				verType types.VerificationType
			}{
				{types.Standard, types.ExpectStandard},
				{types.EidNym, types.ExpectEidNym},
				{types.EidNymRhNym, types.ExpectEidNymRhNym},
			} {
				sig, meta, err := signer.Sign(cred, sk, nym, rNym, ipk, attrs, msg, tc.rhIndex, tc.eidIndex, nil, st.sigType, nil)
				require.NoError(t, err, "sign %v", st.sigType)

				require.NoError(t, verify(sig, attrs, tc.skPos, st.verType), "verify %v", st.sigType)
				require.NoError(t, verify(sig, attrs, tc.skPos, types.BestEffort), "verify %v best effort", st.sigType)

				if st.sigType != types.Standard {
					require.NoError(t, signer.AuditNymEid(ipk, tc.eidIndex, tc.skPos, sig, string(values[tc.eidIndex]), meta.EidNymAuditData.Rand, types.AuditExpectSignature))
					require.Error(t, signer.AuditNymEid(ipk, tc.eidIndex, tc.skPos, sig, "other", meta.EidNymAuditData.Rand, types.AuditExpectSignature))
				}
				if st.sigType == types.EidNymRhNym {
					require.NoError(t, signer.AuditNymRh(ipk, tc.rhIndex, tc.skPos, sig, string(values[tc.rhIndex]), meta.RhNymAuditData.Rand, types.AuditExpectSignature))
					require.Error(t, signer.AuditNymRh(ipk, tc.rhIndex, tc.skPos, sig, "other", meta.RhNymAuditData.Rand, types.AuditExpectSignature))
				}

				// negative: verifier expects a different disclosure set
				for name, other := range map[string]map[int]bool{
					"hide_before_sk":     {2: true, 4: true},
					"hide_after_sk":      {0: true, 2: true},
					"disclose_more":      {0: true, 2: true, 4: true, extra: true},
					"disclose_different": {0: true, extra: true, 4: true},
				} {
					require.Error(t, verify(sig, sigAttrs(other), tc.skPos, st.verType), "verify %v with disclosure set %s", st.sigType, name)
				}

				// negative: wrong value for an attribute disclosed before / after sk
				for _, i := range []int{0, 4} {
					wrong := sigAttrs(disclosed)
					wrong[i].Value = []byte("wrong")
					require.Error(t, verify(sig, wrong, tc.skPos, st.verType), "verify %v with wrong value for a%d", st.sigType, i)
				}

				// negative: wrong sk position
				for _, skIndex := range []int{0, tc.skPos - 1, tc.skPos + 1} {
					if skIndex == tc.skPos || skIndex < 0 || skIndex > len(values) {
						continue
					}
					require.Error(t, verify(sig, attrs, skIndex, st.verType), "verify %v with sk index %d", st.sigType, skIndex)
				}
			}
		})
	}
}
