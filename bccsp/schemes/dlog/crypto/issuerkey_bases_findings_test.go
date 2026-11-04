/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// IssuerPublicKey.Check must reject issuer keys whose bases HSk, HRand and
// HAttrs[i] are not pairwise distinct: with a repeated base the credential only
// binds the sum of the corresponding values (e.g. sk + attribute), not each one.
// The issuer's proof of knowledge does not cover these bases, so a key with
// repeated bases otherwise passes Check.
func TestFindingIssuerPublicKeyCheckRepeatedBases(t *testing.T) {
	for _, e := range envs {
		f := newFindingFx(t, e)
		c := f.curve
		require.NoError(t, proto.Clone(f.key.Ipk).(*IssuerPublicKey).Check(c, f.tr))

		for name, set := range map[string]func(*IssuerPublicKey){
			"HRand=HSk":           func(k *IssuerPublicKey) { k.HRand = k.HSk },
			"HAttrs[0]=HSk":       func(k *IssuerPublicKey) { k.HAttrs[0] = k.HSk },
			"HAttrs[3]=HRand":     func(k *IssuerPublicKey) { k.HAttrs[3] = k.HRand },
			"HAttrs[1]=HAttrs[2]": func(k *IssuerPublicKey) { k.HAttrs[1] = k.HAttrs[2] },
		} {
			k := proto.Clone(f.key.Ipk).(*IssuerPublicKey)
			set(k)
			err := k.Check(c, f.tr)
			require.Error(t, err, "issuer key with %s must be rejected", name)
			require.Contains(t, err.Error(), "not pairwise distinct", name)
		}

		// a missing HAttrs entry is still rejected
		k := proto.Clone(f.key.Ipk).(*IssuerPublicKey)
		k.HAttrs[2] = nil
		require.Error(t, k.Check(c, f.tr), "issuer key with a nil HAttrs entry must be rejected")
	}
}
