/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package amcl

import (
	"encoding/hex"
	"testing"

	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/require"
)

// FINDING-TR-G2: the FP256BN translator's G2FromProto (used for the dlog issuer key W and for
// the revocation epoch public key) only rejects the identity; it accepts a point that is on
// the sextic twist but outside the order-r subgroup, since mathlib's AMCL G2 decoder performs
// no subgroup check (see internal/mathlibfindings TestFindingG2NoSubgroupCheck).
func TestFindingFp256bnG2FromProtoAcceptsPointOutsideSubgroup(t *testing.T) {
	c := math.Curves[math.FP256BN_AMCL]
	h := func(s string) []byte {
		b, err := hex.DecodeString(s)
		require.NoError(t, err)

		return b
	}
	proto := &ECP2{
		Xa: h("0000000000000000000000000000000000000000000000000000000000000001"),
		Xb: h("0000000000000000000000000000000000000000000000000000000000000000"),
		Ya: h("c8931067e59cbf08d406b44ddde32960f67bcad8fe69bc5e469e9ba74ccc1225"),
		Yb: h("a646cec84f20954d589dba3331ab71ba4321d1663c8aea6da59fb69d261559ca"),
	}

	p, err := (&Fp256bn{C: c}).G2FromProto(proto)
	if err == nil {
		require.False(t, p.Mul(c.GroupOrder).Equals(c.NewG2()), "sanity: the point must be outside G2")
	}
	require.Error(t, err, "a G2 point outside the order-r subgroup must be rejected")
}
