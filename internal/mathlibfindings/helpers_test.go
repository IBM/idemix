/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package mathlibfindings contains regression tests for security findings in
// github.com/IBM/mathlib. Every test asserts the correct/safe behaviour and is
// therefore expected to FAIL against the currently pinned mathlib version
// until the corresponding issue is fixed upstream.
package mathlibfindings

import (
	"math/big"
	"testing"

	math "github.com/IBM/mathlib"
)

// forEachCurve runs f as a subtest for every curve exposed by mathlib.
func forEachCurve(t *testing.T, f func(t *testing.T, c *math.Curve)) {
	t.Helper()
	for _, c := range math.Curves {
		t.Run(math.CurveIDToString(c.ID()), func(t *testing.T) {
			f(t, c)
		})
	}
}

// enc32 returns the 32-byte big-endian encoding of x.
func enc32(x *big.Int) []byte {
	return x.FillBytes(make([]byte, 32))
}

// order returns the group order of c as a fresh big.Int.
func order(c *math.Curve) *big.Int {
	return new(big.Int).Set(c.GroupOrder.BigInt())
}
