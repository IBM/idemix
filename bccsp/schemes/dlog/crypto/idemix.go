/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Deprecated: Package idemix implements the legacy CL-signature based scheme.
// It will be removed in Phase 6 of the modernization plan. Use
// bccsp/schemes/aries (BBS+) instead.
package idemix

import (
	math "github.com/IBM/mathlib"
)

type Idemix struct {
	Curve      *math.Curve
	Translator Translator
}
