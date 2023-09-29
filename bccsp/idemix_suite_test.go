/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package idemix_test

import (
	"testing"

	math "github.com/IBM/mathlib"
	"github.com/ale-linux/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestPlain(t *testing.T) {
	bbs12381g2pub.SetCurve(math.Curves[math.BLS12_381_BBS])
	RegisterFailHandler(Fail)
	RunSpecs(t, "Plain Suite")
}
