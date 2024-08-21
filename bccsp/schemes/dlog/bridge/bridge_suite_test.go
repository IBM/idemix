/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package bridge_test

import (
	"io"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestPlain(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Plain Suite")
}

// NewRandPanic is an utility test function that always panic when invoked
func NewRandPanic() io.Reader {
	panic("new rand panic")
}
