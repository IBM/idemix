/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs

import (
	"sync"
	"testing"

	ml "github.com/IBM/mathlib"
	"github.com/stretchr/testify/require"
)

func TestFrFromOKMConcurrent(t *testing.T) {
	message := []byte("test message")

	for i, curve := range ml.Curves {
		const workers = 16
		results := make([]*ml.Zr, workers)

		var wg sync.WaitGroup
		wg.Add(workers)
		for w := range workers {
			go func(w int) {
				defer wg.Done()
				results[w] = FrFromOKM(message, curve)
			}(w)
		}
		wg.Wait()

		expected := FrFromOKM(message, curve)
		for w, r := range results {
			require.True(t, expected.Equals(r), "curve %d, worker %d", i, w)
		}
	}
}
