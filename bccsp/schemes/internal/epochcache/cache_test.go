/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package epochcache

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewKeyIsInjectiveOnFieldBoundaries(t *testing.T) {
	k1, k2 := NewKey([]byte("a"), []byte("b")), NewKey([]byte("a"), []byte("b"))
	require.Equal(t, k1, k2)
	require.NotEqual(t, NewKey([]byte("ab"), []byte("")), NewKey([]byte("a"), []byte("b")))
	require.NotEqual(t, NewKey([]byte("ab")), NewKey([]byte("a"), []byte("b")))
	require.NotEqual(t, NewKey(nil), NewKey())
}

func TestCacheGetAdd(t *testing.T) {
	var c Cache[int]
	k1, k2 := NewKey([]byte("1")), NewKey([]byte("2"))

	_, ok := c.Get(k1)
	require.False(t, ok)

	c.Add(k1, 1)
	v, ok := c.Get(k1)
	require.True(t, ok)
	require.Equal(t, 1, v)

	_, ok = c.Get(k2)
	require.False(t, ok)

	// re-adding a key replaces its value and does not grow the cache
	c.Add(k1, 11)
	require.Equal(t, 1, c.Len())
	v, _ = c.Get(k1)
	require.Equal(t, 11, v)
}

func TestCacheIsBoundedLRU(t *testing.T) {
	c := New[int](3)
	key := func(i int) Key { return NewKey(fmt.Appendf(nil, "%d", i)) }

	for i := range 3 {
		c.Add(key(i), i)
	}
	// touch 0, so that 1 is the least recently used
	_, ok := c.Get(key(0))
	require.True(t, ok)

	c.Add(key(3), 3)
	require.Equal(t, 3, c.Len())
	_, ok = c.Get(key(1))
	require.False(t, ok, "least recently used entry must be evicted")
	for _, i := range []int{0, 2, 3} {
		v, ok := c.Get(key(i))
		require.True(t, ok)
		require.Equal(t, i, v)
	}

	var d Cache[int]
	for i := range 10 * DefaultSize {
		d.Add(key(i), i)
	}
	require.Equal(t, DefaultSize, d.Len())
}

func TestCacheConcurrentUse(t *testing.T) {
	c := New[int](4)
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for i := range 200 {
				k := NewKey(fmt.Appendf(nil, "%d", (g+i)%6))
				c.Add(k, i)
				c.Get(k)
				require.LessOrEqual(t, c.Len(), 4)
			}
		})
	}
	wg.Wait()
	require.LessOrEqual(t, c.Len(), 4)
}
