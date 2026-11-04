/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package epochcache provides a small bounded LRU cache for verified revocation epoch public keys.
// Callers must only Add inputs that verified successfully.
package epochcache

import (
	"crypto/sha256"
	"encoding/binary"
	"sync"
)

// DefaultSize is the number of entries kept by a zero-value Cache.
const DefaultSize = 16

// Key is the SHA-256 digest of the verification inputs.
type Key [sha256.Size]byte

// NewKey hashes the length-prefixed fields.
func NewKey(fields ...[]byte) Key {
	h := sha256.New()
	var l [8]byte
	for _, f := range fields {
		binary.BigEndian.PutUint64(l[:], uint64(len(f)))
		h.Write(l[:])
		h.Write(f)
	}

	var k Key
	h.Sum(k[:0])

	return k
}

type entry[V any] struct {
	key Key
	val V
}

// Cache is a concurrency-safe LRU cache; the zero value holds DefaultSize entries.
type Cache[V any] struct {
	mu   sync.Mutex
	size int
	// entries is ordered from least to most recently used.
	entries []entry[V]
}

// New returns a cache holding up to size entries (DefaultSize if size <= 0).
func New[V any](size int) *Cache[V] {
	return &Cache[V]{size: size}
}

func (c *Cache[V]) capacity() int {
	if c.size <= 0 {
		return DefaultSize
	}

	return c.size
}

// Get returns the value stored under k, marking it as most recently used.
func (c *Cache[V]) Get(k Key) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i := range c.entries {
		if c.entries[i].key == k {
			e := c.entries[i]
			copy(c.entries[i:], c.entries[i+1:])
			c.entries[len(c.entries)-1] = e

			return e.val, true
		}
	}

	var zero V

	return zero, false
}

// Add stores v under k as the most recently used entry, evicting the least
// recently used entry if the cache is full.
func (c *Cache[V]) Add(k Key, v V) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i := range c.entries {
		if c.entries[i].key == k {
			copy(c.entries[i:], c.entries[i+1:])
			c.entries[len(c.entries)-1] = entry[V]{key: k, val: v}

			return
		}
	}

	if len(c.entries) >= c.capacity() {
		copy(c.entries, c.entries[1:])
		c.entries = c.entries[:len(c.entries)-1]
	}
	c.entries = append(c.entries, entry[V]{key: k, val: v})
}

// Len returns the number of entries currently stored.
func (c *Cache[V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.entries)
}
