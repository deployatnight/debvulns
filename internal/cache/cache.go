// Package cache is the shared, lock-protected holder of the latest scan
// Result for the Prometheus exporter.
//
// The lock is held only for the single pointer swap in Update(), never during
// network I/O, so the critical section is sub-microsecond and HTTP scrapes
// are never blocked by a slow refresh. Get() returns nil until the first
// scan has completed, which is the signal that /metrics should return 503.
package cache

import (
	"sync"

	"github.com/deployatnight/debvulns/internal/scan"
)

// Cache is a thread-safe container for the latest *scan.Result.
type Cache struct {
	mu   sync.RWMutex
	data *scan.Result
}

// New returns an empty Cache.
func New() *Cache { return &Cache{} }

// Update atomically replaces the cached snapshot.
func (c *Cache) Update(r *scan.Result) {
	c.mu.Lock()
	c.data = r
	c.mu.Unlock()
}

// Get returns the latest snapshot, or nil if no scan has completed yet.
func (c *Cache) Get() *scan.Result {
	c.mu.RLock()
	r := c.data
	c.mu.RUnlock()
	return r
}
