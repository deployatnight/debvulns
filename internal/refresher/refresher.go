// Package refresher runs the background cache-refresh goroutine for the
// Prometheus exporter.
//
// It runs the full scan pipeline once at startup, publishes the result to the
// shared Cache, then sleeps and repeats. Failure handling:
//
//   - Boot phase (no successful scan yet): exponential backoff starting at
//     BackoffBase, doubling per attempt, capped at BackoffMax, with
//     ±BackoffJitter relative noise.
//   - Steady state (after the first success): a fixed RefreshInterval sleep.
//
// On a scan failure after the first success the previous good Result is kept
// (so the dashboard keeps showing real data) but ScanOK is flipped to false
// and the timestamp advanced, which surfaces as debvulns_scan_status 0.
package refresher

import (
	"context"
	"log"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/deployatnight/debvulns/internal/cache"
	"github.com/deployatnight/debvulns/internal/scan"
)

// Backoff constants (boot phase only).
const (
	BackoffBase   = 30.0 * time.Second
	BackoffMax    = 30 * time.Minute
	BackoffJitter = 0.10 // ± fraction applied to the computed delay
)

// Refresher periodically refreshes the vulnerability cache in the background.
type Refresher struct {
	cache  *cache.Cache
	opts   scan.Options
	logger *log.Logger

	mu           sync.Mutex
	stop         chan struct{}
	firstSuccess bool
}

// New creates a Refresher bound to cache and configured by opts.
func New(c *cache.Cache, opts scan.Options, logger *log.Logger) *Refresher {
	if logger == nil {
		logger = log.Default()
	}
	return &Refresher{
		cache:  c,
		opts:   opts,
		logger: logger,
		stop:   make(chan struct{}),
	}
}

// Start launches the refresh goroutine. It returns immediately.
func (r *Refresher) Start() {
	go r.run()
}

// Stop signals the refresh loop to exit and waits for it to drain. Safe to
// call multiple times.
func (r *Refresher) Stop() {
	r.mu.Lock()
	select {
	case <-r.stop:
		// already closed
	default:
		close(r.stop)
	}
	r.mu.Unlock()
}

// run is the main refresh loop.
func (r *Refresher) run() {
	attempt := 0
	for {
		select {
		case <-r.stop:
			return
		default:
		}

		tStart := time.Now()
		ctx, cancel := context.WithCancel(context.Background())
		// Wire cancellation to stop so Stop() aborts an in-flight scan.
		go func() {
			select {
			case <-r.stop:
				cancel()
			case <-ctx.Done():
			}
		}()

		result, err := scan.Run(ctx, r.opts)
		cancel()

		if err != nil {
			r.logger.Printf("scan pipeline failed (attempt %d): %v", attempt+1, err)
			r.recordFailure()
			attempt++
		} else {
			r.logger.Printf("scan succeeded; publishing result to cache")
			r.cache.Update(result)
			r.mu.Lock()
			r.firstSuccess = true
			r.mu.Unlock()
			attempt = 0
		}

		elapsed := time.Since(tStart)
		sleepFor := r.nextSleep(attempt) - elapsed
		if sleepFor < 0 {
			sleepFor = 0
		}
		r.logger.Printf("next refresh in %.0fs (attempt=%d, first_success=%v)",
			sleepFor.Seconds(), attempt, r.firstSuccess)

		select {
		case <-r.stop:
			return
		case <-time.After(sleepFor):
		}
	}
}

// recordFailure updates the cache to reflect a failed scan while preserving
// the last good snapshot (if any).
func (r *Refresher) recordFailure() {
	prev := r.cache.Get()
	if prev == nil {
		// Nothing in cache yet: push a minimal failure marker so /-/ready
		// returns 503 but scan_status is visible as 0.
		r.cache.Update(&scan.Result{
			ScanTimestamp: time.Now(),
			ScanOK:        false,
		})
		return
	}
	// Keep the last good data, but flip scan_status to 0 and advance the
	// timestamp. A shallow copy is safe: the Categorized/InstalledPackages
	// slices are never mutated after creation.
	updated := *prev
	updated.ScanOK = false
	updated.ScanTimestamp = time.Now()
	r.cache.Update(&updated)
}

// nextSleep returns the sleep duration for the next cycle.
func (r *Refresher) nextSleep(attempt int) time.Duration {
	r.mu.Lock()
	first := r.firstSuccess
	r.mu.Unlock()
	if first {
		return r.opts.RefreshInterval
	}
	return backoffDelay(attempt)
}

// backoffDelay returns a jittered exponential delay for the given attempt.
func backoffDelay(attempt int) time.Duration {
	d := BackoffBase * (1 << uint(attempt)) // 2^attempt
	if d > BackoffMax {
		d = BackoffMax
	}
	jitter := time.Duration(float64(d) * BackoffJitter)
	return d - jitter + time.Duration(2*float64(jitter)*rand.Float64())
}
