// Package ratelimit throttles submissions per credential.
//
// Limits are enforced per process, not cluster-wide. That is a deliberate
// simplification for a mono-tenant deployment: a Postgres- or Redis-backed
// counter would make every submission pay a round trip to protect against an
// abuse case that a single instance already bounds. It is documented as
// per-instance rather than pretended to be global.
package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Limiter holds one token bucket per credential, bounded in size.
//
// The bound matters: keying a map on a client-supplied value with no ceiling is
// how a rate limiter becomes the memory-exhaustion vector it was meant to
// prevent.
type Limiter struct {
	maxEntries int
	// idleTTL evicts buckets for credentials that have gone quiet, so a
	// long-running process does not accumulate them forever.
	idleTTL time.Duration
	now     func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	limiter  *rate.Limiter
	lastSeen time.Time
	// rps and burst are recorded so a changed per-credential override rebuilds
	// the bucket instead of silently keeping the old rate.
	rps   float64
	burst int
}

// Options configures a Limiter.
type Options struct {
	// MaxEntries caps the number of tracked keys. Zero uses a sane default.
	MaxEntries int
	// IdleTTL is how long an unused bucket is kept. Zero uses a sane default.
	IdleTTL time.Duration
	// Now is injectable for tests.
	Now func() time.Time
}

// New builds a Limiter.
func New(opts Options) *Limiter {
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = 10000
	}
	if opts.IdleTTL <= 0 {
		opts.IdleTTL = time.Hour
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Limiter{
		maxEntries: opts.MaxEntries,
		idleTTL:    opts.IdleTTL,
		now:        opts.Now,
		buckets:    make(map[string]*bucket),
	}
}

// Allow reports whether one event is permitted for key at the given rate.
//
// The rate is supplied per call because it comes from the credential's own
// configuration, which an admin can change while the process is running.
func (l *Limiter) Allow(key string, rps float64, burst int) bool {
	if rps <= 0 || burst <= 0 {
		// A zero rate would silently allow everything through a
		// rate.NewLimiter(0, 0), which is the opposite of what a caller asking
		// for "no rate" means. Refuse instead.
		return false
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	entry, ok := l.buckets[key]

	switch {
	case ok && entry.rps == rps && entry.burst == burst:
		entry.lastSeen = now
	case ok:
		// The configured rate changed: rebuild rather than carry stale tokens.
		entry.limiter = rate.NewLimiter(rate.Limit(rps), burst)
		entry.rps, entry.burst, entry.lastSeen = rps, burst, now
	default:
		l.evictLocked(now)
		entry = &bucket{
			limiter:  rate.NewLimiter(rate.Limit(rps), burst),
			lastSeen: now,
			rps:      rps,
			burst:    burst,
		}
		l.buckets[key] = entry
	}

	return entry.limiter.AllowN(now, 1)
}

// Len reports how many keys are currently tracked.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// evictLocked makes room for a new key. It first drops idle buckets, and only if
// that is not enough falls back to dropping an arbitrary one.
//
// Evicting a bucket resets its client's budget, which is the safe direction to
// be wrong in only because the map bound is itself a protection: an attacker who
// could force evictions to reset their own budget would need to cycle through
// MaxEntries distinct credentials, each of which had to be created by an admin.
func (l *Limiter) evictLocked(now time.Time) {
	if len(l.buckets) < l.maxEntries {
		return
	}

	for key, entry := range l.buckets {
		if now.Sub(entry.lastSeen) > l.idleTTL {
			delete(l.buckets, key)
		}
	}
	if len(l.buckets) < l.maxEntries {
		return
	}

	// Still full: drop the least recently seen, which is the closest thing to a
	// fair choice without maintaining a heap.
	var oldestKey string
	var oldest time.Time
	for key, entry := range l.buckets {
		if oldestKey == "" || entry.lastSeen.Before(oldest) {
			oldestKey, oldest = key, entry.lastSeen
		}
	}
	if oldestKey != "" {
		delete(l.buckets, oldestKey)
	}
}
