package ratelimit

import (
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestAllowRespectsBurstThenRate(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(Options{Now: func() time.Time { return now }})

	// The burst is spent first, all at the same instant.
	for i := range 5 {
		if !l.Allow("cred", 10, 5) {
			t.Fatalf("call %d was refused inside the burst", i+1)
		}
	}
	if l.Allow("cred", 10, 5) {
		t.Fatal("the call past the burst was allowed with no time elapsed")
	}

	// At 10 rps one token accrues every 100ms.
	now = now.Add(100 * time.Millisecond)
	if !l.Allow("cred", 10, 5) {
		t.Fatal("a token should have accrued after 100ms")
	}
	if l.Allow("cred", 10, 5) {
		t.Fatal("only one token should have accrued")
	}
}

func TestAllowIsPerKey(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(Options{Now: func() time.Time { return now }})

	if !l.Allow("a", 1, 1) {
		t.Fatal("first call for a was refused")
	}
	if l.Allow("a", 1, 1) {
		t.Fatal("second call for a should be refused")
	}
	// Exhausting one credential must not affect another.
	if !l.Allow("b", 1, 1) {
		t.Fatal("credential b was refused because a was exhausted")
	}
}

// A zero or negative rate must refuse, not allow everything. rate.NewLimiter(0,0)
// would silently permit nothing or everything depending on how it is called, so
// the guard is explicit.
func TestAllowRefusesNonPositiveRates(t *testing.T) {
	l := New(Options{})
	for _, tc := range []struct {
		rps   float64
		burst int
	}{
		{0, 10}, {-1, 10}, {10, 0}, {10, -1}, {0, 0},
	} {
		if l.Allow("cred", tc.rps, tc.burst) {
			t.Fatalf("Allow(rps=%v, burst=%d) permitted an event", tc.rps, tc.burst)
		}
	}
}

// An admin lowering a credential's limit must take effect immediately, not after
// the old bucket happens to drain.
func TestChangedRateRebuildsBucket(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(Options{Now: func() time.Time { return now }})

	for range 100 {
		l.Allow("cred", 1000, 100)
	}
	// The generous bucket is now empty.
	if l.Allow("cred", 1000, 100) {
		t.Fatal("the bucket should be empty")
	}

	// A new configuration rebuilds it with a fresh burst.
	if !l.Allow("cred", 5, 5) {
		t.Fatal("a changed rate should rebuild the bucket")
	}
	if l.Len() != 1 {
		t.Fatalf("Len = %d, want 1: the bucket should be replaced, not duplicated", l.Len())
	}
}

// The map is keyed on a credential id and must never grow without bound.
func TestEvictionBoundsMemory(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(Options{MaxEntries: 10, IdleTTL: time.Minute, Now: func() time.Time { return now }})

	for i := range 100 {
		l.Allow("cred-"+strconv.Itoa(i), 10, 5)
	}
	if got := l.Len(); got > 10 {
		t.Fatalf("Len = %d, want at most 10", got)
	}
}

func TestIdleBucketsAreEvictedFirst(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(Options{MaxEntries: 3, IdleTTL: time.Minute, Now: func() time.Time { return now }})

	l.Allow("old-1", 10, 5)
	l.Allow("old-2", 10, 5)

	// Both are now idle.
	now = now.Add(2 * time.Minute)
	l.Allow("fresh", 10, 5)

	// Adding a fourth key must reclaim the idle ones rather than the fresh one.
	l.Allow("newest", 10, 5)
	if l.Len() > 3 {
		t.Fatalf("Len = %d, want at most 3", l.Len())
	}

	// "fresh" was used recently, so its budget must be intact: it had 5 burst and
	// used 1, so 4 more calls must succeed.
	for i := range 4 {
		if !l.Allow("fresh", 10, 5) {
			t.Fatalf("the recently used bucket lost its budget at call %d", i+1)
		}
	}
}

func TestConcurrentUseIsSafe(t *testing.T) {
	l := New(Options{})

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for range 20 {
				l.Allow("cred-"+strconv.Itoa(i%5), 1000, 1000)
			}
		}(i)
	}
	wg.Wait()

	if got := l.Len(); got != 5 {
		t.Fatalf("Len = %d, want 5", got)
	}
}

// The exact accounting matters: a limiter that allows burst+1 events at once
// would let a compromised credential send more than an operator configured.
func TestAllowCountIsExact(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(Options{Now: func() time.Time { return now }})

	allowed := 0
	for range 1000 {
		if l.Allow("cred", 100, 20) {
			allowed++
		}
	}
	if allowed != 20 {
		t.Fatalf("%d events allowed with no time elapsed, want exactly the burst of 20", allowed)
	}
}
