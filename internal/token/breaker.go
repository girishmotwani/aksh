package token

import (
	"sync"
	"time"
)

// Breaker guards acquisition calls after repeated transient failures.
type Breaker struct {
	mu            sync.Mutex
	threshold     int
	probeInterval time.Duration
	failures      int
	open          bool
	lastFailure   time.Time
	probeInFlight bool
}

// NewBreaker creates a breaker with the given transient failure threshold and probe interval.
func NewBreaker(threshold, probeIntervalSec int) *Breaker {
	if threshold <= 0 {
		threshold = 1
	}
	if probeIntervalSec < 0 {
		probeIntervalSec = 0
	}
	return &Breaker{
		threshold:     threshold,
		probeInterval: time.Duration(probeIntervalSec) * time.Second,
	}
}

// IsOpen reports whether the breaker is open.
func (b *Breaker) IsOpen() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.open
}

// AllowRequest reports whether the next acquisition request may proceed.
func (b *Breaker) AllowRequest() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.open {
		return true
	}
	if b.probeInFlight {
		return false
	}
	if time.Since(b.lastFailure) < b.probeInterval {
		return false
	}

	// Reserve the half-open probe while holding the lock so concurrent callers
	// cannot all interpret the elapsed interval as permission to probe.
	b.probeInFlight = true
	return true
}

// RecordFailure records a failed acquisition attempt.
func (b *Breaker) RecordFailure(class AcquireErrorClass) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Any completed attempt releases a reserved probe, but only transient
	// failures describe provider health and therefore count toward opening.
	b.probeInFlight = false
	if class != AcquireErrorTransient {
		return
	}

	b.failures++
	b.lastFailure = time.Now()
	if b.failures >= b.threshold {
		b.open = true
	}
}

// RecordSuccess records a successful acquisition attempt.
func (b *Breaker) RecordSuccess() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.failures = 0
	b.open = false
	b.lastFailure = time.Time{}
	b.probeInFlight = false
}
