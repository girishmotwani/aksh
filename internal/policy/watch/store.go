// Package watch provides an atomic policy-snapshot Store and a namespaced
// client-go Watcher that keeps the Store current from AkshPolicy CRD changes.
//
// The Store is a lock-free, read-optimised holder of the latest immutable
// policy.PolicySnapshot. Readers on the request hot path call Current/Fresh
// without blocking; the Watcher publishes new snapshots via Swap.
package watch

import (
	"sync/atomic"
	"time"

	"github.com/girishmotwani/aksh/internal/policy"
)

// cell is the immutable (snapshot, publication-time) pair published atomically
// by Swap. Publishing both fields behind a single atomic.Value guarantees that
// a reader never observes a new snapshot paired with a stale timestamp (or vice
// versa) -- the two values move together or not at all.
//
// updated is stored as a time.Time (not stripped unix nanos) so that age is
// computed via time.Since, which uses Go's monotonic clock reading. This makes
// the staleness gate immune to wall-clock jumps (NTP step, VM migration): a
// backward clock movement can never make a stale snapshot look fresh.
type cell struct {
	snapshot policy.PolicySnapshot
	updated  time.Time // publication time, carrying a monotonic reading
}

// Store holds the current immutable policy snapshot and the time it was
// published. It is safe for concurrent use: readers never block writers.
//
// Age is measured with the monotonic clock (via now, defaulting to time.Now);
// callers control the effective age either by passing a backdated now to Swap
// (time.Now().Add(-d) keeps the monotonic reading) or, in tests, by injecting a
// deterministic now clock shared with the watcher so the staleness boundary can
// be crossed without real-time sleeps (honouring the UT spec's "with a fake
// clock" contract).
type Store struct {
	current atomic.Value // holds *cell; nil until the first Swap
	// now is the age-measurement clock. A nil value means time.Now. It is an
	// unexported test seam (mirroring the watcher's now): production never sets
	// it, so age is measured with the real monotonic clock.
	now func() time.Time
}

// clock returns the store's age-measurement time. It defaults to the real
// monotonic time.Now when no clock has been injected.
func (s *Store) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// load returns the current snapshot and its raw (unclamped, possibly negative)
// monotonic age. A negative age can only arise from a non-monotonic publication
// time combined with a wall-clock rollback; callers decide how to treat it.
func (s *Store) load() (policy.PolicySnapshot, time.Duration, bool) {
	v := s.current.Load()
	if v == nil {
		return nil, 0, false
	}
	c, ok := v.(*cell)
	if !ok || c == nil || c.snapshot == nil {
		return nil, 0, false
	}
	return c.snapshot, s.clock().Sub(c.updated), true
}

// Current returns the latest snapshot, its age since publication, and whether a
// snapshot has ever been published. A never-swapped (zero-value) Store returns
// (nil, 0, false) and never panics on the unset atomic.Value. The snapshot and
// its age are always read from the same atomically-published cell, so the pair
// is never torn. The age is returned raw (unclamped): under a clock anomaly it
// may be negative, and callers making a security decision MUST treat age < 0 as
// stale (or use Fresh, which already does). Clamping negative ages here would
// disguise a rolled-back/corrupted publication time as fresh (fail-open) for
// one-sided `age >= maxStaleness` consumers.
func (s *Store) Current() (policy.PolicySnapshot, time.Duration, bool) {
	return s.load()
}

// Fresh returns the current snapshot only when its age is strictly less than
// maxStaleness. The boundary is fail-closed: an age exactly equal to (or greater
// than) maxStaleness is treated as stale, and callers must deny all requests. A
// negative age (a clock anomaly the monotonic clock should preclude) is also
// treated as stale so a corrupted timestamp can never bypass the staleness gate.
func (s *Store) Fresh(maxStaleness time.Duration) (policy.PolicySnapshot, bool) {
	snap, age, ok := s.load()
	if !ok {
		return nil, false
	}
	if age < 0 || age >= maxStaleness {
		return nil, false
	}
	return snap, true
}

// Swap atomically publishes snapshot and records now as its publication time.
// A nil snapshot is ignored so the store is never cleared once populated
// (retain-last-good). now is stored verbatim, letting callers simulate age.
// The snapshot and its timestamp are published together as a single *cell, so
// concurrent readers never observe a torn (new snapshot, old time) pair.
func (s *Store) Swap(snapshot policy.PolicySnapshot, now time.Time) {
	if snapshot == nil {
		return
	}
	s.current.Store(&cell{snapshot: snapshot, updated: now})
}
