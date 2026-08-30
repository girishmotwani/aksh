package watch

import (
	"sync"
	"testing"
	"time"

	v1alpha1 "github.com/girishmotwani/aksh/api/v1alpha1"
	"github.com/girishmotwani/aksh/internal/policy"
)

// mustSnapshot compiles a snapshot from the given policies using the real
// policy.Compile so tests exercise genuine immutable snapshots.
func mustSnapshot(t *testing.T, policies ...v1alpha1.AkshPolicy) policy.PolicySnapshot {
	t.Helper()
	snap, err := policy.Compile(policies)
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	return snap
}

// allowPolicy builds a minimal valid AkshPolicy with one Allow rule to a host.
func allowPolicy(name, host string) v1alpha1.AkshPolicy {
	p := v1alpha1.AkshPolicy{}
	p.Name = name
	p.Namespace = "default"
	p.Spec.Egress.Rules = []v1alpha1.EgressRule{
		{Name: "r-" + name, To: v1alpha1.HostMatch{Host: host}},
	}
	return p
}

func TestStoreCurrent_BeforeSwap_ReturnsZeroAgeFalseNoPanic(t *testing.T) {
	var s Store
	snap, age, ok := s.Current()
	if snap != nil || age != 0 || ok {
		t.Fatalf("Current() = (%v, %v, %v), want (nil, 0, false)", snap, age, ok)
	}
}

func TestStoreFresh_BeforeSwap_ReturnsZeroFalseNoPanic(t *testing.T) {
	var s Store
	snap, ok := s.Fresh(45 * time.Second)
	if snap != nil || ok {
		t.Fatalf("Fresh() = (%v, %v), want (nil, false)", snap, ok)
	}
}

func TestStoreSwap_PublishesSnapshotAndAge(t *testing.T) {
	var s Store
	snap := mustSnapshot(t, allowPolicy("a", "example.com"))
	s.Swap(snap, time.Now())
	got, age, ok := s.Current()
	if !ok {
		t.Fatalf("Current() ok = false, want true")
	}
	if got.Version() != snap.Version() {
		t.Fatalf("Current() version = %q, want %q", got.Version(), snap.Version())
	}
	if age < 0 {
		t.Fatalf("Current() age = %v, want non-negative", age)
	}
}

func TestStoreFresh_AgeBelowMaxStaleness_ReturnsSnapshotTrue(t *testing.T) {
	var s Store
	snap := mustSnapshot(t, allowPolicy("a", "example.com"))
	s.Swap(snap, time.Now().Add(-44999*time.Millisecond))
	got, ok := s.Fresh(45 * time.Second)
	if !ok {
		t.Fatalf("Fresh(45s) ok = false, want true for age 44.999s")
	}
	if got == nil || got.Version() != snap.Version() {
		t.Fatalf("Fresh returned wrong snapshot: %v", got)
	}
}

func TestStoreFresh_AgeEqualMaxStaleness_ReturnsFalse(t *testing.T) {
	var s Store
	snap := mustSnapshot(t, allowPolicy("a", "example.com"))
	s.Swap(snap, time.Now().Add(-45*time.Second))
	got, ok := s.Fresh(45 * time.Second)
	if ok || got != nil {
		t.Fatalf("Fresh(45s) = (%v, %v), want (nil, false) at exactly 45s (fail-closed)", got, ok)
	}
}

func TestStoreFresh_AgeAboveMaxStaleness_ReturnsFalse(t *testing.T) {
	var s Store
	snap := mustSnapshot(t, allowPolicy("a", "example.com"))
	s.Swap(snap, time.Now().Add(-46*time.Second))
	got, ok := s.Fresh(45 * time.Second)
	if ok || got != nil {
		t.Fatalf("Fresh(45s) = (%v, %v), want (nil, false) above 45s", got, ok)
	}
}

// TestStoreFresh_FuturePublishTime_TreatedAsStale proves the fail-closed guard
// against clock anomalies (wall-clock rollback or a future publish time). A
// future publication time yields a negative monotonic age; Fresh must treat it
// as stale rather than clamping to fresh, so a corrupted/rolled-back clock can
// never bypass the staleness gate and serve an old snapshot indefinitely.
func TestStoreFresh_FuturePublishTime_TreatedAsStale(t *testing.T) {
	var s Store
	snap := mustSnapshot(t, allowPolicy("a", "example.com"))
	s.Swap(snap, time.Now().Add(1*time.Hour)) // published "in the future"
	if got, ok := s.Fresh(45 * time.Second); ok || got != nil {
		t.Fatalf("Fresh(45s) = (%v, %v), want (nil, false) for a future/negative-age snapshot (fail-closed)", got, ok)
	}
}

// TestStoreCurrent_FuturePublishTime_ReturnsRawNegativeAge proves Current() does
// NOT clamp a negative age to zero. Clamping would disguise a rolled-back or
// corrupted publication time as fresh (age 0) for one-sided `age >= maxStaleness`
// consumers (e.g. the request-path match stage), a fail-open. Current must
// surface the raw negative age so such consumers can fail closed.
func TestStoreCurrent_FuturePublishTime_ReturnsRawNegativeAge(t *testing.T) {
	var s Store
	snap := mustSnapshot(t, allowPolicy("a", "example.com"))
	s.Swap(snap, time.Now().Add(1*time.Hour)) // published "in the future"
	_, age, ok := s.Current()
	if !ok {
		t.Fatalf("Current() ok = false, want true after Swap")
	}
	if age >= 0 {
		t.Fatalf("Current() age = %v, want a negative (unclamped) age for a future publish time", age)
	}
}

func TestStoreSwap_ConcurrentReadersSeeOldOrNewSnapshot(t *testing.T) {
	var s Store
	oldSnap := mustSnapshot(t, allowPolicy("old", "old.example.com"))
	newSnap := mustSnapshot(t, allowPolicy("new", "new.example.com"))
	s.Swap(oldSnap, time.Now())

	valid := map[string]bool{oldSnap.Version(): true, newSnap.Version(): true}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				snap, _, ok := s.Current()
				if !ok || snap == nil {
					t.Errorf("Current() returned no snapshot during concurrent swap")
					return
				}
				if !valid[snap.Version()] {
					t.Errorf("Current() returned partial/unknown snapshot version %q", snap.Version())
					return
				}
			}
		}()
	}
	for i := 0; i < 2000; i++ {
		s.Swap(newSnap, time.Now())
		s.Swap(oldSnap, time.Now())
	}
	close(stop)
	wg.Wait()
}

// TestStoreSwap_ConcurrentReaders_VersionAndAgePairConsistent proves the fix for
// the torn (snapshot, timestamp) publication: each version is swapped with a
// distinct, well-separated backdated timestamp, and concurrent readers assert
// the observed version always pairs with an age in that version's band. Under a
// non-atomic two-field Store a reader could see the new version with the old
// timestamp (or vice versa); publishing both behind one atomic cell makes that
// impossible.
func TestStoreSwap_ConcurrentReaders_VersionAndAgePairConsistent(t *testing.T) {
	var s Store
	freshSnap := mustSnapshot(t, allowPolicy("fresh", "fresh.example.com"))
	agedSnap := mustSnapshot(t, allowPolicy("aged", "aged.example.com"))
	if freshSnap.Version() == agedSnap.Version() {
		t.Fatalf("test setup: snapshots must have distinct versions")
	}
	const agedOffset = 30 * time.Second
	const band = 15 * time.Second

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				snap, age, ok := s.Current()
				if !ok || snap == nil {
					continue
				}
				switch snap.Version() {
				case freshSnap.Version():
					if age >= band {
						t.Errorf("fresh snapshot paired with aged timestamp: age=%v", age)
						return
					}
				case agedSnap.Version():
					if age < band {
						t.Errorf("aged snapshot paired with fresh timestamp: age=%v", age)
						return
					}
				default:
					t.Errorf("unknown snapshot version %q", snap.Version())
					return
				}
			}
		}()
	}
	for i := 0; i < 5000; i++ {
		s.Swap(freshSnap, time.Now())
		s.Swap(agedSnap, time.Now().Add(-agedOffset))
	}
	close(stop)
	wg.Wait()
}

func TestStoreFresh_ConcurrentReadersAndSwap_NoRace(t *testing.T) {
	var s Store
	snap := mustSnapshot(t, allowPolicy("a", "example.com"))
	s.Swap(snap, time.Now())

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = s.Fresh(45 * time.Second)
				_, _, _ = s.Current()
			}
		}()
	}
	for i := 0; i < 5000; i++ {
		s.Swap(snap, time.Now())
	}
	close(stop)
	wg.Wait()
}
