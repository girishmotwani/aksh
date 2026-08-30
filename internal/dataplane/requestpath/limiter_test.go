package requestpath_test

import (
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/dataplane/requestpath"
)

func TestNewLimiter_PositiveN_ReturnsUsableLimiterWithZeroInFlight(t *testing.T) {
	limiter := requestpath.NewLimiter(2)
	if limiter == nil {
		t.Fatal("NewLimiter() = nil, want non-nil")
	}
	if got := limiter.InFlight(); got != 0 {
		t.Fatalf("InFlight() = %d, want 0", got)
	}
}

func TestNewLimiter_NonPositiveCapacity_ClampsToOne(t *testing.T) {
	for _, capacity := range []int{0, -1} {
		t.Run(strconv.Itoa(capacity), func(t *testing.T) {
			limiter := requestpath.NewLimiter(capacity)
			if limiter == nil {
				t.Fatal("NewLimiter() = nil, want non-nil")
			}
			if ok := limiter.TryAcquire(); !ok {
				t.Fatal("first TryAcquire() = false, want true")
			}
			if ok := limiter.TryAcquire(); ok {
				t.Fatal("second TryAcquire() = true, want false")
			}
		})
	}
}

func TestTryAcquire_UnderCap_ReturnsTrueAndIncrementsInFlight(t *testing.T) {
	limiter := requestpath.NewLimiter(2)
	if ok := limiter.TryAcquire(); !ok {
		t.Fatal("TryAcquire() = false, want true")
	}
	if got := limiter.InFlight(); got != 1 {
		t.Fatalf("InFlight() = %d, want 1", got)
	}
}

func TestTryAcquire_AtCap_ReturnsFalseAndInFlightUnchanged(t *testing.T) {
	limiter := requestpath.NewLimiter(1)
	if ok := limiter.TryAcquire(); !ok {
		t.Fatal("first TryAcquire() = false, want true")
	}
	if ok := limiter.TryAcquire(); ok {
		t.Fatal("second TryAcquire() = true, want false")
	}
	if got := limiter.InFlight(); got != 1 {
		t.Fatalf("InFlight() = %d, want 1", got)
	}
}

func TestRelease_AfterAcquire_DecrementsInFlight(t *testing.T) {
	limiter := requestpath.NewLimiter(1)
	if ok := limiter.TryAcquire(); !ok {
		t.Fatal("TryAcquire() = false, want true")
	}
	limiter.Release()
	if got := limiter.InFlight(); got != 0 {
		t.Fatalf("InFlight() = %d, want 0", got)
	}
	if ok := limiter.TryAcquire(); !ok {
		t.Fatal("TryAcquire() after Release = false, want true")
	}
}

func TestRelease_WithoutPriorAcquire_PanicsOnOverRelease(t *testing.T) {
	limiter := requestpath.NewLimiter(1)
	defer func() {
		if recover() == nil {
			t.Fatal("Release() did not panic on over-release")
		}
	}()
	limiter.Release()
}

func TestInFlight_ConcurrentAcquireRelease_ReflectsAccurateCountAtEachObservation(t *testing.T) {
	limiter := requestpath.NewLimiter(2)

	firstAcquired := make(chan struct{})
	secondAcquired := make(chan struct{})
	releaseFirst := make(chan struct{})
	releaseSecond := make(chan struct{})
	done := make(chan struct{}, 2)

	go func() {
		if !limiter.TryAcquire() {
			t.Error("first TryAcquire() = false, want true")
		}
		close(firstAcquired)
		<-releaseFirst
		limiter.Release()
		done <- struct{}{}
	}()

	<-firstAcquired
	if got := limiter.InFlight(); got != 1 {
		t.Fatalf("InFlight() after first acquire = %d, want 1", got)
	}

	go func() {
		if !limiter.TryAcquire() {
			t.Error("second TryAcquire() = false, want true")
		}
		close(secondAcquired)
		<-releaseSecond
		limiter.Release()
		done <- struct{}{}
	}()

	<-secondAcquired
	if got := limiter.InFlight(); got != 2 {
		t.Fatalf("InFlight() after second acquire = %d, want 2", got)
	}

	close(releaseFirst)
	<-done
	if got := limiter.InFlight(); got != 1 {
		t.Fatalf("InFlight() after first release = %d, want 1", got)
	}

	close(releaseSecond)
	<-done
	if got := limiter.InFlight(); got != 0 {
		t.Fatalf("InFlight() after second release = %d, want 0", got)
	}
}

func TestLimiter_ConcurrentAcquireAndRelease_NeverExceedsCapNeverGoesNegative(t *testing.T) {
	const (
		capacity   = 4
		goroutines = 16
		iterations = 100
	)

	limiter := requestpath.NewLimiter(capacity)
	var held atomic.Int64
	var maxHeld atomic.Int64
	var wg sync.WaitGroup

	start := make(chan struct{})
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range iterations {
				if !limiter.TryAcquire() {
					continue
				}

				current := held.Add(1)
				for {
					previous := maxHeld.Load()
					if current <= previous || maxHeld.CompareAndSwap(previous, current) {
						break
					}
				}
				if current < 0 {
					t.Error("held count went negative")
				}
				if current > capacity {
					t.Errorf("held count = %d, want <= %d", current, capacity)
				}
				if got := limiter.InFlight(); got < 0 || got > capacity {
					t.Errorf("InFlight() = %d, want within [0, %d]", got, capacity)
				}

				time.Sleep(time.Microsecond)

				if current := held.Add(-1); current < 0 {
					t.Error("held count went negative after release")
				}
				limiter.Release()
			}
		}()
	}

	close(start)
	wg.Wait()

	if got := limiter.InFlight(); got != 0 {
		t.Fatalf("InFlight() after concurrent run = %d, want 0", got)
	}
	if got := maxHeld.Load(); got > capacity {
		t.Fatalf("max held = %d, want <= %d", got, capacity)
	}
}
