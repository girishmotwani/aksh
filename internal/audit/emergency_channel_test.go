package audit_test

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/girishmotwani/aksh/internal/audit"
)

// erroringWriter simulates an impaired stderr (node log pressure): every write
// fails, exercising the §3.1 "two of three channels remain sound" caveat.
type erroringWriter struct{}

func (erroringWriter) Write([]byte) (int, error) {
	return 0, errors.New("stderr impaired")
}

// recordingReadiness is a ReadinessSink test double capturing every SetReady
// transition in order.
type recordingReadiness struct {
	mu     sync.Mutex
	states []bool
}

func (r *recordingReadiness) SetReady(ready bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.states = append(r.states, ready)
}

func (r *recordingReadiness) snapshot() []bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]bool(nil), r.states...)
}

func (r *recordingReadiness) last() (bool, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.states) == 0 {
		return false, false
	}
	return r.states[len(r.states)-1], true
}

// emergencyMetrics is a typed MetricsRecorder test double that captures
// AuditUnavailable calls; every other method is inherited as a no-op.
type emergencyMetrics struct {
	*rejectionMetrics
	mu          sync.Mutex
	unavailable []bool
}

func newEmergencyMetrics() *emergencyMetrics {
	return &emergencyMetrics{rejectionMetrics: &rejectionMetrics{}}
}

func (m *emergencyMetrics) AuditUnavailable(unavailable bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.unavailable = append(m.unavailable, unavailable)
}

func (m *emergencyMetrics) unavailableCalls() []bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]bool(nil), m.unavailable...)
}

func (m *emergencyMetrics) lastUnavailable() (bool, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.unavailable) == 0 {
		return false, false
	}
	return m.unavailable[len(m.unavailable)-1], true
}

// #29
func TestNewEmergencyChannel_NilMetricsAndReadiness_UsesNoop(t *testing.T) {
	var buf bytes.Buffer
	ec := audit.NewEmergencyChannel(&buf, nil, nil)

	// nil metrics/readiness must not panic and the log signal must still fire.
	ec.Signal("audit buffer full")

	if !strings.Contains(buf.String(), "audit buffer full") {
		t.Fatalf("stderr = %q, want it to contain the cause", buf.String())
	}
}

// #30
func TestSignal_TerminalAuditFailure_WritesLineToStderr(t *testing.T) {
	var buf bytes.Buffer
	ec := audit.NewEmergencyChannel(&buf, newEmergencyMetrics(), &recordingReadiness{})

	ec.Signal("exceeds deadline")

	out := buf.String()
	if strings.Count(out, "\n") != 1 {
		t.Fatalf("stderr = %q, want exactly one line", out)
	}
	if !strings.Contains(out, "exceeds deadline") {
		t.Fatalf("stderr = %q, want it to contain the cause", out)
	}
}

// #33
func TestSignal_StderrPath_DoesNotDependOnAuditSink(t *testing.T) {
	// NewEmergencyChannel takes no AuditSink at all: the stderr line is written
	// on the injected application stream, structurally independent of the sink.
	var buf bytes.Buffer
	ec := audit.NewEmergencyChannel(&buf, newEmergencyMetrics(), &recordingReadiness{})

	ec.Signal("stdout blocked")

	if !strings.Contains(buf.String(), "stdout blocked") {
		t.Fatalf("stderr = %q, want the emergency line on the application stream", buf.String())
	}
}

// #31
func TestSignal_TerminalAuditFailure_SetsUnavailableGaugeToOne(t *testing.T) {
	metrics := newEmergencyMetrics()
	ec := audit.NewEmergencyChannel(&bytes.Buffer{}, metrics, &recordingReadiness{})

	ec.Signal("audit buffer full")

	last, ok := metrics.lastUnavailable()
	if !ok || last != true {
		t.Fatalf("AuditUnavailable calls = %v, want last=true", metrics.unavailableCalls())
	}
}

// #32
func TestSignal_TerminalAuditFailure_ReadinessFails(t *testing.T) {
	readiness := &recordingReadiness{}
	ec := audit.NewEmergencyChannel(&bytes.Buffer{}, newEmergencyMetrics(), readiness)

	ec.Signal("audit buffer full")

	last, ok := readiness.last()
	if !ok || last != false {
		t.Fatalf("readiness states = %v, want last=false", readiness.snapshot())
	}
}

// #34
func TestSignal_StderrImpaired_GaugeAndReadinessStillFire(t *testing.T) {
	metrics := newEmergencyMetrics()
	readiness := &recordingReadiness{}
	// stderr write errors, but the gauge and readiness channels must still fire.
	ec := audit.NewEmergencyChannel(erroringWriter{}, metrics, readiness)

	ec.Signal("stdout blocked")

	last, ok := metrics.lastUnavailable()
	if !ok || last != true {
		t.Fatalf("AuditUnavailable calls = %v, want last=true despite stderr error", metrics.unavailableCalls())
	}
	rlast, rok := readiness.last()
	if !rok || rlast != false {
		t.Fatalf("readiness states = %v, want last=false despite stderr error", readiness.snapshot())
	}
}

// #35
func TestRecover_NextSuccessfulWrite_GaugeReturnsToZero(t *testing.T) {
	metrics := newEmergencyMetrics()
	ec := audit.NewEmergencyChannel(&bytes.Buffer{}, metrics, &recordingReadiness{})

	ec.Signal("audit buffer full")
	ec.Recover()

	last, ok := metrics.lastUnavailable()
	if !ok || last != false {
		t.Fatalf("AuditUnavailable calls = %v, want last=false", metrics.unavailableCalls())
	}
}

// #36
func TestRecover_NextSuccessfulWrite_ReadinessRecovers(t *testing.T) {
	readiness := &recordingReadiness{}
	ec := audit.NewEmergencyChannel(&bytes.Buffer{}, newEmergencyMetrics(), readiness)

	ec.Signal("audit buffer full")
	ec.Recover()

	last, ok := readiness.last()
	if !ok || last != true {
		t.Fatalf("readiness states = %v, want last=true", readiness.snapshot())
	}
}

// #37
func TestRecover_NoRestartRequired_NotLatched(t *testing.T) {
	metrics := newEmergencyMetrics()
	readiness := &recordingReadiness{}
	ec := audit.NewEmergencyChannel(&bytes.Buffer{}, metrics, readiness)

	for i := 0; i < 3; i++ {
		ec.Signal("audit buffer full")
		if last, ok := metrics.lastUnavailable(); !ok || last != true {
			t.Fatalf("cycle %d: gauge = %v, want unavailable=true", i, metrics.unavailableCalls())
		}
		if last, ok := readiness.last(); !ok || last != false {
			t.Fatalf("cycle %d: readiness = %v, want false", i, readiness.snapshot())
		}
		ec.Recover()
		if last, ok := metrics.lastUnavailable(); !ok || last != false {
			t.Fatalf("cycle %d: gauge = %v, want unavailable=false after recover", i, metrics.unavailableCalls())
		}
		if last, ok := readiness.last(); !ok || last != true {
			t.Fatalf("cycle %d: readiness = %v, want true after recover", i, readiness.snapshot())
		}
	}
}

// #38
func TestRecover_PreservesPolicySnapshotAndTokenCache(t *testing.T) {
	metrics := newEmergencyMetrics()
	readiness := &recordingReadiness{}
	ec := audit.NewEmergencyChannel(&bytes.Buffer{}, metrics, readiness)

	ec.Signal("audit buffer full")
	ec.Recover()

	// Recovery touches only the gauge and readiness — nothing else. There is no
	// policy-snapshot or token-cache side effect to discard (the struct owns no
	// such state; see the internal HasNoPolicyOrTokenState test).
	if got := metrics.unavailableCalls(); len(got) != 2 || got[0] != true || got[1] != false {
		t.Fatalf("AuditUnavailable calls = %v, want [true false] only", got)
	}
	if got := readiness.snapshot(); len(got) != 2 || got[0] != false || got[1] != true {
		t.Fatalf("readiness states = %v, want [false true] only", got)
	}
}

// #39
func TestSignal_SustainedPressure_ReadinessFlaps(t *testing.T) {
	readiness := &recordingReadiness{}
	ec := audit.NewEmergencyChannel(&bytes.Buffer{}, newEmergencyMetrics(), readiness)

	for i := 0; i < 4; i++ {
		ec.Signal("audit buffer full")
		ec.Recover()
	}

	// Honest flapping: readiness alternates false,true,false,true,... rather
	// than latching once.
	want := []bool{false, true, false, true, false, true, false, true}
	got := readiness.snapshot()
	if len(got) != len(want) {
		t.Fatalf("readiness states = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("readiness states = %v, want %v", got, want)
		}
	}
}

// #40
func TestTransitionCount_EachStateChange_Increments(t *testing.T) {
	ec := audit.NewEmergencyChannel(&bytes.Buffer{}, newEmergencyMetrics(), &recordingReadiness{})

	if got := ec.TransitionCount(); got != 0 {
		t.Fatalf("initial TransitionCount() = %d, want 0", got)
	}

	ec.Signal("x")
	if got := ec.TransitionCount(); got != 1 {
		t.Fatalf("after Signal TransitionCount() = %d, want 1", got)
	}
	// A repeated Signal while already not-ready is not a ready<->not-ready
	// transition, so it must not increment.
	ec.Signal("x")
	if got := ec.TransitionCount(); got != 1 {
		t.Fatalf("after repeated Signal TransitionCount() = %d, want 1", got)
	}
	ec.Recover()
	if got := ec.TransitionCount(); got != 2 {
		t.Fatalf("after Recover TransitionCount() = %d, want 2", got)
	}
	ec.Recover()
	if got := ec.TransitionCount(); got != 2 {
		t.Fatalf("after repeated Recover TransitionCount() = %d, want 2", got)
	}
}

// #41
func TestTransitionCount_FlapUnderPressure_CountsAllTransitions(t *testing.T) {
	ec := audit.NewEmergencyChannel(&bytes.Buffer{}, newEmergencyMetrics(), &recordingReadiness{})

	const cycles = 50
	for i := 0; i < cycles; i++ {
		ec.Signal("audit buffer full")
		ec.Recover()
	}

	// Every genuine transition counts with no coalescing: N fail/recover cycles
	// produce 2N transitions.
	if got := ec.TransitionCount(); got != uint64(2*cycles) {
		t.Fatalf("TransitionCount() = %d, want %d", got, 2*cycles)
	}
}

// TestTransitionCount_ConcurrentSignalRecover_ThreadSafe drives Signal and
// Recover from many goroutines to exercise the mutex-serialized state machine
// for deadlock/consistency (the -race detector is unavailable under
// CGO_ENABLED=0, so this asserts liveness + gauge/readiness agreement rather
// than relying on -race). Because gauge, readiness and the flap count are all
// updated under one lock, the final gauge value must always agree with the
// final readiness state.
func TestTransitionCount_ConcurrentSignalRecover_ThreadSafe(t *testing.T) {
	metrics := newEmergencyMetrics()
	readiness := &recordingReadiness{}
	// Signal writes to stderr OUTSIDE the lock, so the injected writer is hit
	// concurrently; io.Discard is concurrency-safe (a bytes.Buffer is not).
	ec := audit.NewEmergencyChannel(io.Discard, metrics, readiness)

	const goroutines = 50
	const iters = 40
	var wg sync.WaitGroup
	start := make(chan struct{})
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			<-start
			for i := 0; i < iters; i++ {
				if (g+i)%2 == 0 {
					ec.Signal("concurrent")
				} else {
					ec.Recover()
				}
				_ = ec.TransitionCount()
			}
		}(g)
	}
	close(start)
	wg.Wait()

	// A final deterministic Signal must leave gauge and readiness consistent:
	// both are applied atomically under the same lock.
	ec.Signal("final")
	gauge, ok := metrics.lastUnavailable()
	if !ok || gauge != true {
		t.Fatalf("final gauge unavailable = %v (ok=%v), want true", gauge, ok)
	}
	ready, ok := readiness.last()
	if !ok || ready != false {
		t.Fatalf("final readiness = %v (ok=%v), want false", ready, ok)
	}
	// After heavy flapping plus the final deterministic Signal, at least the
	// final transition (and, in practice, many concurrent ones) must be
	// counted; < 2 would indicate transitions are being silently dropped.
	if tc := ec.TransitionCount(); tc < 2 {
		t.Fatalf("TransitionCount = %d after heavy flapping + final Signal, want >= 2", tc)
	}
}
