// Package audit — emergency_channel.go implements the INV-6 bounded-exception
// signaller of S6 §3.1. When audit has terminally failed, the resulting denial
// cannot itself be audited; it is instead signalled on three independent paths:
// a stderr line, the aksh_audit_unavailable gauge, and a readiness failure.
package audit

import (
	"fmt"
	"io"
	"os"
	"sync"
)

// ReadinessSink is the seam the EmergencyChannel drives to take the pod out of
// service on a terminal audit failure (§3.1 channel 3) and restore it on
// recovery. A nil ReadinessSink defaults to a no-op.
type ReadinessSink interface {
	// SetReady reports the emergency-driven readiness state: false on a
	// terminal audit failure, true on recovery.
	SetReady(ready bool)
}

// emergencyLineFormat is the single stderr line written on a terminal audit
// failure (§3.1 channel 1). It is a fixed, structured prefix plus the cause.
const emergencyLineFormat = "aksh: audit unavailable (fail-closed): %s\n"

// EmergencyChannel signals terminal audit failure and automatic recovery on
// three independent channels (§3.1). It owns only the minimal signalling state
// required for the gauge, readiness and flap count — deliberately no policy
// snapshot or token cache, so recovery discards neither.
type EmergencyChannel struct {
	stderr    io.Writer
	metrics   MetricsRecorder
	readiness ReadinessSink

	mu          sync.Mutex
	ready       bool
	transitions uint64
}

// NewEmergencyChannel constructs an EmergencyChannel. A nil stderr defaults to
// os.Stderr (the application stream, independent of the audit sink); nil
// metrics/readiness seams default to no-ops so the stderr signal still fires.
func NewEmergencyChannel(stderr io.Writer, m MetricsRecorder, readiness ReadinessSink) *EmergencyChannel {
	if stderr == nil {
		stderr = os.Stderr
	}
	return &EmergencyChannel{
		stderr:    stderr,
		metrics:   m,
		readiness: readiness,
		ready:     true,
	}
}

// Signal announces a terminal audit failure on all three §3.1 channels. The
// stderr write (channel 1) is best-effort: its failure must not prevent the
// gauge (channel 2) and readiness (channel 3) signals from firing.
func (e *EmergencyChannel) Signal(cause string) {
	if e == nil {
		return
	}
	// Channel 1 — one line on the application stream. Best-effort and done
	// OUTSIDE the lock (a slow/impaired stream must not stall the serialized
	// gauge/readiness update): a write error is captured and dropped, never
	// propagated, so it cannot short-circuit the other two channels.
	_, _ = fmt.Fprintf(e.stderr, emergencyLineFormat, cause)

	// Channels 2 (gauge) and 3 (readiness) are applied atomically with the
	// readiness state under a single lock so they can never diverge under a
	// Signal/Recover race.
	e.setState(false)
}

// Recover signals that audit is healthy again after a subsequent successful
// write: the gauge returns to 0 and readiness recovers. Recovery is automatic
// and not latched — Signal→Recover may repeat indefinitely without a restart —
// and touches only the gauge and readiness, never any policy snapshot or token
// cache (this type owns none).
func (e *EmergencyChannel) Recover() {
	if e == nil {
		return
	}
	e.setState(true)
}

// TransitionCount returns the monotonic number of ready<->not-ready readiness
// transitions. Every genuine transition is counted with no coalescing, so a
// flap under sustained pressure is itself alertable (§3.1).
func (e *EmergencyChannel) TransitionCount() uint64 {
	if e == nil {
		return 0
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.transitions
}

// Signalf is the printf-style adapter that lets an existing
// func(format string, args ...any) emergency callback (e.g. the one
// RejectionRecorder holds) drive the EmergencyChannel.
func (e *EmergencyChannel) Signalf(format string, args ...any) {
	if e == nil {
		return
	}
	e.Signal(fmt.Sprintf(format, args...))
}

// setState drives the gauge, readiness and flap count to a consistent state
// under a single lock, so concurrent Signal/Recover callers can never leave the
// gauge (channel 2) and readiness (channel 3) disagreeing. The gauge and
// readiness seams are invoked while the lock is held; both MetricsRecorder and
// ReadinessSink implementations in this codebase are non-reentrant and
// non-blocking (an atomic gauge Set and an atomic readiness store), so holding
// the lock cannot deadlock — that non-reentrancy is their contract.
func (e *EmergencyChannel) setState(ready bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ready != ready {
		e.ready = ready
		e.transitions++
	}
	if e.metrics != nil {
		e.metrics.AuditUnavailable(!ready)
	}
	if e.readiness != nil {
		e.readiness.SetReady(ready)
	}
}
