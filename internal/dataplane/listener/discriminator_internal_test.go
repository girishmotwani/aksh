package listener

import (
	"fmt"
	"net"
	"os"
	"testing"
)

// TestIsDeadlineExceeded_WrappedTimeoutError_StillDetected is a regression
// test for the dev-review finding that isDeadlineExceeded used a direct
// `err.(net.Error)` type assertion, which fails to unwrap a timeout error
// wrapped via fmt.Errorf("...: %w", err) -- misclassifying a wrapped
// deadline-exceeded error as ProtocolUnknown (short peek) instead of
// ErrPeekTimeout.
func TestIsDeadlineExceeded_WrappedTimeoutError_StillDetected(t *testing.T) {
	base := &net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}
	wrapped := fmt.Errorf("classify: %w", base)
	if !isDeadlineExceeded(wrapped) {
		t.Fatalf("isDeadlineExceeded(wrapped timeout error) = false, want true")
	}
}

// TestIsDeadlineExceeded_NonDeadlineTimeoutError_NotMisclassified is a
// regression test for the dev-review finding that isDeadlineExceeded used
// the imprecise net.Error.Timeout() heuristic, which is also true for
// timeouts unrelated to a Peek deadline expiring (e.g. a dial/connect
// timeout surfaced on the same connection). Only errors that genuinely
// wrap os.ErrDeadlineExceeded should be treated as "the deadline we set
// expired"; a generic Timeout()==true error that is not
// os.ErrDeadlineExceeded must not be misclassified as one.
func TestIsDeadlineExceeded_NonDeadlineTimeoutError_NotMisclassified(t *testing.T) {
	// dialTimeoutError simulates a generic net.Error with Timeout()==true
	// that is NOT the deadline-exceeded sentinel (e.g. as returned by a
	// dial timeout), distinct from timeoutError/os.ErrDeadlineExceeded.
	err := &net.OpError{Op: "dial", Err: dialTimeoutError{}}
	if isDeadlineExceeded(err) {
		t.Fatalf("isDeadlineExceeded(generic dial-timeout error) = true, want false (only os.ErrDeadlineExceeded should count)")
	}
}

// dialTimeoutError is a net.Error whose Timeout() returns true but which
// is not os.ErrDeadlineExceeded, used to distinguish "any timeout" from
// "the read/write deadline we set actually expired".
type dialTimeoutError struct{}

func (dialTimeoutError) Error() string { return "simulated dial timeout" }
func (dialTimeoutError) Timeout() bool { return true }

// the dev-review finding that discardScratch was fixed at 4096 bytes while
// the discriminator only ever peeks PeekSize (24) bytes, wasting memory on
// every peekedConn instance. discardScratchSize must track PeekSize exactly,
// never exceed it.
func TestPeekedConn_DiscardScratchSize_MatchesPeekSize(t *testing.T) {
	if discardScratchSize != PeekSize {
		t.Fatalf("discardScratchSize = %d, want %d (PeekSize)", discardScratchSize, PeekSize)
	}
}

// staticAssertH2CPrefaceIsConstString has no runtime effect. It only compiles
// if h2cPreface is an untyped/typed constant (assignable to a const-typed
// local); a package-level []byte var could never be used in a const
// declaration's initializer, so this line fails to compile if h2cPreface
// ever regresses to a mutable []byte var. Closes the dev-review finding that
// a mutable package-level var could corrupt protocol detection for every
// subsequent connection if ever mutated at runtime.
const staticAssertH2CPrefaceIsConstString = h2cPreface

// TestClassifyBytes_H2CPrefaceMatch_DoesNotAllocate has moved to
// discriminator_norace_internal_test.go (dev-review iter12 finding:
// -race's own instrumentation allocates bookkeeping state around memory
// accesses, which made this allocation-sensitive assertion flap under
// `-race` builds; it must only run in non-race builds via a
// `//go:build !race` tag rather than living in this always-built file).

// TestH2CPreface_IsImmutableConst is a regression test for the dev-review
// finding that h2cPreface was a mutable package-level []byte var. It is now
// a string const; strings in Go are immutable by language guarantee, so
// confirming its value here (alongside the compile-time assertion above)
// locks in the fix.
func TestH2CPreface_IsImmutableConst(t *testing.T) {
	const want = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	if h2cPreface != want {
		t.Fatalf("h2cPreface = %q, want %q", h2cPreface, want)
	}
	if staticAssertH2CPrefaceIsConstString != want {
		t.Fatalf("staticAssertH2CPrefaceIsConstString = %q, want %q", staticAssertH2CPrefaceIsConstString, want)
	}
}

// TestClassifyBytes_SSLv3RecordHeader_IsNotClassifiedAsTLS is a regression
// test for the dev-review finding that classifyBytes accepted a TLS
// record-layer minor version of 0x00 (SSLv3) as ProtocolTLS. SSLv3 is
// deprecated and insecure (POODLE); this discriminator's TLS acceptance
// range must start at TLS 1.0 (minor version 0x01).
func TestClassifyBytes_SSLv3RecordHeader_IsNotClassifiedAsTLS(t *testing.T) {
	sslv3Header := []byte{0x16, 0x03, 0x00, 0x00, 0x31}
	if got := classifyBytes(sslv3Header); got == ProtocolTLS {
		t.Fatalf("classifyBytes(SSLv3 record header) = ProtocolTLS, want anything else (SSLv3 must not classify as TLS)")
	}
}
