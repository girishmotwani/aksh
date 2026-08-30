package listener

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
)

// TestIsClosedConnErr_CoversDeadlineAndReset is a regression test for the
// dev-review finding that isClosedConnErr only matched io.EOF,
// net.ErrClosed, and io.ErrClosedPipe, missing os.ErrDeadlineExceeded
// (returned by SetDeadline-backed connections during orderly context-cancel
// shutdown) and syscall.ECONNRESET wrapped in *net.OpError (a benign
// connection-reset that occurs on Linux). Both previously caused Handle to
// return a spurious error instead of treating the shutdown as expected.
func TestIsClosedConnErr_CoversDeadlineAndReset(t *testing.T) {
	resetErr := &net.OpError{Op: "read", Err: syscall.ECONNRESET}

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"deadline exceeded", os.ErrDeadlineExceeded, true},
		{"wrapped econnreset", resetErr, true},
		{"unrelated error", errors.New("boom"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isClosedConnErr(tc.err); got != tc.want {
				t.Fatalf("isClosedConnErr(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
