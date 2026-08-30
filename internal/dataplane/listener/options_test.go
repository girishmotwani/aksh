package listener_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/dataplane/listener"
)

type testMetrics struct{ audit.NopMetricsRecorder }

type noopHandler struct{}

func (noopHandler) Handle(context.Context, *listener.ConnContext) error { return nil }

func validOptions() listener.Options {
	return listener.Options{
		Name:                   "control",
		ListenAddr:             netip.MustParseAddrPort("127.0.0.1:15001"),
		Handler:                noopHandler{},
		Metrics:                testMetrics{},
		MaxConnections:         512,
		PeekTimeout:            10 * time.Second,
		HandshakeRatePerSecond: 50,
		HandshakeRateBurst:     100,
	}
}

func TestValidate(t *testing.T) {
	t.Run("Validate_NilReceiver_ReturnsErrMissingOptionsNotPanic", func(t *testing.T) {
		// Regression test for the dev-review finding that (*Options).Validate
		// dereferences o immediately, so a nil *Options receiver panics
		// instead of returning a deterministic error.
		var opts *listener.Options
		if err := opts.Validate(); !errors.Is(err, listener.ErrMissingOptions) {
			t.Fatalf("Validate() error = %v, want ErrMissingOptions", err)
		}
	})

	t.Run("Validate_ZeroValueOptions_ReturnsErrMissingListenAddr", func(t *testing.T) {
		opts := listener.Options{}
		if err := opts.Validate(); !errors.Is(err, listener.ErrMissingListenAddr) {
			t.Fatalf("Validate() error = %v, want ErrMissingListenAddr", err)
		}
	})

	t.Run("Validate_NonLoopbackListenAddr_ReturnsErrNonLoopbackAddr", func(t *testing.T) {
		opts := validOptions()
		opts.ListenAddr = netip.MustParseAddrPort("10.0.0.1:15001")
		if err := opts.Validate(); !errors.Is(err, listener.ErrNonLoopbackAddr) {
			t.Fatalf("Validate() error = %v, want ErrNonLoopbackAddr", err)
		}
	})

	t.Run("Validate_IPv6LoopbackListenAddr_ReturnsErrNonLoopbackAddr", func(t *testing.T) {
		// ::1 is a loopback address, but Bind hardcodes net.Listen("tcp4",
		// ...), so accepting it here would only defer a confusing
		// address-family-mismatch failure to Bind. Validate intentionally
		// rejects any non-IPv4 address, including IPv6 loopback.
		opts := validOptions()
		opts.ListenAddr = netip.MustParseAddrPort("[::1]:15001")
		if err := opts.Validate(); !errors.Is(err, listener.ErrNonLoopbackAddr) {
			t.Fatalf("Validate() error = %v, want ErrNonLoopbackAddr", err)
		}
	})

	t.Run("Validate_LoopbackListenAddr_Passes", func(t *testing.T) {
		opts := validOptions()
		if err := opts.Validate(); err != nil {
			t.Fatalf("Validate() error = %v, want nil", err)
		}
	})

	t.Run("Validate_NilConnHandler_ReturnsErrMissingHandler", func(t *testing.T) {
		opts := validOptions()
		opts.Handler = nil
		if err := opts.Validate(); !errors.Is(err, listener.ErrMissingHandler) {
			t.Fatalf("Validate() error = %v, want ErrMissingHandler", err)
		}
	})

	t.Run("Validate_NilMetricsRecorder_ReturnsErrMissingMetrics", func(t *testing.T) {
		opts := validOptions()
		opts.Metrics = nil
		if err := opts.Validate(); !errors.Is(err, listener.ErrMissingMetrics) {
			t.Fatalf("Validate() error = %v, want ErrMissingMetrics", err)
		}
	})

	t.Run("Validate_MaxConnectionsZero_ReturnsErrInvalidMaxConnections", func(t *testing.T) {
		opts := validOptions()
		opts.MaxConnections = 0
		if err := opts.Validate(); !errors.Is(err, listener.ErrInvalidMaxConnections) {
			t.Fatalf("Validate() error = %v, want ErrInvalidMaxConnections", err)
		}
	})

	t.Run("Validate_MaxConnectionsPositive_Passes", func(t *testing.T) {
		// Repurposed from a duplicate of Validate_LoopbackListenAddr_Passes
		// (dev-review finding: identical assertion, no added coverage).
		// Exercises MaxConnections == 512, the design's documented default.
		opts := validOptions()
		opts.MaxConnections = 512
		if err := opts.Validate(); err != nil {
			t.Fatalf("Validate() error = %v, want nil for MaxConnections = 512", err)
		}
	})

	t.Run("Validate_PeekTimeoutZero_ReturnsErrInvalidPeekTimeout", func(t *testing.T) {
		opts := validOptions()
		opts.PeekTimeout = 0
		if err := opts.Validate(); !errors.Is(err, listener.ErrInvalidPeekTimeout) {
			t.Fatalf("Validate() error = %v, want ErrInvalidPeekTimeout", err)
		}
	})

	t.Run("Validate_BlockNonTCPWithoutAllowUnsafeStartup_ReturnsErrRequiresUnsafeStartup", func(t *testing.T) {
		opts := validOptions()
		opts.BlockNonTCP = true
		opts.AllowUnsafeStartup = false
		if err := opts.Validate(); !errors.Is(err, listener.ErrRequiresUnsafeStartup) {
			t.Fatalf("Validate() error = %v, want ErrRequiresUnsafeStartup", err)
		}
	})

	t.Run("Validate_BlockNonTCPWithAllowUnsafeStartup_Passes", func(t *testing.T) {
		opts := validOptions()
		opts.BlockNonTCP = true
		opts.AllowUnsafeStartup = true
		if err := opts.Validate(); err != nil {
			t.Fatalf("Validate() error = %v, want nil", err)
		}
	})

	t.Run("Validate_AllFieldsWellFormed_ReturnsNilError", func(t *testing.T) {
		opts := validOptions()
		opts.BlockNonTCP = false
		if err := opts.Validate(); err != nil {
			t.Fatalf("Validate() error = %v, want nil", err)
		}
	})

	t.Run("Validate_EmptyNameAndZeroMaxConnections_ReturnsErrMissingNameNotMaxConnections", func(t *testing.T) {
		// Regression test for the dev-review finding that Name (a
		// fundamental identity field) was validated after MaxConnections
		// and PeekTimeout, so a caller missing both Name and a positive
		// MaxConnections received the less-actionable
		// ErrInvalidMaxConnections instead of ErrMissingName.
		opts := validOptions()
		opts.Name = ""
		opts.MaxConnections = 0
		if err := opts.Validate(); !errors.Is(err, listener.ErrMissingName) {
			t.Fatalf("Validate() error = %v, want ErrMissingName", err)
		}
	})

	t.Run("Validate_EmptyNameAndZeroPeekTimeout_ReturnsErrMissingNameNotPeekTimeout", func(t *testing.T) {
		opts := validOptions()
		opts.Name = ""
		opts.PeekTimeout = 0
		if err := opts.Validate(); !errors.Is(err, listener.ErrMissingName) {
			t.Fatalf("Validate() error = %v, want ErrMissingName", err)
		}
	})

	t.Run("Validate_EmptyListenerName_ReturnsErrMissingName", func(t *testing.T) {
		opts := validOptions()
		opts.Name = ""
		if err := opts.Validate(); !errors.Is(err, listener.ErrMissingName) {
			t.Fatalf("Validate() error = %v, want ErrMissingName", err)
		}
	})

	t.Run("Validate_EmptyNameAndBlockNonTCPWithoutUnsafeStartup_ReturnsErrMissingNameNotUnsafeStartup", func(t *testing.T) {
		// Simple presence checks (Name) must precede more complex
		// conditional checks (BlockNonTCP/AllowUnsafeStartup interaction),
		// so a caller with both problems gets the simpler, more actionable
		// error rather than a misleading one.
		opts := validOptions()
		opts.Name = ""
		opts.BlockNonTCP = true
		opts.AllowUnsafeStartup = false
		if err := opts.Validate(); !errors.Is(err, listener.ErrMissingName) {
			t.Fatalf("Validate() error = %v, want ErrMissingName", err)
		}
	})
}
