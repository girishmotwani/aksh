package capture_test

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/dataplane/capture"
)

// fakeMetrics is a plain-struct audit.MetricsRecorder; Validate() only checks
// that the dependency is present, so the methods record nothing.
type fakeMetrics struct{ audit.NopMetricsRecorder }

// validOptions returns an Options populated with every field at a valid
// representative value.
func validOptions() capture.Options {
	opts := capture.DefaultOptions()
	opts.PodPath = "/host/sys/fs/cgroup/kubepods.slice/kubepods-burstable-pod11111111-2222-3333-4444-555555555555.slice"
	opts.HostCgroupMount = "/host/sys/fs/cgroup"
	opts.Metrics = fakeMetrics{}
	opts.PinRoot = "/sys/fs/bpf"
	opts.DNSServer = netip.MustParseAddrPort("10.96.0.10:53")
	return opts
}

// assertNotError was removed in review iteration 1: an assertion of the form
// "the error is not this sentinel" passes for every other failure too, which
// hid whether the case under test had actually succeeded. The positive cases
// now assert a nil error.

// TestValidate covers unit test spec section 7 (#75-#94): capture.Options and
// its Validate() method. The subtests whose names do not appear in the spec are
// marked "not a spec case" and were added in review iteration 1.
func TestValidate(t *testing.T) {
	// Not a spec case. (*Options).Validate() has an explicit nil-receiver
	// guard, which was otherwise unexercised.
	t.Run("Validate_NilOptionsPointer_ReturnsErrMissingConfig", func(t *testing.T) {
		var opts *capture.Options
		if err := opts.Validate(); !errors.Is(err, capture.ErrMissingConfig) {
			t.Fatalf("Validate() error = %v, want ErrMissingConfig", err)
		}
	})

	t.Run("Validate_ZeroValueOptions_ReturnsErrMissingPodPath", func(t *testing.T) {
		opts := &capture.Options{}
		if err := opts.Validate(); !errors.Is(err, capture.ErrMissingPodPath) {
			t.Fatalf("Validate() error = %v, want ErrMissingPodPath", err)
		}
	})

	t.Run("Validate_EmptyPodPath_ReturnsErrMissingPodPath", func(t *testing.T) {
		opts := validOptions()
		opts.PodPath = ""
		if err := opts.Validate(); !errors.Is(err, capture.ErrMissingPodPath) {
			t.Fatalf("Validate() error = %v, want ErrMissingPodPath", err)
		}
	})

	t.Run("Validate_EmptyHostCgroupMount_ReturnsErrMissingHostMount", func(t *testing.T) {
		opts := validOptions()
		opts.HostCgroupMount = ""
		if err := opts.Validate(); !errors.Is(err, capture.ErrMissingHostMount) {
			t.Fatalf("Validate() error = %v, want ErrMissingHostMount", err)
		}
	})

	t.Run("Validate_NilMetricsRecorder_ReturnsErrMissingMetrics", func(t *testing.T) {
		opts := validOptions()
		opts.Metrics = nil
		if err := opts.Validate(); !errors.Is(err, capture.ErrMissingMetrics) {
			t.Fatalf("Validate() error = %v, want ErrMissingMetrics", err)
		}
	})

	t.Run("Validate_ProxyUIDZero_ReturnsErrInvalidProxyUID", func(t *testing.T) {
		opts := validOptions()
		opts.ProxyUID = 0
		if err := opts.Validate(); !errors.Is(err, capture.ErrInvalidProxyUID) {
			t.Fatalf("Validate() error = %v, want ErrInvalidProxyUID", err)
		}
	})

	t.Run("Validate_ProxyUIDNonZero_PassesCheck", func(t *testing.T) {
		opts := validOptions()
		opts.ProxyUID = 1774
		// validOptions() is valid in every other respect, so the only correct
		// outcome is a nil error. Asserting merely "not ErrInvalidProxyUID"
		// would let an unrelated validation failure pass this case.
		if err := opts.Validate(); err != nil {
			t.Fatalf("Validate() error = %v, want nil", err)
		}
	})

	t.Run("Validate_IPv6CaptureRequested_ReturnsErrIPv6Unsupported", func(t *testing.T) {
		opts := validOptions()
		opts.CaptureIPv6 = true
		if err := opts.Validate(); !errors.Is(err, capture.ErrIPv6Unsupported) {
			t.Fatalf("Validate() error = %v, want ErrIPv6Unsupported", err)
		}
	})

	t.Run("Validate_MountBPFFSFalseAndNotMounted_PassesValidateButDefersToPreflight", func(t *testing.T) {
		opts := validOptions()
		opts.MountBPFFS = false
		if err := opts.Validate(); err != nil {
			t.Fatalf("Validate() error = %v, want nil (bpffs mount state is preflight P6's job)", err)
		}
	})

	// #83-#86 keep the spec's subtest names but use the design's fail-closed
	// semantics: it is DISABLING BlockNonTCP/RunProbe that requires
	// AllowUnsafeStartup (design section 18). See the Findings document.
	t.Run("Validate_BlockNonTCPWithoutAllowUnsafeStartup_ReturnsErrRequiresUnsafeStartup", func(t *testing.T) {
		opts := validOptions()
		opts.BlockNonTCP = false
		opts.AllowUnsafeStartup = false
		if err := opts.Validate(); !errors.Is(err, capture.ErrRequiresUnsafeStartup) {
			t.Fatalf("Validate() error = %v, want ErrRequiresUnsafeStartup", err)
		}
	})

	t.Run("Validate_BlockNonTCPWithAllowUnsafeStartup_Passes", func(t *testing.T) {
		opts := validOptions()
		opts.BlockNonTCP = false
		opts.AllowUnsafeStartup = true
		if err := opts.Validate(); err != nil {
			t.Fatalf("Validate() error = %v, want nil", err)
		}
	})

	t.Run("Validate_RunProbeWithoutAllowUnsafeStartup_ReturnsErrRequiresUnsafeStartup", func(t *testing.T) {
		opts := validOptions()
		opts.RunProbe = false
		opts.AllowUnsafeStartup = false
		if err := opts.Validate(); !errors.Is(err, capture.ErrRequiresUnsafeStartup) {
			t.Fatalf("Validate() error = %v, want ErrRequiresUnsafeStartup", err)
		}
	})

	t.Run("Validate_RunProbeWithAllowUnsafeStartup_Passes", func(t *testing.T) {
		opts := validOptions()
		opts.RunProbe = false
		opts.AllowUnsafeStartup = true
		if err := opts.Validate(); err != nil {
			t.Fatalf("Validate() error = %v, want nil", err)
		}
	})

	t.Run("Validate_AttachCheckIntervalZero_ReturnsErrInvalidAttachCheckInterval", func(t *testing.T) {
		opts := validOptions()
		opts.AttachCheckInterval = 0
		opts.AllowUnsafeStartup = true // no escape hatch exists for this control
		if err := opts.Validate(); !errors.Is(err, capture.ErrInvalidAttachCheckInterval) {
			t.Fatalf("Validate() error = %v, want ErrInvalidAttachCheckInterval", err)
		}
	})

	t.Run("Validate_AttachCheckIntervalNegative_ReturnsErrInvalidAttachCheckInterval", func(t *testing.T) {
		opts := validOptions()
		opts.AttachCheckInterval = -1 * time.Second
		opts.AllowUnsafeStartup = true
		if err := opts.Validate(); !errors.Is(err, capture.ErrInvalidAttachCheckInterval) {
			t.Fatalf("Validate() error = %v, want ErrInvalidAttachCheckInterval", err)
		}
	})

	// #89 keeps the spec's subtest name but uses 30s: design section 13.1 bounds
	// AttachCheckInterval to [10s, 60s], so the spec's 5s must be rejected.
	t.Run("Validate_AttachCheckIntervalPositive_Passes", func(t *testing.T) {
		opts := validOptions()
		opts.AttachCheckInterval = 30 * time.Second
		if err := opts.Validate(); err != nil {
			t.Fatalf("Validate() error = %v, want nil", err)
		}
	})

	// Not spec cases. Spec #87-#89 exercise zero, negative and one in-range
	// value; the bound itself (design section 13.1, [10s, 60s]) was untested,
	// so an implementation that accepted any positive duration would pass.
	t.Run("Validate_AttachCheckIntervalAtLowerBound_Passes", func(t *testing.T) {
		opts := validOptions()
		opts.AttachCheckInterval = 10 * time.Second
		if err := opts.Validate(); err != nil {
			t.Fatalf("Validate() error = %v, want nil", err)
		}
	})

	t.Run("Validate_AttachCheckIntervalBelowLowerBound_ReturnsErrInvalidAttachCheckInterval", func(t *testing.T) {
		opts := validOptions()
		opts.AttachCheckInterval = 10*time.Second - time.Nanosecond
		opts.AllowUnsafeStartup = true
		if err := opts.Validate(); !errors.Is(err, capture.ErrInvalidAttachCheckInterval) {
			t.Fatalf("Validate() error = %v, want ErrInvalidAttachCheckInterval", err)
		}
	})

	t.Run("Validate_AttachCheckIntervalAtUpperBound_Passes", func(t *testing.T) {
		opts := validOptions()
		opts.AttachCheckInterval = 60 * time.Second
		if err := opts.Validate(); err != nil {
			t.Fatalf("Validate() error = %v, want nil", err)
		}
	})

	t.Run("Validate_AttachCheckIntervalAboveUpperBound_ReturnsErrInvalidAttachCheckInterval", func(t *testing.T) {
		opts := validOptions()
		opts.AttachCheckInterval = 60*time.Second + time.Nanosecond
		opts.AllowUnsafeStartup = true
		if err := opts.Validate(); !errors.Is(err, capture.ErrInvalidAttachCheckInterval) {
			t.Fatalf("Validate() error = %v, want ErrInvalidAttachCheckInterval", err)
		}
	})

	// Not spec cases. DNSServer reaches netip.Addr.As4() when the frozen
	// configuration image is built, so an unvalidated non-IPv4 value panics
	// there; Validate() must reject it first.
	t.Run("Validate_DNSServerIPv6_ReturnsErrInvalidDNSServer", func(t *testing.T) {
		opts := validOptions()
		opts.DNSServer = netip.MustParseAddrPort("[2001:4860:4860::8888]:53")
		if err := opts.Validate(); !errors.Is(err, capture.ErrInvalidDNSServer) {
			t.Fatalf("Validate() error = %v, want ErrInvalidDNSServer", err)
		}
	})

	t.Run("Validate_DNSServerZeroPort_ReturnsErrInvalidDNSServer", func(t *testing.T) {
		opts := validOptions()
		opts.DNSServer = netip.AddrPortFrom(netip.MustParseAddr("10.96.0.10"), 0)
		if err := opts.Validate(); !errors.Is(err, capture.ErrInvalidDNSServer) {
			t.Fatalf("Validate() error = %v, want ErrInvalidDNSServer", err)
		}
	})

	t.Run("Validate_DNSServerUnset_Passes", func(t *testing.T) {
		opts := validOptions()
		opts.DNSServer = netip.AddrPort{}
		if err := opts.Validate(); err != nil {
			t.Fatalf("Validate() error = %v, want nil (the zero value disables the DEV-01 exception)", err)
		}
	})

	// Not spec cases. ListenerAddr is checked on the unmapped address, so the
	// 4-in-6 spelling of IPv4 loopback is accepted and a genuine IPv6 loopback
	// is not.
	t.Run("Validate_ListenerAddrIPv4MappedLoopback_Passes", func(t *testing.T) {
		opts := validOptions()
		opts.ListenerAddr = netip.MustParseAddrPort("[::ffff:127.0.0.1]:15001")
		if err := opts.Validate(); err != nil {
			t.Fatalf("Validate() error = %v, want nil", err)
		}
	})

	t.Run("Validate_ListenerAddrIPv6Loopback_ReturnsErrInvalidListenerAddr", func(t *testing.T) {
		opts := validOptions()
		opts.ListenerAddr = netip.MustParseAddrPort("[::1]:15001")
		if err := opts.Validate(); !errors.Is(err, capture.ErrInvalidListenerAddr) {
			t.Fatalf("Validate() error = %v, want ErrInvalidListenerAddr", err)
		}
	})

	t.Run("Validate_ListenerAddrNonLoopback_ReturnsErrInvalidListenerAddr", func(t *testing.T) {
		opts := validOptions()
		opts.ListenerAddr = netip.MustParseAddrPort("10.0.0.5:15001")
		if err := opts.Validate(); !errors.Is(err, capture.ErrInvalidListenerAddr) {
			t.Fatalf("Validate() error = %v, want ErrInvalidListenerAddr", err)
		}
	})

	t.Run("Validate_PinLinksDefaultFalse_AcceptedByValidate", func(t *testing.T) {
		if capture.DefaultOptions().PinLinks {
			t.Fatalf("DefaultOptions().PinLinks = true, want false while gate M1 is unverified")
		}
		opts := validOptions()
		opts.PinLinks = false
		opts.PinRoot = ""
		if err := opts.Validate(); err != nil {
			t.Fatalf("Validate() error = %v, want nil", err)
		}
	})

	t.Run("Validate_PinLinksTrueWithoutPinRoot_ReturnsErrMissingPinRoot", func(t *testing.T) {
		opts := validOptions()
		opts.PinLinks = true
		opts.PinRoot = ""
		if err := opts.Validate(); !errors.Is(err, capture.ErrMissingPinRoot) {
			t.Fatalf("Validate() error = %v, want ErrMissingPinRoot", err)
		}
	})

	t.Run("Validate_PinLinksTrueWithPinRoot_Passes", func(t *testing.T) {
		opts := validOptions()
		opts.PinLinks = true
		opts.PinRoot = "/sys/fs/bpf"
		if err := opts.Validate(); err != nil {
			t.Fatalf("Validate() error = %v, want nil", err)
		}
	})

	t.Run("Validate_AllFieldsWellFormed_ReturnsNilError", func(t *testing.T) {
		opts := validOptions()
		if err := opts.Validate(); err != nil {
			t.Fatalf("Validate() error = %v, want nil", err)
		}
	})

	t.Run("Validate_MultipleFieldsInvalidSimultaneously_ReturnsFirstEncounteredError", func(t *testing.T) {
		opts := validOptions()
		opts.PodPath = ""
		opts.HostCgroupMount = ""
		err := opts.Validate()
		if !errors.Is(err, capture.ErrMissingPodPath) {
			t.Fatalf("Validate() error = %v, want ErrMissingPodPath (PodPath is checked first)", err)
		}
		if errors.Is(err, capture.ErrMissingHostMount) {
			t.Fatalf("Validate() error = %v, want validation to stop at the first failure", err)
		}
	})
}
