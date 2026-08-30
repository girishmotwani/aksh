package capture

import "errors"

// Sentinel errors returned by construction and configuration validation.
var (
	// ErrUnsupportedPlatform is returned by every non-Linux stub.
	ErrUnsupportedPlatform = errors.New("capture: operation is not supported on this platform")
	// ErrMissingOptions is returned when LoadAndAttach is called with a nil
	// *Options, before any kernel object is touched.
	ErrMissingOptions = errors.New("capture: Options is required")
	// ErrMissingResolver is returned when a method is called on a nil resolver.
	ErrMissingResolver = errors.New("capture: resolver is nil")
	// ErrMissingConfig is returned when a constructor receives a nil configuration.
	ErrMissingConfig = errors.New("capture: configuration is nil")
	// ErrEmptyPodPath is returned when an empty pod cgroup path is supplied.
	ErrEmptyPodPath = errors.New("capture: pod cgroup path is empty")
	// ErrMissingPodPath is returned when Options.PodPath is unset.
	ErrMissingPodPath = errors.New("capture: PodPath is required")
	// ErrMissingHostMount is returned when Options.HostCgroupMount is unset.
	ErrMissingHostMount = errors.New("capture: HostCgroupMount is required")
	// ErrMissingLocalMount is returned when the proxy's own cgroup2 mount is
	// unset. Discovery cannot proceed without it: the case B search matches the
	// inode of that mount against the host tree.
	ErrMissingLocalMount = errors.New("capture: LocalCgroupMount is required")
	// ErrMissingProcCgroupPath is returned when the process cgroup file is
	// unset. It is the only permitted input to discovery, so there is no
	// fallback that could be substituted for it.
	ErrMissingProcCgroupPath = errors.New("capture: ProcCgroupPath is required")
	// ErrMissingMetrics is returned when Options.Metrics is nil.
	ErrMissingMetrics = errors.New("capture: Metrics recorder is required")
	// ErrInvalidProxyUID is returned when Options.ProxyUID is zero.
	ErrInvalidProxyUID = errors.New("capture: ProxyUID must be non-zero")
	// ErrIPv6Unsupported is returned when IPv6 capture is requested.
	ErrIPv6Unsupported = errors.New("capture: IPv6 capture is not implemented in phase 5A")
	// ErrRequiresUnsafeStartup is returned when a fail-open configuration is
	// requested without AllowUnsafeStartup.
	ErrRequiresUnsafeStartup = errors.New("capture: option requires AllowUnsafeStartup")
	// ErrInvalidAttachCheckInterval is returned when AttachCheckInterval is
	// outside the mandatory [10s, 60s] range. This control has no escape hatch.
	ErrInvalidAttachCheckInterval = errors.New("capture: AttachCheckInterval must be within [10s, 60s]")
	// ErrMissingPinRoot is returned when PinLinks is set without a PinRoot.
	ErrMissingPinRoot = errors.New("capture: PinRoot is required when PinLinks is enabled")
	// ErrInvalidListenerAddr is returned when ListenerAddr is not IPv4 loopback.
	ErrInvalidListenerAddr = errors.New("capture: ListenerAddr must be an IPv4 loopback address")
	// ErrInvalidDNSServer is returned when DNSServer is set to something the
	// DEV-01 exception cannot express: a non-IPv4 address or a zero port.
	ErrInvalidDNSServer = errors.New("capture: DNSServer must be an IPv4 address with a non-zero port")
	// ErrInvalidBypassCIDR is returned when a BypassCIDRs entry is not an IPv4
	// prefix, is shorter than /8, has host bits set, or the list is longer than
	// the kernel map holds. A bypassed prefix is unpoliced, so this is rejected
	// outright rather than clamped.
	ErrInvalidBypassCIDR = errors.New("capture: BypassCIDRs entries must be IPv4 prefixes of /8 or longer with no host bits set")
	// ErrInvalidMapEntries is returned when MapEntries is outside [1024, 65536].
	ErrInvalidMapEntries = errors.New("capture: MapEntries must be within [1024, 65536]")
	// ErrInvalidDestMaxAge is returned when DestMaxAge is outside [1s, 120s].
	ErrInvalidDestMaxAge = errors.New("capture: DestMaxAge must be within [1s, 120s]")
)

// Capture-runtime sentinels named by the design (sections 6.5.3, 8.1). They are
// declared here so that the Linux slice and the listener bind to one definition.
var (
	// ErrNotTCP reports a non-TCP socket reaching a TCP-only path.
	ErrNotTCP = errors.New("capture: connection is not TCP")
	// ErrAddressFamily reports an unsupported socket address family.
	ErrAddressFamily = errors.New("capture: unsupported address family")
	// ErrNoOriginalDestination reports that no destination record exists.
	ErrNoOriginalDestination = errors.New("capture: no original destination record")
	// ErrMapUnavailable reports that the destination map is not usable.
	ErrMapUnavailable = errors.New("capture: destination map is unavailable")
	// ErrLoopGuard reports a connection originated by the proxy UID (T2).
	ErrLoopGuard = errors.New("capture: loop guard tripped")
	// ErrStaleEntry reports a destination record older than DestMaxAge.
	ErrStaleEntry = errors.New("capture: destination record is stale")
	// ErrMalformedEntry reports a destination record that failed decoding.
	ErrMalformedEntry = errors.New("capture: destination record is malformed")
)

// FailureCode is the stable identifier of a preflight or resolution failure.
// The codes are the E_* identifiers in design sections 6.1.3 and 6.7.
type FailureCode string

// Preflight and cgroup-resolution failure codes.
const (
	E_CGO_ENABLED       FailureCode = "E_CGO_ENABLED"
	E_KERNEL_TOO_OLD    FailureCode = "E_KERNEL_TOO_OLD"
	E_NO_CGROUP2        FailureCode = "E_NO_CGROUP2"
	E_CGROUP_SCOPE      FailureCode = "E_CGROUP_SCOPE"
	E_CGROUPNS_OPAQUE   FailureCode = "E_CGROUPNS_OPAQUE"
	E_AMBIGUOUS_CGROUP  FailureCode = "E_AMBIGUOUS_CGROUP"
	E_CGROUP_WALK_LIMIT FailureCode = "E_CGROUP_WALK_LIMIT"
	E_NO_BPFFS          FailureCode = "E_NO_BPFFS"
	E_MISSING_CAPS      FailureCode = "E_MISSING_CAPS"
	E_MEMLOCK           FailureCode = "E_MEMLOCK"
	E_PROG_LOAD         FailureCode = "E_PROG_LOAD"
	E_CONFIG_WRITE      FailureCode = "E_CONFIG_WRITE"
	E_CONFIG_FREEZE     FailureCode = "E_CONFIG_FREEZE"
	E_ATTACH            FailureCode = "E_ATTACH"
	E_ATTACH_VERIFY     FailureCode = "E_ATTACH_VERIFY"
	E_PIN_ROOT_UNSAFE   FailureCode = "E_PIN_ROOT_UNSAFE"
	E_PROBE             FailureCode = "E_PROBE"
	E_PRIVDROP          FailureCode = "E_PRIVDROP"
	E_PROBE_UID         FailureCode = "E_PROBE_UID"
)

// PreflightError carries the failure code of the gate or validation that
// failed, together with the underlying cause. Callers inspect it with
// errors.As; the cause remains reachable through errors.Is.
type PreflightError struct {
	// Code is the stable E_* identifier of the failure.
	Code FailureCode
	// Gate names the gate or validation that produced the failure (e.g. "P5", "V2").
	Gate string
	// Err is the underlying cause, if any.
	Err error
}

// Error implements the error interface.
func (e *PreflightError) Error() string {
	msg := "capture: " + string(e.Code)
	if e.Gate != "" {
		msg += " (" + e.Gate + ")"
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// Unwrap exposes the underlying cause to errors.Is and errors.As.
func (e *PreflightError) Unwrap() error { return e.Err }

// newPreflightError builds a *PreflightError for the given gate and code.
func newPreflightError(gate string, code FailureCode, err error) *PreflightError {
	return &PreflightError{Code: code, Gate: gate, Err: err}
}
