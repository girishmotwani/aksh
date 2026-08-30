package capture

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
)

// Default values from design sections 13.1 and 18.
const (
	defaultProxyUID            uint32        = 1774
	defaultProxyGID            uint32        = 1774
	defaultProcCgroupPath                    = "/proc/self/cgroup"
	defaultLocalCgroupMount                  = "/sys/fs/cgroup"
	defaultHostCgroupMount                   = "/host/sys/fs/cgroup"
	defaultPinRoot                           = "/sys/fs/bpf"
	defaultMapEntries          uint32        = 16384
	defaultDestMaxAge          time.Duration = 15 * time.Second
	defaultAttachCheckInterval time.Duration = 30 * time.Second
)

// Bounds from design section 13.1. AttachCheckInterval has no AllowUnsafeStartup
// escape hatch: the check is half of MC-S1a-01.
const (
	minMapEntries          uint32        = 1024
	maxMapEntries          uint32        = 65536
	minDestMaxAge          time.Duration = 1 * time.Second
	maxDestMaxAge          time.Duration = 120 * time.Second
	minAttachCheckInterval time.Duration = 10 * time.Second
	maxAttachCheckInterval time.Duration = 60 * time.Second
)

// Bounds on the capture bypass list. A bypassed prefix is unpoliced, so these
// exist to keep a configuration mistake from becoming a silent hole.
//
// minBypassPrefixBits is 8 because that is the shortest prefix that can still
// be described as "an address range this deployment owns": a Kubernetes service
// CIDR is conventionally a /12 or /16 and a pod CIDR a /16, while /0 through /7
// are wide enough to cover an arbitrary internet destination and would turn
// capture off for it. maxBypassCIDRs matches the LPM trie's max_entries in
// aksh_capture.c, so a list that the kernel could not hold is refused before
// any privileged work rather than half-written.
const (
	minBypassPrefixBits = 8
	maxBypassCIDRs      = 64
)

// KernelVersion is a major/minor kernel version, compared numerically so that
// vendor suffixes cannot affect the gate P2 decision.
type KernelVersion struct {
	Major int
	Minor int
}

// String renders the version as "major.minor".
func (v KernelVersion) String() string { return fmt.Sprintf("%d.%d", v.Major, v.Minor) }

// AtLeast reports whether v is at or above floor.
func (v KernelVersion) AtLeast(floor KernelVersion) bool {
	if v.Major != floor.Major {
		return v.Major > floor.Major
	}
	return v.Minor >= floor.Minor
}

// The 5A kernel floor. cgroup/connect4 with the bpf_sk_lookup and sockops
// support this design relies on is only dependable from 5.15, so the floor is
// not configurable below it.
const (
	minSupportedKernelMajor = 5
	minSupportedKernelMinor = 15
)

// MinSupportedKernel returns the 5A kernel floor. It is a function rather than
// a package-level var because Go has no struct constants and a var would let
// any caller lower the floor at run time; KernelVersion is a value type, so the
// returned copy cannot affect anything else.
func MinSupportedKernel() KernelVersion {
	return KernelVersion{Major: minSupportedKernelMajor, Minor: minSupportedKernelMinor}
}

// Options configures the capture layer. Validate() runs before preflight, so a
// configuration error is reported before any privileged work happens.
type Options struct {
	// PodPath is the resolved pod cgroup the programs attach to.
	PodPath string
	// HostCgroupMount is the read-only bind of the host cgroup2 root.
	HostCgroupMount string
	// LocalCgroupMount is the proxy's own cgroup2 mount.
	LocalCgroupMount string
	// ProcCgroupPath is the process cgroup file used for resolution.
	ProcCgroupPath string
	// Metrics receives the capture-layer counters; it is mandatory.
	Metrics audit.MetricsRecorder
	// ProxyUID is the uid the proxy drops to and the uid the capture programs
	// exclude. It must never be zero.
	ProxyUID uint32
	// ProxyGID is the primary group the proxy drops to.
	ProxyGID uint32
	// ListenerAddr is where captured connections are redirected. The zero value
	// selects the default; a set value must be IPv4 loopback.
	ListenerAddr netip.AddrPort
	// DNSServer is the DEV-01 DNS exception; the zero value disables it.
	DNSServer netip.AddrPort
	// BypassCIDRs lists IPv4 destination prefixes that are never redirected
	// and therefore never policed. It exists so that a pod can reach its own
	// in-cluster control plane (its agent framework's scheduler, a local tool
	// server, a metrics endpoint) over plaintext, which aksh would otherwise
	// capture and reject T9.
	//
	// Every entry is a deliberate hole in INV-3, so the bounds below are not
	// negotiable and there is no AllowUnsafeStartup escape hatch: a prefix
	// shorter than minBypassPrefixBits, or more than maxBypassCIDRs entries,
	// is rejected outright. Empty is the default and preserves the pre-bypass
	// behaviour exactly.
	BypassCIDRs []netip.Prefix
	// CaptureIPv6 requests IPv6 capture, which 5A does not implement.
	CaptureIPv6 bool
	// MountBPFFS lets preflight gate P6 mount bpffs when it is absent.
	MountBPFFS bool
	// BlockNonTCP blocks non-TCP egress in the cgroup socket hooks. Disabling it
	// is an INV-3 hole and requires AllowUnsafeStartup.
	BlockNonTCP bool
	// RunProbe gates the P12 redirect and P14 UID-exclusion probes. Disabling it
	// means capture is assumed rather than proved and requires AllowUnsafeStartup.
	RunProbe bool
	// AllowUnsafeStartup permits the fail-open combinations above. Test-only.
	AllowUnsafeStartup bool
	// AttachCheckInterval is the attachment health-check period. It must be
	// within [10s, 60s]; there is no escape hatch.
	AttachCheckInterval time.Duration
	// PinLinks pins the attached links to bpffs. It defaults to false because
	// pre-merge kernel gate M1 is unverified (design section 6.7.3).
	PinLinks bool
	// PinRoot is the bpffs mount holding pinned links; required when PinLinks is set.
	PinRoot string
	// PinRootPrivate records that the deployer mounted a bpffs for this pod
	// alone. It relaxes nothing and is logged in the startup summary.
	PinRootPrivate bool
	// MapEntries sizes the destination maps; range [1024, 65536].
	MapEntries uint32
	// DestMaxAge bounds destination-record freshness; range [1s, 120s].
	DestMaxAge time.Duration
	// MinKernel is the kernel floor enforced by gate P2.
	MinKernel KernelVersion
	// Context bounds the load and the attachment health-check goroutine started
	// by LoadAndAttach. LoadAndAttach takes no context parameter (its signature
	// is frozen), so cancellation of a load in progress and shutdown of the
	// health loop are driven through this field; a nil Context means
	// context.Background().
	Context context.Context
}

// DefaultOptions returns the design defaults. The two fields with no safe
// default (PodPath and Metrics) are deliberately left unset, so the returned
// value does not pass Validate() on its own. HostCgroupMount is mandatory too
// but has a conventional deployment path, so it is defaulted here and only
// rejected when a caller clears it.
func DefaultOptions() Options {
	return Options{
		LocalCgroupMount:    defaultLocalCgroupMount,
		ProcCgroupPath:      defaultProcCgroupPath,
		HostCgroupMount:     defaultHostCgroupMount,
		ProxyUID:            defaultProxyUID,
		ProxyGID:            defaultProxyGID,
		ListenerAddr:        netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 15001),
		CaptureIPv6:         false,
		MountBPFFS:          false,
		BlockNonTCP:         true,
		RunProbe:            true,
		AllowUnsafeStartup:  false,
		AttachCheckInterval: defaultAttachCheckInterval,
		PinLinks:            false,
		PinRoot:             defaultPinRoot,
		MapEntries:          defaultMapEntries,
		DestMaxAge:          defaultDestMaxAge,
		MinKernel:           MinSupportedKernel(),
	}
}

// Validate returns the first configuration error, in a fixed order: the
// mandatory fields first, then the security controls of design section 18.
// Numeric fields left at their zero value are treated as "use the default" and
// are not range-checked; AttachCheckInterval is the deliberate exception,
// because zero must be rejected outright (MC-S1a-01).
func (o *Options) Validate() error {
	if o == nil {
		return ErrMissingConfig
	}
	if o.PodPath == "" {
		return ErrMissingPodPath
	}
	if o.HostCgroupMount == "" {
		return ErrMissingHostMount
	}
	if o.Metrics == nil {
		return ErrMissingMetrics
	}
	if o.ProxyUID == 0 {
		return ErrInvalidProxyUID
	}
	if o.CaptureIPv6 {
		return ErrIPv6Unsupported
	}
	if !o.BlockNonTCP && !o.AllowUnsafeStartup {
		return fmt.Errorf("BlockNonTCP=false leaves an INV-3 hole: %w", ErrRequiresUnsafeStartup)
	}
	if !o.RunProbe && !o.AllowUnsafeStartup {
		return fmt.Errorf("RunProbe=false assumes capture rather than proving it: %w", ErrRequiresUnsafeStartup)
	}
	if o.AttachCheckInterval < minAttachCheckInterval || o.AttachCheckInterval > maxAttachCheckInterval {
		return fmt.Errorf("AttachCheckInterval=%v is outside [%v, %v]: %w",
			o.AttachCheckInterval, minAttachCheckInterval, maxAttachCheckInterval, ErrInvalidAttachCheckInterval)
	}
	if o.PinLinks && o.PinRoot == "" {
		return ErrMissingPinRoot
	}
	if o.ListenerAddr.IsValid() {
		// Both checks run on the unmapped address: ::ffff:127.0.0.1 is the
		// IPv4 loopback address, and Addr.IsLoopback() answers false for the
		// 4-in-6 spelling of it.
		addr := o.ListenerAddr.Addr().Unmap()
		if !addr.Is4() || !addr.IsLoopback() {
			return fmt.Errorf("ListenerAddr=%v: %w", o.ListenerAddr, ErrInvalidListenerAddr)
		}
	}
	// The DEV-01 DNS exception is written into a 32-bit IPv4 field of
	// aksh_config, so a set DNSServer must be an IPv4 address with a real
	// port. Without this check an IPv6 value reaches netip.Addr.As4() in
	// buildConfigImage and panics.
	if o.DNSServer.IsValid() {
		addr := o.DNSServer.Addr().Unmap()
		if !addr.Is4() || o.DNSServer.Port() == 0 {
			return fmt.Errorf("DNSServer=%v: %w", o.DNSServer, ErrInvalidDNSServer)
		}
	}
	if err := validateBypassCIDRs(o.BypassCIDRs); err != nil {
		return err
	}
	if o.MapEntries != 0 && (o.MapEntries < minMapEntries || o.MapEntries > maxMapEntries) {
		return fmt.Errorf("MapEntries=%d is outside [%d, %d]: %w", o.MapEntries, minMapEntries, maxMapEntries, ErrInvalidMapEntries)
	}
	if o.DestMaxAge != 0 && (o.DestMaxAge < minDestMaxAge || o.DestMaxAge > maxDestMaxAge) {
		return fmt.Errorf("DestMaxAge=%v is outside [%v, %v]: %w", o.DestMaxAge, minDestMaxAge, maxDestMaxAge, ErrInvalidDestMaxAge)
	}
	return nil
}

// validateBypassCIDRs enforces the bounds on the unpoliced-destination list.
//
// It rejects rather than sanitises. A prefix whose host bits are set (say
// 10.0.0.5/8) is very likely a typo for a single host, and silently masking it
// to 10.0.0.0/8 would hand the deployer a hole 16 million addresses wider than
// the one they thought they asked for.
func validateBypassCIDRs(prefixes []netip.Prefix) error {
	if len(prefixes) > maxBypassCIDRs {
		return fmt.Errorf("BypassCIDRs has %d entries, more than the %d the kernel map holds: %w",
			len(prefixes), maxBypassCIDRs, ErrInvalidBypassCIDR)
	}
	for _, p := range prefixes {
		if _, err := canonicalBypassPrefix(p); err != nil {
			return fmt.Errorf("BypassCIDRs: %w", err)
		}
	}
	return nil
}
