package capture

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// PreflightSeams carries every operating-system and kernel dependency the
// preflight gates need. Production wiring supplies the Linux implementations;
// tests supply plain-struct fakes, so the gate logic itself is platform
// neutral and fully testable on any host.
type PreflightSeams struct {
	// Cgo answers gate P1.
	Cgo CgoProbe
	// Uname answers gate P2.
	Uname UnameReader
	// FSMagic answers gates P3 and P4.
	FSMagic FSMagicProber
	// BPFFS answers gate P6.
	BPFFS BPFFSMounter
	// Capabilities answers gate P7.
	Capabilities CapabilityProber
	// Memlock answers gate P8.
	Memlock MemlockRaiser
	// Cgroup answers gate P5.
	Cgroup CgroupResolver
	// Loader answers gate P9.
	Loader ProgramLoader
	// Config answers gate P10.
	Config ConfigMapAccessor
	// Attacher answers gate P11.
	Attacher CgroupAttacher
	// PinRoot answers gate P15.
	PinRoot PinRootStater
	// Redirect answers gate P12.
	Redirect RedirectProber
	// PrivDrop answers gate P13.
	PrivDrop PrivilegeDropper
	// UIDExclusion answers gate P14.
	UIDExclusion UIDExclusionProber
}

// Capabilities required by gate P7, in the order they are probed.
var requiredCapabilities = []string{"CAP_BPF", "CAP_NET_ADMIN"}

// RunEnvironmentPreflight executes only the environment-validation gates
// P1-P8: the pure checks that must reject a bad environment before any kernel
// object is created. It runs opts.Validate() and then P1, P2, P3/P4, P5, P6,
// P7, P8 in that order, stopping at the first failure. Production wires it
// ahead of the eager LoadAndAttach so a mis-scoped AKSH_CAPTURE_POD_PATH or a
// missing capability is rejected before anything is loaded or attached; the
// later P9-P15 gates load programs, attach and drop privileges, which
// production already performs through LoadAndAttach and the orchestrator, so
// running them here would double-load and double-attach.
//
// Every failure is a *PreflightError carrying the stable E_* code of the gate
// that rejected the environment, so a caller can map the outcome onto an
// operator-facing diagnosis without string matching.
func RunEnvironmentPreflight(opts *Options, seams PreflightSeams) error {
	if opts == nil {
		return ErrMissingConfig
	}
	if err := opts.Validate(); err != nil {
		return err
	}

	if err := gateP1(seams); err != nil {
		return err
	}
	if err := gateP2(opts, seams); err != nil {
		return err
	}
	if err := gateP3P4(opts, seams); err != nil {
		return err
	}
	if err := gateP5(opts, seams); err != nil {
		return err
	}
	if err := gateP6(opts, seams); err != nil {
		return err
	}
	if err := gateP7(seams); err != nil {
		return err
	}
	if err := gateP8(seams); err != nil {
		return err
	}
	return nil
}

// RunPreflight executes the startup gates of design section 6.7 in order and
// stops at the first failure. Every failure is a *PreflightError carrying the
// stable E_* code of the gate that rejected the environment, so a caller can
// map the outcome onto an operator-facing diagnosis without string matching.
//
// It is the environment gates P1-P8 (RunEnvironmentPreflight) followed by the
// kernel-object gates P9-P15; the split lets production run the environment
// gates alone before the eager LoadAndAttach without re-loading or re-attaching.
func RunPreflight(opts *Options, seams PreflightSeams) error {
	if err := RunEnvironmentPreflight(opts, seams); err != nil {
		return err
	}
	if err := gateP9(seams); err != nil {
		return err
	}
	if err := gateP10(opts, seams); err != nil {
		return err
	}
	if err := gateP11(opts, seams); err != nil {
		return err
	}
	if err := gateP15(opts, seams); err != nil {
		return err
	}
	if err := gateP12(opts, seams); err != nil {
		return err
	}
	if err := gateP13(opts, seams); err != nil {
		return err
	}
	if err := gateP14(opts, seams); err != nil {
		return err
	}
	return nil
}

// gateP1 requires a pure-Go build. syscall.AllThreadsSyscall, which the
// privilege drop of design section 6.6.2 depends on, refuses to run when the
// binary was linked with cgo.
func gateP1(seams PreflightSeams) error {
	if seams.Cgo == nil {
		return newPreflightError("P1", E_CGO_ENABLED, errors.New("no cgo probe configured"))
	}
	if seams.Cgo.CgoEnabled() {
		return newPreflightError("P1", E_CGO_ENABLED,
			errors.New("binary was built with cgo; syscall.AllThreadsSyscall requires CGO_ENABLED=0"))
	}
	return nil
}

// gateP2 enforces the kernel floor. cgroup/connect4 with the bpf_sk_lookup and
// sockops support this design relies on is only dependable from 5.15.
func gateP2(opts *Options, seams PreflightSeams) error {
	if seams.Uname == nil {
		return newPreflightError("P2", E_KERNEL_TOO_OLD, errors.New("no uname reader configured"))
	}
	release, err := seams.Uname.Release()
	if err != nil {
		return newPreflightError("P2", E_KERNEL_TOO_OLD, err)
	}
	got, err := ParseKernelVersion(release)
	if err != nil {
		return newPreflightError("P2", E_KERNEL_TOO_OLD, err)
	}
	floor := opts.MinKernel
	if floor == (KernelVersion{}) {
		floor = MinSupportedKernel()
	}
	if !got.AtLeast(floor) {
		return newPreflightError("P2", E_KERNEL_TOO_OLD,
			fmt.Errorf("kernel %s is below the %s floor", got, floor))
	}
	return nil
}

// gateP3P4 requires both the local and the host cgroup mounts to be cgroup2.
// A v1 hierarchy silently changes what an attachment means, so it is rejected
// rather than tolerated.
func gateP3P4(opts *Options, seams PreflightSeams) error {
	if seams.FSMagic == nil {
		return newPreflightError("P3", E_NO_CGROUP2, errors.New("no filesystem magic prober configured"))
	}
	for _, m := range []struct {
		gate string
		path string
	}{
		{"P3", opts.LocalCgroupMount},
		{"P4", opts.HostCgroupMount},
	} {
		magic, err := seams.FSMagic.FSMagic(m.path)
		if err != nil {
			return newPreflightError(m.gate, E_NO_CGROUP2, err)
		}
		if magic != Cgroup2SuperMagic {
			return newPreflightError(m.gate, E_NO_CGROUP2,
				fmt.Errorf("%s has filesystem magic %#x, want cgroup2 %#x", m.path, magic, Cgroup2SuperMagic))
		}
	}
	return nil
}

// gateP5 resolves the pod cgroup. Resolution failures already carry their own
// E_* code (V1-V8 of design section 6.1.3); the code is propagated unchanged so
// that the operator sees which scope assertion rejected the path.
func gateP5(opts *Options, seams PreflightSeams) error {
	if seams.Cgroup == nil {
		return newPreflightError("P5", E_CGROUP_SCOPE, errors.New("no cgroup resolver configured"))
	}
	if _, err := seams.Cgroup.ResolvePodCgroup(opts.PodPath); err != nil {
		var pfErr *PreflightError
		if errors.As(err, &pfErr) {
			return err
		}
		return newPreflightError("P5", E_CGROUP_SCOPE, err)
	}
	return nil
}

// gateP6 requires a bpffs mount. It is only created here when the deployer
// opted in with MountBPFFS; otherwise an absent mount is a hard failure, since
// silently continuing would leave links unpinned without saying so.
func gateP6(opts *Options, seams PreflightSeams) error {
	if seams.BPFFS == nil {
		return newPreflightError("P6", E_NO_BPFFS, errors.New("no bpffs mounter configured"))
	}
	mounted, err := seams.BPFFS.IsBPFFSMounted(opts.PinRoot)
	if err != nil {
		return newPreflightError("P6", E_NO_BPFFS, err)
	}
	if mounted {
		return nil
	}
	if !opts.MountBPFFS {
		return newPreflightError("P6", E_NO_BPFFS,
			fmt.Errorf("%s is not a bpffs mount and MountBPFFS is disabled", opts.PinRoot))
	}
	if err := seams.BPFFS.MountBPFFS(opts.PinRoot); err != nil {
		return newPreflightError("P6", E_NO_BPFFS, err)
	}
	return nil
}

// gateP7 requires the capabilities the load and attach need. Discovering the
// absence here produces a named failure instead of an opaque EPERM later.
func gateP7(seams PreflightSeams) error {
	if seams.Capabilities == nil {
		return newPreflightError("P7", E_MISSING_CAPS, errors.New("no capability prober configured"))
	}
	for _, name := range requiredCapabilities {
		held, err := seams.Capabilities.HasCapability(name)
		if err != nil {
			return newPreflightError("P7", E_MISSING_CAPS, err)
		}
		if !held {
			return newPreflightError("P7", E_MISSING_CAPS, fmt.Errorf("%s is not in the effective set", name))
		}
	}
	return nil
}

// gateP8 raises RLIMIT_MEMLOCK so that map creation is not charged against a
// default 64 KiB budget on older kernels.
func gateP8(seams PreflightSeams) error {
	if seams.Memlock == nil {
		return newPreflightError("P8", E_MEMLOCK, errors.New("no memlock raiser configured"))
	}
	if err := seams.Memlock.RemoveMemlock(); err != nil {
		return newPreflightError("P8", E_MEMLOCK, err)
	}
	return nil
}

// ConfigImageSize is the wire size of the aksh_config map value. Gate P10
// compares every byte of the readback against this many written bytes.
const ConfigImageSize = 32

// gateP9 loads and verifies the programs. Doing it before any attachment means
// a verifier rejection is reported as E_PROG_LOAD rather than surfacing later
// as an attach failure with no useful cause.
func gateP9(seams PreflightSeams) error {
	if seams.Loader == nil {
		return newPreflightError("P9", E_PROG_LOAD, errors.New("no program loader configured"))
	}
	if _, err := seams.Loader.LoadPrograms(); err != nil {
		return newPreflightError("P9", E_PROG_LOAD, err)
	}
	return nil
}

// gateP10 writes the configuration, reads it back byte for byte and freezes the
// map. The readback is not redundant: a silently truncated or byte-swapped
// write would otherwise make the datapath act on a configuration nobody chose.
func gateP10(opts *Options, seams PreflightSeams) error {
	if seams.Config == nil {
		return newPreflightError("P10", E_CONFIG_WRITE, errors.New("no config map accessor configured"))
	}
	image, err := buildConfigImage(opts)
	if err != nil {
		return newPreflightError("P10", E_CONFIG_WRITE, err)
	}
	if err := seams.Config.WriteConfig(image); err != nil {
		return newPreflightError("P10", E_CONFIG_WRITE, err)
	}
	readback, err := seams.Config.ReadConfig()
	if err != nil {
		return newPreflightError("P10", E_CONFIG_WRITE, err)
	}
	if !bytes.Equal(image, readback) {
		return newPreflightError("P10", E_CONFIG_WRITE,
			fmt.Errorf("config readback %x differs from the written image %x", readback, image))
	}
	if err := seams.Config.FreezeConfig(); err != nil {
		return newPreflightError("P10", E_CONFIG_FREEZE, err)
	}
	return nil
}

// gateP11 attaches the programs and then asks the kernel which programs are
// actually attached there. Trusting the attach call alone would leave a
// half-attached cgroup indistinguishable from a healthy one.
func gateP11(opts *Options, seams PreflightSeams) error {
	if seams.Attacher == nil {
		return newPreflightError("P11", E_ATTACH, errors.New("no cgroup attacher configured"))
	}
	attached, err := seams.Attacher.Attach(opts.PodPath)
	if err != nil {
		return newPreflightError("P11", E_ATTACH, err)
	}
	observed, err := seams.Attacher.AttachedProgIDs(opts.PodPath)
	if err != nil {
		return newPreflightError("P11", E_ATTACH_VERIFY, err)
	}
	if !sameProgIDs(attached, observed) {
		return newPreflightError("P11", E_ATTACH_VERIFY,
			fmt.Errorf("kernel reports attached program ids %v, want %v", observed, attached))
	}
	return nil
}

// gateP15 checks the pin root's ownership before anything is pinned into it
// (MC-S1a-01). A world-writable or non-root-owned pin root would let an
// unprivileged process replace the pinned links after the drop.
func gateP15(opts *Options, seams PreflightSeams) error {
	if !opts.PinLinks {
		return nil
	}
	if seams.PinRoot == nil {
		return newPreflightError("P15", E_PIN_ROOT_UNSAFE, errors.New("no pin root stater configured"))
	}
	info, err := seams.PinRoot.StatPinRoot(opts.PinRoot)
	if err != nil {
		return newPreflightError("P15", E_PIN_ROOT_UNSAFE, err)
	}
	switch {
	case !info.IsDir:
		return newPreflightError("P15", E_PIN_ROOT_UNSAFE, fmt.Errorf("%s is not a directory", opts.PinRoot))
	case info.UID != 0:
		return newPreflightError("P15", E_PIN_ROOT_UNSAFE,
			fmt.Errorf("%s is owned by uid %d, want 0", opts.PinRoot, info.UID))
	case info.Mode&0o077 != 0:
		return newPreflightError("P15", E_PIN_ROOT_UNSAFE,
			fmt.Errorf("%s has mode %#o, want no group or other access", opts.PinRoot, info.Mode))
	}
	return nil
}

// gateP12 proves that redirection actually happens, rather than assuming it.
// It is skipped only when the deployer accepted that trade with
// AllowUnsafeStartup, which Validate() enforces.
func gateP12(opts *Options, seams PreflightSeams) error {
	if !opts.RunProbe {
		return nil
	}
	if seams.Redirect == nil {
		return newPreflightError("P12", E_PROBE, errors.New("no redirect prober configured"))
	}
	if err := seams.Redirect.ProbeRedirect(); err != nil {
		return newPreflightError("P12", E_PROBE, err)
	}
	return nil
}

// gateP13 drops privileges. It runs after every privileged operation and
// before the UID-exclusion probe, so the probe observes the same identity the
// proxy will run under.
func gateP13(opts *Options, seams PreflightSeams) error {
	if seams.PrivDrop == nil {
		return newPreflightError("P13", E_PRIVDROP, errors.New("no privilege dropper configured"))
	}
	cfg := PrivDropConfig{
		ProxyUID:         opts.ProxyUID,
		ProxyGID:         opts.ProxyGID,
		KeepCapabilities: []string{"CAP_BPF"},
		NoNewPrivs:       true,
	}
	if err := seams.PrivDrop.DropPrivileges(cfg); err != nil {
		return newPreflightError("P13", E_PRIVDROP, err)
	}
	return nil
}

// gateP14 proves the proxy's own UID is excluded from capture, which is what
// keeps the datapath from looping its own egress back into itself (T2).
func gateP14(opts *Options, seams PreflightSeams) error {
	if !opts.RunProbe {
		return nil
	}
	if seams.UIDExclusion == nil {
		return newPreflightError("P14", E_PROBE_UID, errors.New("no uid-exclusion prober configured"))
	}
	if err := seams.UIDExclusion.ProbeUIDExclusion(); err != nil {
		return newPreflightError("P14", E_PROBE_UID, err)
	}
	return nil
}

// sameProgIDs reports whether two program-id lists hold the same ids,
// irrespective of the order the kernel reports them in.
func sameProgIDs(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]uint32(nil), a...)
	y := append([]uint32(nil), b...)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

// buildConfigImage renders Options into the 32-byte aksh_config value. The
// address and port fields carry network-order bytes reinterpreted as native
// words, exactly as the C program reads them (design section 6.4.3).
func buildConfigImage(opts *Options) ([]byte, error) {
	cfg := akshConfig{
		ProxyUID: opts.ProxyUID,
		Flags:    flagCaptureEnabled,
	}
	if opts.BlockNonTCP {
		cfg.Flags |= flagBlockNonTCP
	}
	if !opts.CaptureIPv6 {
		cfg.Flags |= flagDenyIPv6
	}
	if opts.ListenerAddr.IsValid() {
		addr := opts.ListenerAddr.Addr().Unmap()
		if !addr.Is4() {
			return nil, fmt.Errorf("capture: ListenerAddr=%v: %w", opts.ListenerAddr, ErrInvalidListenerAddr)
		}
		a4 := addr.As4()
		cfg.ListenerIP4 = binary.NativeEndian.Uint32(a4[:])
		cfg.ListenerPort = htons(opts.ListenerAddr.Port())
	}
	if opts.DNSServer.IsValid() {
		addr := opts.DNSServer.Addr().Unmap()
		if !addr.Is4() {
			return nil, fmt.Errorf("capture: DNSServer=%v: %w", opts.DNSServer, ErrInvalidDNSServer)
		}
		a4 := addr.As4()
		cfg.DNSIP4 = binary.NativeEndian.Uint32(a4[:])
		cfg.DNSPort = htons(opts.DNSServer.Port())
	}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.NativeEndian, &cfg); err != nil {
		return nil, err
	}
	if buf.Len() != ConfigImageSize {
		return nil, fmt.Errorf("capture: config image is %d bytes, want %d", buf.Len(), ConfigImageSize)
	}
	return buf.Bytes(), nil
}

// ParseKernelVersion extracts the major and minor numbers from a uname release
// string such as "5.15.0-1064-azure". Vendor suffixes are ignored: only the
// numeric prefix decides gate P2.
func ParseKernelVersion(release string) (KernelVersion, error) {
	trimmed := strings.TrimSpace(release)
	if trimmed == "" {
		return KernelVersion{}, errors.New("capture: empty kernel release string")
	}
	fields := strings.SplitN(trimmed, ".", 3)
	if len(fields) < 2 {
		return KernelVersion{}, fmt.Errorf("capture: kernel release %q has no minor version", release)
	}
	major, err := strconv.Atoi(numericPrefix(fields[0]))
	if err != nil {
		return KernelVersion{}, fmt.Errorf("capture: kernel release %q has no numeric major version", release)
	}
	minor, err := strconv.Atoi(numericPrefix(fields[1]))
	if err != nil {
		return KernelVersion{}, fmt.Errorf("capture: kernel release %q has no numeric minor version", release)
	}
	return KernelVersion{Major: major, Minor: minor}, nil
}

// numericPrefix returns the leading run of decimal digits in s.
func numericPrefix(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return s[:i]
		}
	}
	return s
}
