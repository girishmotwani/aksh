//go:build linux

package capture

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// This file supplies the production implementations of the P1-P8 environment
// seams. They are the only preflight seams with production wiring: P9-P15 load
// programs, write the config map, attach, probe redirection and drop
// privileges, all of which production already performs through LoadAndAttach
// and the orchestrator, so re-implementing them here would double-load and
// double-attach. Every implementation is a thin, testable wrapper over one
// operating-system primitive so that the gate logic in preflight.go stays
// platform neutral.

// procSelfStatus is the file the capability prober parses. It is a field
// default rather than a hard-coded read so tests can point the prober at a
// crafted status file without a real capability set.
const procSelfStatus = "/proc/self/status"

// productionCgoProbe answers gate P1 from the actual build state via cgoLinked,
// which is resolved at compile time by the cgo/!cgo build-tagged files. It
// deliberately reads no environment variable: CGO_ENABLED can disagree with the
// binary that was actually produced, and P1 must reflect the binary (issue #66).
type productionCgoProbe struct{}

// CgoEnabled reports whether this binary was linked with cgo.
func (productionCgoProbe) CgoEnabled() bool { return cgoLinked() }

// unameReader answers gate P2 by reading the kernel release with uname(2). The
// release field is a NUL-terminated C string in a fixed-size array, so the
// trailing NULs are trimmed before it is parsed.
type unameReader struct{}

// Release returns the running kernel's release string.
func (unameReader) Release() (string, error) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "", fmt.Errorf("capture: uname: %w", err)
	}
	return unix.ByteSliceToString(u.Release[:]), nil
}

// statfsProber answers gates P3/P4 (and V1 inside the resolver) by reporting the
// filesystem magic of a path with statfs(2).
type statfsProber struct{}

// FSMagic returns the statfs f_type of path as an unsigned 32-bit value.
func (statfsProber) FSMagic(path string) (uint32, error) {
	var sfs unix.Statfs_t
	if err := unix.Statfs(path, &sfs); err != nil {
		return 0, fmt.Errorf("capture: statfs %q: %w", path, err)
	}
	return uint32(sfs.Type), nil
}

// bpffsMounter answers gate P6. It observes the pin root with statfs(2) and, when
// the deployer opted in, creates the bpffs mount there.
type bpffsMounter struct{}

// IsBPFFSMounted reports whether path is a bpffs mount by comparing its statfs
// magic against BPFFSMagic.
func (bpffsMounter) IsBPFFSMounted(path string) (bool, error) {
	var sfs unix.Statfs_t
	if err := unix.Statfs(path, &sfs); err != nil {
		return false, fmt.Errorf("capture: statfs %q: %w", path, err)
	}
	return uint32(sfs.Type) == BPFFSMagic, nil
}

// MountBPFFS mounts a bpffs at path.
func (bpffsMounter) MountBPFFS(path string) error {
	if err := unix.Mount("bpffs", path, "bpf", 0, ""); err != nil {
		return fmt.Errorf("capture: mount bpffs at %q: %w", path, err)
	}
	return nil
}

// procCapabilityProber answers gate P7 by parsing the effective capability set
// (CapEff) out of /proc/self/status. The capability name is resolved through the
// package's existing capNameToBit table (privdrop_linux.go) so the two places
// that speak capability names cannot drift apart; an unknown name is a hard
// error rather than a silent false, so a typo can never make P7 pass vacuously.
type procCapabilityProber struct {
	// statusPath is the /proc/self/status file to parse; empty means the real one.
	statusPath string
}

// HasCapability reports whether name is in the effective capability set.
func (p procCapabilityProber) HasCapability(name string) (bool, error) {
	bit, ok := capNameToBit[name]
	if !ok {
		return false, fmt.Errorf("capture: unknown capability %q", name)
	}
	path := p.statusPath
	if path == "" {
		path = procSelfStatus
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("capture: read %q: %w", path, err)
	}
	eff, err := parseCapEff(raw)
	if err != nil {
		return false, err
	}
	return eff&(uint64(1)<<bit) != 0, nil
}

// parseCapEff extracts the CapEff hexadecimal bitmask from a /proc/<pid>/status
// image. A missing or malformed CapEff line is a hard error so the prober fails
// closed rather than reporting every capability as absent.
func parseCapEff(status []byte) (uint64, error) {
	const prefix = "CapEff:"
	scanner := bufio.NewScanner(bytes.NewReader(status))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		field := strings.TrimSpace(strings.TrimPrefix(line, prefix))
		var mask uint64
		if _, err := fmt.Sscanf(field, "%x", &mask); err != nil {
			return 0, fmt.Errorf("capture: malformed CapEff %q: %w", field, err)
		}
		return mask, nil
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("capture: scan process status: %w", err)
	}
	return 0, fmt.Errorf("capture: no CapEff line in process status")
}

// memlockRaiser answers gate P8 by wrapping rlimit.RemoveMemlock, which raises
// RLIMIT_MEMLOCK where it still applies and is a no-op on kernels that account
// BPF memory to the memory cgroup. It is safe to call more than once.
type memlockRaiser struct{}

// RemoveMemlock raises RLIMIT_MEMLOCK so a map or program allocation cannot be
// refused for want of locked memory.
func (memlockRaiser) RemoveMemlock() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("capture: remove memlock: %w", err)
	}
	return nil
}

// NewProductionPreflightSeams builds the P1-P8 environment seams for
// RunEnvironmentPreflight from opts. Only the environment seams are populated;
// the P9-P15 kernel-object seams are deliberately left nil because production
// performs that work through LoadAndAttach and the orchestrator, and
// RunEnvironmentPreflight never reads them. The cgroup resolver's non-fatal
// V7/V8 warnings have no sink here because the builder receives no logger; the
// caller wires the fatal checks, which is what the security boundary needs.
func NewProductionPreflightSeams(opts *Options) (PreflightSeams, error) {
	if opts == nil {
		return PreflightSeams{}, ErrMissingOptions
	}
	fsMagic := statfsProber{}
	resolver, err := NewPodCgroupResolver(&PodCgroupResolverConfig{
		HostCgroupMount:  opts.HostCgroupMount,
		LocalCgroupMount: opts.LocalCgroupMount,
		ProcCgroupPath:   opts.ProcCgroupPath,
		ProxyPID:         os.Getpid(),
		FSMagic:          fsMagic,
		Inode:            statInodeProber{},
		Dirs:             osCgroupDirReader{},
	})
	if err != nil {
		return PreflightSeams{}, err
	}
	return PreflightSeams{
		Cgo:          productionCgoProbe{},
		Uname:        unameReader{},
		FSMagic:      fsMagic,
		BPFFS:        bpffsMounter{},
		Capabilities: procCapabilityProber{},
		Memlock:      memlockRaiser{},
		Cgroup:       resolver,
	}, nil
}
