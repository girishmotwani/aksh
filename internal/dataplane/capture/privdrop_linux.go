//go:build linux

package capture

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// capNameToBit maps the capability names this package accepts to their kernel
// bit numbers. Only the names named by design section 6.6.1 are needed: CAP_BPF
// is retained, and CAP_SETPCAP is raised transiently to shrink the bounding set.
var capNameToBit = map[string]uint{
	"CAP_BPF":       unix.CAP_BPF,
	"CAP_NET_ADMIN": unix.CAP_NET_ADMIN,
	"CAP_SETUID":    unix.CAP_SETUID,
	"CAP_SETGID":    unix.CAP_SETGID,
	"CAP_SETPCAP":   unix.CAP_SETPCAP,
}

// privDropSyscalls is the unexported, Linux-only seam over every operating-system
// primitive the drop touches. Production wires the real syscalls; the
// ebpf_integration tests replace individual fields so a step can be forced to
// fail or to no-op without performing a real, irreversible drop in the test
// process.
type privDropSyscalls struct {
	setKeepCaps      func(on bool) error
	setGroups        func(gids []uint32) error
	setGID           func(gid uint32) error
	setUID           func(uid uint32) error
	setCaps          func(caps []string) error
	dropBoundingCaps func(keep []string) error
	setNoNewPrivs    func() error

	getUID           func() uint32
	getEUID          func() uint32
	getGID           func() uint32
	getGroups        func() ([]uint32, error)
	getEffectiveCaps func() (uint64, error)
	getNoNewPrivs    func() (int, error)
	getKeepCaps      func() (int, error)
	getBoundingCaps  func() (uint64, error)
	probeSetUIDZero  func() error
}

// privDropSeam is the live seam DropPrivileges reads. It is a package variable
// so tests can swap fields; production initialises it to the real syscalls.
var privDropSeam = defaultPrivDropSyscalls()

func defaultPrivDropSyscalls() privDropSyscalls {
	return privDropSyscalls{
		setKeepCaps:      realSetKeepCaps,
		setGroups:        realSetGroups,
		setGID:           realSetGID,
		setUID:           realSetUID,
		setCaps:          realSetCaps,
		dropBoundingCaps: realDropBoundingCaps,
		setNoNewPrivs:    realSetNoNewPrivs,
		getUID:           func() uint32 { return uint32(unix.Getuid()) },
		getEUID:          func() uint32 { return uint32(unix.Geteuid()) },
		getGID:           func() uint32 { return uint32(unix.Getgid()) },
		getGroups:        realGetGroups,
		getEffectiveCaps: realGetEffectiveCaps,
		getNoNewPrivs:    realGetNoNewPrivs,
		getKeepCaps:      realGetKeepCaps,
		getBoundingCaps:  realGetBoundingCaps,
		probeSetUIDZero:  realProbeSetUIDZero,
	}
}

// DropPrivileges runs the privilege-drop sequence of design section 6.6.2
// (steps 3-11; steps 1-2 - the CGO_ENABLED=0 build and completing all privileged
// work - are the caller's responsibility). Every step is fail-closed: any OS
// error, or a final verification that finds the drop did not fully take, returns
// a *PreflightError carrying E_PRIVDROP so the caller aborts startup rather than
// continuing in a partially-dropped state.
func DropPrivileges(cfg PrivDropConfig) error {
	s := privDropSeam
	keep := cfg.KeepCapabilities

	// Step 3: retain the permitted set across the coming UID change; without
	// this the kernel clears it and step 7 would have nothing to retain.
	if err := s.setKeepCaps(true); err != nil {
		return privDropError(3, "PR_SET_KEEPCAPS(1)", err)
	}
	// Step 4: install the exact supplementary group set (empty clears them)
	// before setgid/setuid, while CAP_SETGID is still held.
	if err := s.setGroups(cfg.SupplementaryGIDs); err != nil {
		return privDropError(4, "setgroups", err)
	}
	// Step 5: group before user - after setuid CAP_SETGID is gone.
	if err := s.setGID(cfg.ProxyGID); err != nil {
		return privDropError(5, "setgid", err)
	}
	// Step 6: drop the UID on every thread.
	if err := s.setUID(cfg.ProxyUID); err != nil {
		return privDropError(6, "setuid", err)
	}
	// Step 7 (raise): the UID change cleared the effective set, so move the
	// retained caps back into it, plus the CAP_SETPCAP that PR_CAPBSET_DROP
	// requires. CAP_SETPCAP is removed again by the finalising capset below.
	if err := s.setCaps(withSetpcap(keep)); err != nil {
		return privDropError(7, "capset-raise", err)
	}
	// Step 8: shrink the bounding set to the kept caps, irreversibly.
	if err := s.dropBoundingCaps(keep); err != nil {
		return privDropError(8, "PR_CAPBSET_DROP", err)
	}
	// Step 7 (finalise): reduce the permitted and effective sets to exactly the
	// kept capabilities, dropping the transient CAP_SETPCAP.
	if err := s.setCaps(keep); err != nil {
		return privDropError(7, "capset-finalize", err)
	}
	// Step 9: clear KEEPCAPS so a later exec cannot inherit ambient caps.
	if err := s.setKeepCaps(false); err != nil {
		return privDropError(9, "PR_SET_KEEPCAPS(0)", err)
	}
	// Step 10: block privilege gain through exec.
	if cfg.NoNewPrivs {
		if err := s.setNoNewPrivs(); err != nil {
			return privDropError(10, "PR_SET_NO_NEW_PRIVS", err)
		}
	}
	// Step 11: prove the drop actually happened.
	return verifyDrop(s, cfg)
}

// verifyDrop is design section 6.6.2 step 11: it fails closed if the identity,
// groups or capabilities are not exactly the target, or if setuid(0) does not
// fail - the only direct proof the transition is irreversible.
func verifyDrop(s privDropSyscalls, cfg PrivDropConfig) error {
	if got := s.getUID(); got != cfg.ProxyUID {
		return privDropError(11, "verify getuid", fmt.Errorf("getuid()=%d, want %d", got, cfg.ProxyUID))
	}
	if got := s.getEUID(); got != cfg.ProxyUID {
		return privDropError(11, "verify geteuid", fmt.Errorf("geteuid()=%d, want %d", got, cfg.ProxyUID))
	}
	if got := s.getGID(); got != cfg.ProxyGID {
		return privDropError(11, "verify getgid", fmt.Errorf("getgid()=%d, want %d", got, cfg.ProxyGID))
	}
	groups, err := s.getGroups()
	if err != nil {
		return privDropError(11, "verify getgroups", err)
	}
	if !sameGroupSet(groups, cfg.SupplementaryGIDs) {
		return privDropError(11, "verify getgroups", fmt.Errorf("groups=%v, want %v", groups, cfg.SupplementaryGIDs))
	}
	want, err := capsMask(cfg.KeepCapabilities)
	if err != nil {
		return privDropError(11, "verify caps", err)
	}
	got, err := s.getEffectiveCaps()
	if err != nil {
		return privDropError(11, "verify caps", err)
	}
	if got != want {
		return privDropError(11, "verify caps", fmt.Errorf("effective caps=%#x, want %#x", got, want))
	}
	// Prove the bounding set was shrunk to exactly the kept capabilities; a
	// larger set means a later exec could regain privileges the drop meant to
	// remove.
	bounding, err := s.getBoundingCaps()
	if err != nil {
		return privDropError(11, "verify bounding caps", err)
	}
	if bounding != want {
		return privDropError(11, "verify bounding caps",
			fmt.Errorf("bounding caps=%#x, want %#x", bounding, want))
	}
	// KEEPCAPS must be cleared so ambient capabilities cannot survive an exec.
	keepCaps, err := s.getKeepCaps()
	if err != nil {
		return privDropError(11, "verify keepcaps", err)
	}
	if keepCaps != 0 {
		return privDropError(11, "verify keepcaps",
			fmt.Errorf("PR_GET_KEEPCAPS=%d, want 0", keepCaps))
	}
	// NO_NEW_PRIVS must be set when requested so exec cannot raise privileges.
	if cfg.NoNewPrivs {
		nnp, err := s.getNoNewPrivs()
		if err != nil {
			return privDropError(11, "verify no_new_privs", err)
		}
		if nnp != 1 {
			return privDropError(11, "verify no_new_privs",
				fmt.Errorf("PR_GET_NO_NEW_PRIVS=%d, want 1", nnp))
		}
	}
	// The setuid(0) probe proves irreversibility only when it fails with EPERM;
	// a success, or any other error, is treated as a failed drop (fail closed).
	if err := s.probeSetUIDZero(); !errors.Is(err, unix.EPERM) {
		return privDropError(11, "verify setuid(0)",
			fmt.Errorf("setuid(0) must fail with EPERM to prove the drop is irreversible, got: %v", err))
	}
	return nil
}

// privDropError wraps a failed step as a *PreflightError carrying E_PRIVDROP,
// matching how gate P13 constructs and callers assert privilege-drop failures.
func privDropError(step int, name string, err error) error {
	return newPreflightError("P13", E_PRIVDROP,
		fmt.Errorf("privilege-drop step %d (%s): %w", step, name, err))
}

// withSetpcap returns keep with CAP_SETPCAP appended when absent.
func withSetpcap(keep []string) []string {
	for _, n := range keep {
		if n == "CAP_SETPCAP" {
			return keep
		}
	}
	out := make([]string, 0, len(keep)+1)
	out = append(out, keep...)
	out = append(out, "CAP_SETPCAP")
	return out
}

// capsMask builds the 64-bit capability mask for the named capabilities.
func capsMask(names []string) (uint64, error) {
	var m uint64
	for _, n := range names {
		bit, ok := capNameToBit[n]
		if !ok {
			return 0, fmt.Errorf("unknown capability %q", n)
		}
		m |= uint64(1) << bit
	}
	return m, nil
}

// sameGroupSet reports whether a and b hold the same group ids ignoring order
// and duplicates.
func sameGroupSet(a, b []uint32) bool {
	set := make(map[uint32]struct{}, len(a))
	for _, g := range a {
		set[g] = struct{}{}
	}
	other := make(map[uint32]struct{}, len(b))
	for _, g := range b {
		other[g] = struct{}{}
	}
	if len(set) != len(other) {
		return false
	}
	for g := range set {
		if _, ok := other[g]; !ok {
			return false
		}
	}
	return true
}

func realSetKeepCaps(on bool) error {
	v := 0
	if on {
		v = 1
	}
	return unix.Prctl(unix.PR_SET_KEEPCAPS, uintptr(v), 0, 0, 0)
}

// realSetGroups installs gids on every thread; an empty set clears all
// supplementary groups.
func realSetGroups(gids []uint32) error {
	if len(gids) == 0 {
		if _, _, errno := syscall.AllThreadsSyscall(syscall.SYS_SETGROUPS, 0, 0, 0); errno != 0 {
			return errno
		}
		return nil
	}
	ids := append([]uint32(nil), gids...)
	_, _, errno := syscall.AllThreadsSyscall(syscall.SYS_SETGROUPS,
		uintptr(len(ids)), uintptr(unsafe.Pointer(&ids[0])), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func realSetGID(gid uint32) error {
	if _, _, errno := syscall.AllThreadsSyscall(syscall.SYS_SETGID, uintptr(gid), 0, 0); errno != 0 {
		return errno
	}
	return nil
}

func realSetUID(uid uint32) error {
	if _, _, errno := syscall.AllThreadsSyscall(syscall.SYS_SETUID, uintptr(uid), 0, 0); errno != 0 {
		return errno
	}
	return nil
}

// realSetCaps sets the permitted and effective sets to exactly caps (inheritable
// cleared).
func realSetCaps(caps []string) error {
	var hdr unix.CapUserHeader
	hdr.Version = unix.LINUX_CAPABILITY_VERSION_3
	hdr.Pid = 0
	var data [2]unix.CapUserData
	for _, name := range caps {
		bit, ok := capNameToBit[name]
		if !ok {
			return fmt.Errorf("unknown capability %q", name)
		}
		data[bit>>5].Permitted |= 1 << (bit & 31)
		data[bit>>5].Effective |= 1 << (bit & 31)
	}
	return unix.Capset(&hdr, &data[0])
}

// realDropBoundingCaps issues PR_CAPBSET_DROP for every capability the kernel
// knows except those in keep, shrinking the bounding set irreversibly.
func realDropBoundingCaps(keep []string) error {
	keepBits := make(map[uint]struct{}, len(keep))
	for _, n := range keep {
		bit, ok := capNameToBit[n]
		if !ok {
			return fmt.Errorf("unknown capability %q in keep list", n)
		}
		keepBits[bit] = struct{}{}
	}
	for c := uint(0); c <= uint(unix.CAP_LAST_CAP); c++ {
		if _, ok := keepBits[c]; ok {
			continue
		}
		present, err := unix.PrctlRetInt(unix.PR_CAPBSET_READ, uintptr(c), 0, 0, 0)
		if err != nil {
			if errors.Is(err, syscall.EINVAL) {
				break // beyond CAP_LAST_CAP; nothing more to drop
			}
			return fmt.Errorf("PR_CAPBSET_READ(%d): %w", c, err)
		}
		if present == 0 {
			continue
		}
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0); err != nil {
			return fmt.Errorf("PR_CAPBSET_DROP(%d): %w", c, err)
		}
	}
	return nil
}

func realSetNoNewPrivs() error {
	return unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
}

func realGetGroups() ([]uint32, error) {
	gs, err := unix.Getgroups()
	if err != nil {
		return nil, err
	}
	out := make([]uint32, 0, len(gs))
	for _, g := range gs {
		out = append(out, uint32(g))
	}
	return out, nil
}

func realGetEffectiveCaps() (uint64, error) {
	var hdr unix.CapUserHeader
	hdr.Version = unix.LINUX_CAPABILITY_VERSION_3
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return 0, err
	}
	return uint64(data[0].Effective) | uint64(data[1].Effective)<<32, nil
}

// realGetNoNewPrivs reads PR_GET_NO_NEW_PRIVS (1 once no-new-privs is set).
func realGetNoNewPrivs() (int, error) {
	return unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
}

// realGetKeepCaps reads PR_GET_KEEPCAPS (0 once KEEPCAPS is cleared).
func realGetKeepCaps() (int, error) {
	return unix.PrctlRetInt(unix.PR_GET_KEEPCAPS, 0, 0, 0, 0)
}

// realGetBoundingCaps returns the capability bounding set as a 64-bit mask by
// reading PR_CAPBSET_READ over 0..CAP_LAST_CAP. It fails closed on any kernel
// error other than EINVAL, which marks the end of the known capability range.
func realGetBoundingCaps() (uint64, error) {
	var m uint64
	for c := uint(0); c <= uint(unix.CAP_LAST_CAP); c++ {
		present, err := unix.PrctlRetInt(unix.PR_CAPBSET_READ, uintptr(c), 0, 0, 0)
		if err != nil {
			if errors.Is(err, syscall.EINVAL) {
				break // beyond CAP_LAST_CAP
			}
			return 0, fmt.Errorf("PR_CAPBSET_READ(%d): %w", c, err)
		}
		if present == 1 {
			m |= uint64(1) << c
		}
	}
	return m, nil
}

// realProbeSetUIDZero attempts setuid(0) across every thread. After a successful
// drop the kernel rejects it with EPERM without changing anything, which is the
// proof the transition is irreversible. Using AllThreadsSyscall (rather than a
// single-thread RawSyscall) ensures the probe detects any thread that could
// still return to UID 0.
func realProbeSetUIDZero() error {
	if _, _, errno := syscall.AllThreadsSyscall(syscall.SYS_SETUID, 0, 0, 0); errno != 0 {
		return errno
	}
	return nil
}
