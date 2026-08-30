package capture

// The interfaces below are the seams through which the platform-neutral
// preflight engine and the cgroup resolver reach the operating system, the
// kernel and the BPF objects. Production implementations live in the
// Linux-tagged files; tests supply plain-struct fakes.

// CgoProbe reports whether the binary was built with cgo enabled. Gate P1
// requires a pure-Go build so that syscall.AllThreadsSyscall is usable.
type CgoProbe interface {
	CgoEnabled() bool
}

// UnameReader returns the kernel release string, as uname() reports it.
type UnameReader interface {
	Release() (string, error)
}

// FSMagicProber reports the filesystem magic of a path (statfs f_type).
type FSMagicProber interface {
	FSMagic(path string) (uint32, error)
}

// BPFFSMounter observes and, when permitted, creates the bpffs mount that
// holds pinned objects.
type BPFFSMounter interface {
	IsBPFFSMounted(path string) (bool, error)
	MountBPFFS(path string) error
}

// CapabilityProber reports whether an effective capability is held. The name
// is the kernel spelling, e.g. "CAP_BPF" or "CAP_NET_ADMIN"; gate P7 asks only
// for those two.
type CapabilityProber interface {
	HasCapability(name string) (bool, error)
}

// MemlockRaiser satisfies gate P8: RLIMIT_MEMLOCK must not be able to refuse a
// map or program allocation (design section 6.8, gate P8). The single method
// carries the whole contract - it wraps rlimit.RemoveMemlock(), which raises
// the limit to infinity where it still applies and is a no-op on kernels that
// account BPF memory to the memory cgroup. A nil error therefore means "the
// limit cannot block us", not "the limit was changed"; implementations must be
// safe to call more than once.
type MemlockRaiser interface {
	RemoveMemlock() error
}

// CgroupResolver resolves and validates the pod cgroup path. PodCgroupResolver
// is the production implementation.
type CgroupResolver interface {
	ResolvePodCgroup(podPath string) (string, error)
}

// ProgramLoader loads and verifies the BPF programs. It returns the ids of the
// loaded programs so that gate P11 can verify what the kernel attached.
type ProgramLoader interface {
	LoadPrograms() ([]uint32, error)
}

// ConfigMapAccessor writes, reads back and freezes the aksh_config array map.
// The configuration crosses the seam as its raw byte image so that gate P10 can
// compare all bytes without the seam naming an unexported struct.
type ConfigMapAccessor interface {
	WriteConfig(image []byte) error
	ReadConfig() ([]byte, error)
	FreezeConfig() error
}

// CgroupAttacher attaches the loaded programs to a cgroup and re-queries the
// kernel for the program ids actually attached there.
type CgroupAttacher interface {
	Attach(cgroupPath string) ([]uint32, error)
	AttachedProgIDs(cgroupPath string) ([]uint32, error)
}

// PinRootStater reports the ownership and mode of the pin root subtree.
type PinRootStater interface {
	StatPinRoot(path string) (PinRootInfo, error)
}

// RedirectProber runs the phase-B redirect self-probe (design section 6.7.1).
type RedirectProber interface {
	ProbeRedirect() error
}

// PrivilegeDropper runs the 11-step privilege-drop sequence and its post-drop
// assertions (design section 6.6.2).
type PrivilegeDropper interface {
	DropPrivileges(cfg PrivDropConfig) error
}

// UIDExclusionProber runs the post-drop UID-exclusion probe (design section 6.7.2).
type UIDExclusionProber interface {
	ProbeUIDExclusion() error
}

// CgroupNamespaceProber answers whether the process's cgroup namespace allows
// the pod cgroup to be named on the host mount. The bounded search that answers
// it reports E_CGROUPNS_OPAQUE when nothing matches, E_AMBIGUOUS_CGROUP when
// more than one directory matches, and E_CGROUP_WALK_LIMIT when either walk
// bound is exceeded (design section 6.1.2 case B).
type CgroupNamespaceProber interface {
	ConfirmVisible(podPath string) error
}

// CgroupInodeStater reports the inode number of a directory. Case B of design
// section 6.1.2 turns on the fact that cgroup2 is a single filesystem, so the
// same directory carries the same inode whether it is reached through the
// namespace-local mount or through the host mount. That is what lets a process
// which cannot name its own cgroup still identify it.
type CgroupInodeStater interface {
	InodeOf(path string) (uint64, error)
}

// CgroupDirEntry is one immediate subdirectory of a cgroup directory together
// with its inode, which is the only property the case B search compares.
type CgroupDirEntry struct {
	// Name is the base name of the subdirectory.
	Name string
	// Ino is the inode number of the subdirectory.
	Ino uint64
}

// CgroupDirReader lists the immediate subdirectories of a cgroup directory.
// It exists so that the bounded walk, which is the security-relevant part, is
// ordinary Go that can be tested exhaustively on any platform, while the
// operating-system access behind it stays a thin wrapper. Implementations must
// not follow symlinks: cgroup2 contains none, and following one is precisely
// how a walk would escape the host mount.
type CgroupDirReader interface {
	ReadCgroupDirs(path string) ([]CgroupDirEntry, error)
}

// ProcTableReader reports the process ids listed in a cgroup.procs file.
type ProcTableReader interface {
	ProcsIn(cgroupDir string) ([]int, error)
}
