package capture

import "unsafe"

// Kernel-facing mirrors of the C structures in design section 6.4.1. Field
// order, sizes and explicit padding must match the C layout byte for byte:
// cilium/ebpf marshals these with native endianness, and section 6.4.3 defines
// what the bytes mean. The names follow the unit test specification (section 4).

// bpfSockTuple mirrors the IPv4 arm of the kernel's struct bpf_sock_tuple:
// 12 bytes, 4-byte aligned, no implicit padding.
type bpfSockTuple struct {
	SAddr uint32 // offset 0, network-order address bytes
	DAddr uint32 // offset 4, network-order address bytes
	SPort uint16 // offset 8, network-order port bytes
	DPort uint16 // offset 10, network-order port bytes
}

// akshPairValue mirrors struct orig_dst, the value of both destination maps:
// 24 bytes, 8-byte aligned, no implicit padding.
type akshPairValue struct {
	IP      uint32 // offset 0, network-order address bytes
	Port    uint16 // offset 4, network-order port bytes
	Flags   uint16 // offset 6, bit0 dstIPv4, bit1 dstIPv6 (reserved)
	UID     uint32 // offset 8, host order; real UID that called connect()
	Pad     uint32 // offset 12, must be zero
	StampNS uint64 // offset 16, CLOCK_MONOTONIC nanoseconds taken in connect4
}

// akshPairKey mirrors struct pair_key, the key of pair_orig_dst: 8 bytes.
// Port is a uint32 because bpf_sock_ops.local_port is a host-order __u32.
type akshPairKey struct {
	IP   uint32 // offset 0, network-order address bytes
	Port uint32 // offset 4, host-order port, zero-extended from uint16
}

// akshConfig mirrors struct aksh_config, the frozen configuration map value:
// 32 bytes with every alignment hole written out explicitly.
type akshConfig struct {
	ProxyUID     uint32 // offset 0, host order
	ListenerIP4  uint32 // offset 4, network order
	ListenerPort uint16 // offset 8, network order; written with htons
	Flags        uint16 // offset 10, host order
	DNSIP4       uint32 // offset 12, network order; 0 disables the exception
	DNSPort      uint16 // offset 16, network order; written with htons
	Pad          uint16 // offset 18, must be zero
	Pad2         uint32 // offset 20, must be zero; mirrors the C alignment hole
	Reserved     uint64 // offset 24
}

// Flag bits of akshConfig.Flags (design section 6.4.1). They are declared in
// their own block so that they cannot be confused with the akshPairValue.Flags
// bits below, which are a separate bit space and deliberately reuse the same
// bit positions.
const (
	flagCaptureEnabled uint16 = 1 << 0
	flagBlockNonTCP    uint16 = 1 << 1
	flagDenyIPv6       uint16 = 1 << 2
)

// Flag bits of akshPairValue.Flags. This bit space belongs to the destination
// map value and is unrelated to the akshConfig.Flags bits above; bit 0 and
// bit 1 mean something different here.
const (
	dstIPv4 uint16 = 1 << 0
	dstIPv6 uint16 = 1 << 1
)

// Compile-time ABI guards for the kernel-mirrored structs above. These types
// are read and written as raw kernel memory, so a silent layout drift corrupts
// map keys and values at run time instead of failing loudly. Each pair of
// zero-length array declarations fails to compile - with a "constant ...
// overflows uintptr" error - if the size or offset moves in either direction.
// The equivalent run-time assertions live in the spec section 4 cases; these
// catch the drift a build earlier, including where the tests are not run.
var (
	_ [unsafe.Sizeof(bpfSockTuple{}) - 12]byte
	_ [12 - unsafe.Sizeof(bpfSockTuple{})]byte
	_ [unsafe.Offsetof(bpfSockTuple{}.SAddr) - 0]byte
	_ [0 - unsafe.Offsetof(bpfSockTuple{}.SAddr)]byte
	_ [unsafe.Offsetof(bpfSockTuple{}.DAddr) - 4]byte
	_ [4 - unsafe.Offsetof(bpfSockTuple{}.DAddr)]byte
	_ [unsafe.Offsetof(bpfSockTuple{}.SPort) - 8]byte
	_ [8 - unsafe.Offsetof(bpfSockTuple{}.SPort)]byte
	_ [unsafe.Offsetof(bpfSockTuple{}.DPort) - 10]byte
	_ [10 - unsafe.Offsetof(bpfSockTuple{}.DPort)]byte

	_ [unsafe.Sizeof(akshPairValue{}) - 24]byte
	_ [24 - unsafe.Sizeof(akshPairValue{})]byte
	_ [unsafe.Offsetof(akshPairValue{}.IP) - 0]byte
	_ [0 - unsafe.Offsetof(akshPairValue{}.IP)]byte
	_ [unsafe.Offsetof(akshPairValue{}.Port) - 4]byte
	_ [4 - unsafe.Offsetof(akshPairValue{}.Port)]byte
	_ [unsafe.Offsetof(akshPairValue{}.Flags) - 6]byte
	_ [6 - unsafe.Offsetof(akshPairValue{}.Flags)]byte
	_ [unsafe.Offsetof(akshPairValue{}.UID) - 8]byte
	_ [8 - unsafe.Offsetof(akshPairValue{}.UID)]byte
	_ [unsafe.Offsetof(akshPairValue{}.Pad) - 12]byte
	_ [12 - unsafe.Offsetof(akshPairValue{}.Pad)]byte
	_ [unsafe.Offsetof(akshPairValue{}.StampNS) - 16]byte
	_ [16 - unsafe.Offsetof(akshPairValue{}.StampNS)]byte

	_ [unsafe.Sizeof(akshPairKey{}) - 8]byte
	_ [8 - unsafe.Sizeof(akshPairKey{})]byte
	_ [unsafe.Offsetof(akshPairKey{}.Port) - 4]byte
	_ [4 - unsafe.Offsetof(akshPairKey{}.Port)]byte

	_ [unsafe.Sizeof(akshConfig{}) - 32]byte
	_ [32 - unsafe.Sizeof(akshConfig{})]byte
	_ [unsafe.Offsetof(akshConfig{}.ListenerIP4) - 4]byte
	_ [4 - unsafe.Offsetof(akshConfig{}.ListenerIP4)]byte
	_ [unsafe.Offsetof(akshConfig{}.ListenerPort) - 8]byte
	_ [8 - unsafe.Offsetof(akshConfig{}.ListenerPort)]byte
	_ [unsafe.Offsetof(akshConfig{}.Flags) - 10]byte
	_ [10 - unsafe.Offsetof(akshConfig{}.Flags)]byte
	_ [unsafe.Offsetof(akshConfig{}.DNSIP4) - 12]byte
	_ [12 - unsafe.Offsetof(akshConfig{}.DNSIP4)]byte
	_ [unsafe.Offsetof(akshConfig{}.DNSPort) - 16]byte
	_ [16 - unsafe.Offsetof(akshConfig{}.DNSPort)]byte
	_ [unsafe.Offsetof(akshConfig{}.Pad) - 18]byte
	_ [18 - unsafe.Offsetof(akshConfig{}.Pad)]byte
	_ [unsafe.Offsetof(akshConfig{}.Pad2) - 20]byte
	_ [20 - unsafe.Offsetof(akshConfig{}.Pad2)]byte
	_ [unsafe.Offsetof(akshConfig{}.Reserved) - 24]byte
	_ [24 - unsafe.Offsetof(akshConfig{}.Reserved)]byte
)

// PrivDropConfig is the input to the 11-step privilege-drop sequence
// (design section 6.6.2). It is declared without a build tag so that the
// Linux implementation and the non-Linux stub bind to one definition.
type PrivDropConfig struct {
	// ProxyUID is the unprivileged UID the process drops to.
	ProxyUID uint32
	// ProxyGID is the primary group the process drops to.
	ProxyGID uint32
	// SupplementaryGIDs is the exact supplementary group set to install.
	SupplementaryGIDs []uint32
	// KeepCapabilities lists the capabilities retained after the drop (CAP_BPF).
	KeepCapabilities []string
	// NoNewPrivs requests PR_SET_NO_NEW_PRIVS before the drop.
	NoNewPrivs bool
}

// AttachInfo describes the kernel objects created by a successful load and
// attach. It is declared without a build tag for the same reason as
// PrivDropConfig.
type AttachInfo struct {
	// ProgIDs are the kernel program ids of the attached programs.
	ProgIDs []uint32
	// CgroupID is the kernel id of the cgroup the programs are attached to.
	CgroupID uint64
	// PinPaths are the bpffs paths of the pinned links, empty when PinLinks is false.
	PinPaths []string
}

// PinRootInfo is the observed ownership and mode of a pin-root directory,
// evaluated by preflight gate P15 (MC-S1a-01, design section 6.8.6).
type PinRootInfo struct {
	// IsDir reports whether the pin root is a directory.
	IsDir bool
	// FSMagic is the filesystem magic reported for the pin root.
	FSMagic uint32
	// UID is the owning user id.
	UID uint32
	// GID is the owning group id.
	GID uint32
	// Mode is the permission bits of the directory.
	Mode uint32
}
