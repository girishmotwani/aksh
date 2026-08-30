//go:build linux && ebpf_integration

package bpf

// Test harness for the aksh_capture.c BPF programs, per
// docs/design/S1a-dataplane-capture-UnitTests-eBPF-Addendum.md §2.
//
// Each test needs a real socket syscall performed by a process whose REAL uid
// (not effective uid -- aksh_uid() in the C source reads the real uid, see
// design §6.5) is a specific value, while that process is a member of a
// scratch cgroup v2 hierarchy the test attached its BPF programs to. Go's
// os/exec + SysProcAttr.Credential changes credentials at exec time but does
// not, by itself, provide a way to join a cgroup first (writing to
// cgroup.procs from the parent for a not-yet-started child is racy; writing
// it for an already-started child is what we do below).
//
// The chosen mechanism is a self re-exec: the compiled test binary
// (os.Args[0]) is re-invoked as a plain child process (started as root, no
// Credential set). TestMain checks for the AKSH_BPF_PROBE env var before
// go test's normal flag parsing / m.Run(); if present, the child (a) writes
// its own PID into the scratch cgroup's cgroup.procs (this requires no
// special privilege here since the container runs as root and owns the
// scratch cgroup), (b) calls syscall.Setuid to permanently drop its REAL uid
// to the scenario's target uid (a process can always lower its own
// privilege), (c) performs exactly one socket operation described by the
// remaining AKSH_BPF_PROBE_* env vars, (d) prints a single-line JSON result
// to stdout, and (e) exits 0 regardless of the socket operation's outcome
// (the outcome is data, not a probe failure).

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

func init() {
	if os.Getenv("AKSH_BPF_PROBE") == "1" {
		runProbeAndExit()
	}
}

func TestMain(m *testing.M) {
	if os.Getenv("AKSH_BPF_PROBE") == "1" {
		return
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintf(os.Stderr, "remove memlock: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// probeResult is the JSON payload the probe child prints on its single
// stdout line for the parent to parse and assert on.
type probeResult struct {
	// ConnectErrno/SocketErrno are 0 on success, else the syscall's errno
	// (as an int, e.g. int(unix.EPERM)).
	ConnectErrno int    `json:"connect_errno"`
	SocketErrno  int    `json:"socket_errno"`
	SendtoErrno  int    `json:"sendto_errno"`
	PeerAddr     string `json:"peer_addr,omitempty"`  // getpeername() after connect, "ip:port"
	LocalAddr    string `json:"local_addr,omitempty"` // getsockname() after connect, "ip:port"
	ConnectAddr  string `json:"connect_addr,omitempty"`
	Fatal        string `json:"fatal,omitempty"` // set if the probe itself failed unexpectedly
}

// runProbeAndExit is invoked from init() in the re-exec'd child. It never
// returns.
func runProbeAndExit() {
	res := probeResult{}
	defer func() {
		enc, _ := json.Marshal(res)
		fmt.Println(string(enc))
		os.Exit(0)
	}()

	cgroupPath := os.Getenv("AKSH_BPF_PROBE_CGROUP")
	if cgroupPath != "" {
		if err := os.WriteFile(filepath.Join(cgroupPath, "cgroup.procs"),
			[]byte(strconv.Itoa(os.Getpid())), 0644); err != nil {
			res.Fatal = "join cgroup: " + err.Error()
			return
		}
	}

	targetUID := os.Getenv("AKSH_BPF_PROBE_UID")
	if targetUID != "" {
		uid, err := strconv.Atoi(targetUID)
		if err != nil {
			res.Fatal = "parse uid: " + err.Error()
			return
		}
		// Setuid sets the real, effective, and saved UID for single-threaded
		// callers; this process is freshly exec'd and single-threaded at
		// this point, before any goroutines that might call into the
		// runtime's thread-locking machinery, so this is safe.
		if err := syscall.Setuid(uid); err != nil {
			res.Fatal = "setuid: " + err.Error()
			return
		}
	}

	proto := os.Getenv("AKSH_BPF_PROBE_PROTO") // "tcp" or "udp"
	dstAddr := os.Getenv("AKSH_BPF_PROBE_DST") // "ip:port"

	switch os.Getenv("AKSH_BPF_PROBE_OP") {
	case "connect":
		localPort := 0
		if s := os.Getenv("AKSH_BPF_PROBE_LOCAL_PORT"); s != "" {
			p, err := strconv.Atoi(s)
			if err != nil {
				res.Fatal = "parse local port: " + err.Error()
				return
			}
			localPort = p
		}
		var network string
		switch proto {
		case "tcp6":
			network = "tcp6"
		case "udp":
			network = "udp4"
		case "udp6":
			network = "udp6"
		default:
			network = "tcp4"
		}
		dialer := net.Dialer{Timeout: 500 * time.Millisecond}
		if localPort != 0 {
			// SO_REUSEADDR lets this bind succeed even if a prior test's
			// connection using the same fixed local port is still in
			// TIME_WAIT -- without it, TestAkshSockops_ReusedLocalAddrPort
			// (which deliberately reuses a fixed {ip,port} tuple to prove
			// pair_orig_dst's stale-entry overwrite) is flaky across
			// consecutive full-suite runs (observed: intermittent EADDRINUSE
			// from a previous test run's residual socket).
			dialer.Control = func(_, _ string, c syscall.RawConn) error {
				var sockErr error
				if err := c.Control(func(fd uintptr) {
					sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				}); err != nil {
					return err
				}
				return sockErr
			}
			if network == "tcp6" || network == "udp6" {
				dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP("::1"), Port: localPort}
				if proto == "udp6" {
					dialer.LocalAddr = &net.UDPAddr{IP: net.ParseIP("::1"), Port: localPort}
				}
			} else {
				dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: localPort}
				if proto == "udp" {
					dialer.LocalAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: localPort}
				}
			}
		}
		conn, err := dialer.Dial(network, dstAddr)
		if err != nil {
			res.ConnectErrno = errnoOf(err)
			return
		}
		defer conn.Close()
		res.PeerAddr = conn.RemoteAddr().String()
		res.LocalAddr = conn.LocalAddr().String()
		res.ConnectAddr = dstAddr
	case "socket":
		domain := unix.AF_INET
		typ := unix.SOCK_STREAM
		protocol := 0
		if proto == "tcp6" || proto == "udp6" {
			domain = unix.AF_INET6
		}
		switch os.Getenv("AKSH_BPF_PROBE_SOCKTYPE") {
		case "dgram":
			typ = unix.SOCK_DGRAM
		case "dgram_icmp":
			// An IPPROTO_ICMP datagram socket ("ping" socket, allowed for
			// uids inside net.ipv4.ping_group_range). It is SOCK_DGRAM but
			// never traverses cgroup/sendmsg4, so sock_create must keep
			// denying it even though plain UDP datagrams are now permitted.
			typ = unix.SOCK_DGRAM
			protocol = unix.IPPROTO_ICMP
		case "raw":
			typ = unix.SOCK_RAW
			protocol = unix.IPPROTO_RAW
		case "seqpacket":
			typ = unix.SOCK_SEQPACKET
		case "sctp_stream":
			typ = unix.SOCK_STREAM
			protocol = unix.IPPROTO_SCTP
		}
		fd, err := unix.Socket(domain, typ, protocol)
		if err != nil {
			res.SocketErrno = errnoOf(err)
			return
		}
		unix.Close(fd)
	case "sendto_unconnected":
		domain := unix.AF_INET
		if proto == "udp6" {
			domain = unix.AF_INET6
		}
		fd, err := unix.Socket(domain, unix.SOCK_DGRAM, 0)
		if err != nil {
			res.SocketErrno = errnoOf(err)
			return
		}
		defer unix.Close(fd)
		sa, err := sockaddrFor(proto, dstAddr)
		if err != nil {
			res.Fatal = "parse dst: " + err.Error()
			return
		}
		if err := unix.Sendto(fd, []byte("x"), 0, sa); err != nil {
			res.SendtoErrno = errnoOf(err)
			return
		}
	default:
		res.Fatal = "unknown AKSH_BPF_PROBE_OP"
	}
}

func errnoOf(err error) int {
	if err == nil {
		return 0
	}
	var errno syscall.Errno
	if e, ok := err.(*net.OpError); ok {
		if sys, ok := e.Err.(*os.SyscallError); ok {
			if en, ok := sys.Err.(syscall.Errno); ok {
				errno = en
			}
		} else if en, ok := e.Err.(syscall.Errno); ok {
			errno = en
		}
	} else if en, ok := err.(syscall.Errno); ok {
		errno = en
	}
	if errno == 0 {
		// Fall back to a sentinel so a genuinely non-errno failure is
		// still visible to the parent as "some error happened" rather
		// than silently looking like success.
		return -1
	}
	return int(errno)
}

func sockaddrInet4(addr string) (unix.Sockaddr, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return nil, fmt.Errorf("not an IPv4 address: %s", host)
	}
	sa := &unix.SockaddrInet4{Port: port}
	copy(sa.Addr[:], ip)
	return sa, nil
}

func sockaddrInet6(addr string) (unix.Sockaddr, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host).To16()
	if ip == nil || net.ParseIP(host).To4() != nil {
		return nil, fmt.Errorf("not an IPv6 address: %s", host)
	}
	sa := &unix.SockaddrInet6{Port: port}
	copy(sa.Addr[:], ip)
	return sa, nil
}

func sockaddrFor(proto, addr string) (unix.Sockaddr, error) {
	if proto == "udp6" || proto == "tcp6" {
		return sockaddrInet6(addr)
	}
	return sockaddrInet4(addr)
}

// scratchCgroup creates an empty leaf cgroup for a single test and returns
// its path. The returned path is what the caller attaches BPF programs to,
// and it is the ONLY thing that must ever be attached to.
//
// The subtlety, and the reason this function does more than mount:
//
// A cgroup v2 mount does not create a hierarchy. Unlike most filesystems,
// cgroup v2 is a single unified tree per cgroup namespace, so mounting it
// merely opens another view of the tree that already exists -- two separate
// mounts share one tree, and each mount point IS that tree's root (both
// report inode 2 for cgroup.procs). Attaching to the mount point therefore
// attaches to the root cgroup.
//
// That is not a container-scoped root either. These tests require
// --privileged, and Docker does not give privileged containers a private
// cgroup namespace, so /proc/self/cgroup reads "0::/docker/<id>" rather than
// "0::/": the host's whole tree is visible. Attaching at the mount point
// scopes the program to every process on the host, measured at 276 processes
// including kubepods (i.e. any running kind cluster).
//
// The consequences are not merely noisy assertions. A cgroup program's scope
// is "this cgroup and all descendants", so a connect4 program attached at the
// root rewrites destinations for unrelated processes machine-wide, and
// per-test map assertions count strangers' connects. See issue #82.
//
// The fix is to attach to a real leaf: create a child directory under the
// mount (each directory in a cgroup2 tree IS a cgroup) and return that. The
// probe joins it via cgroup.procs, so the attach scope is exactly one process.
func scratchCgroup(t *testing.T) string {
	t.Helper()
	mnt := t.TempDir()
	if err := unix.Mount("none", mnt, "cgroup2", 0, ""); err != nil {
		t.Fatalf("mount cgroup2: %v", err)
	}
	t.Cleanup(func() {
		_ = unix.Unmount(mnt, 0)
	})

	// A cgroup can only be removed once empty, and it can only be empty once
	// the probe child has exited, so removal is best-effort: a leaked probe
	// must not fail an otherwise passing test. The directory is uniquely
	// named per test so a leftover never collides with a later run.
	leaf := filepath.Join(mnt, "aksh-test-"+strconv.Itoa(os.Getpid())+"-"+sanitizeCgroupName(t.Name()))
	if err := os.Mkdir(leaf, 0o755); err != nil {
		t.Fatalf("create leaf cgroup %s: %v", leaf, err)
	}
	t.Cleanup(func() {
		_ = os.Remove(leaf)
	})

	// Fail loudly rather than silently re-introducing the root-attach bug:
	// a freshly created leaf cgroup must contain no processes at all.
	if pids := cgroupProcs(t, leaf); len(pids) != 0 {
		t.Fatalf("new leaf cgroup %s is not empty: %s; attaching here would "+
			"scope the BPF program to processes the test does not control",
			leaf, describePids(pids))
	}
	return leaf
}

// sanitizeCgroupName maps a Go test name to something safe for a directory
// name; subtest names contain '/' and may contain spaces.
func sanitizeCgroupName(name string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, name)
}

// cgroupProcs returns the PIDs currently in the cgroup at path.
//
// A PID reads as 0 when the process exists but is outside the reader's PID
// namespace, which is precisely what host processes look like from inside a
// test container -- so a zero is meaningful evidence, not a parse failure.
func cgroupProcs(t *testing.T, path string) []int {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(path, "cgroup.procs"))
	if err != nil {
		t.Fatalf("read cgroup.procs in %s: %v", path, err)
	}
	var pids []int
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		pid, convErr := strconv.Atoi(line)
		if convErr != nil {
			t.Fatalf("parse pid %q from %s/cgroup.procs: %v", line, path, convErr)
		}
		pids = append(pids, pid)
	}
	return pids
}

// describePids summarises a PID list for a failure message. The list can hold
// hundreds of entries when a cgroup is scoped too broadly, and dumping all of
// them buries the number that actually matters.
func describePids(pids []int) string {
	const sample = 8
	shown := pids
	suffix := ""
	if len(shown) > sample {
		shown = shown[:sample]
		suffix = ", ..."
	}
	parts := make([]string, 0, len(shown))
	for _, pid := range shown {
		parts = append(parts, strconv.Itoa(pid))
	}
	return fmt.Sprintf("%d pids [%s%s] (0 = outside this PID namespace)",
		len(pids), strings.Join(parts, " "), suffix)
}

// runProbe re-execs the current test binary as a probe child joined to
// cgroupPath and running as uid, performing the single socket operation op
// against dst. env may add scenario-specific vars (e.g. socket type).
func runProbe(t *testing.T, cgroupPath string, uid int, op, proto, dst string, extra map[string]string) probeResult {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(self, "-test.run=^$") // run no actual go tests; init() intercepts first
	cmd.Env = append(os.Environ(),
		"AKSH_BPF_PROBE=1",
		"AKSH_BPF_PROBE_CGROUP="+cgroupPath,
		"AKSH_BPF_PROBE_UID="+strconv.Itoa(uid),
		"AKSH_BPF_PROBE_OP="+op,
		"AKSH_BPF_PROBE_PROTO="+proto,
		"AKSH_BPF_PROBE_DST="+dst,
	)
	for k, v := range extra {
		cmd.Env = append(cmd.Env, "AKSH_BPF_PROBE_"+k+"="+v)
	}
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("probe child exited non-zero: %v, stderr=%s", err, ee.Stderr)
		}
		t.Fatalf("run probe: %v", err)
	}
	var res probeResult
	if jsonErr := json.Unmarshal(lastLine(out), &res); jsonErr != nil {
		t.Fatalf("parse probe output %q: %v", out, jsonErr)
	}
	if res.Fatal != "" {
		t.Fatalf("probe child reported fatal error: %s", res.Fatal)
	}
	return res
}

func lastLine(b []byte) []byte {
	// The probe prints exactly one JSON line; strip any trailing newline.
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

// loadedProgram bundles what a test needs to run one or more programs
// attached to a scratch cgroup with a specific aksh_config, then clean up.
type loadedProgram struct {
	objs  AkshbpfObjects
	links []link.Link
}

// loadAndAttach loads AkshbpfObjects (optionally with a modified spec, when
// specOverride is non-nil), writes cfg into aksh_config, attaches progNames
// (map keys of AkshbpfPrograms field access, see attach()) to cgroupPath,
// and returns a teardown-capable handle.
func loadAndAttach(t *testing.T, cgroupPath string, cfg AkshbpfAkshCfg, specOverride func(*ebpf.CollectionSpec), progNames ...string) *loadedProgram {
	t.Helper()
	spec, err := LoadAkshbpf()
	if err != nil {
		t.Fatalf("LoadAkshbpf: %v", err)
	}
	if specOverride != nil {
		specOverride(spec)
	}

	var objs AkshbpfObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		t.Fatalf("LoadAndAssign: %v", err)
	}

	if err := objs.AkshConfig.Update(uint32(0), cfg, ebpf.UpdateAny); err != nil {
		objs.Close()
		t.Fatalf("write aksh_config: %v", err)
	}

	lp := &loadedProgram{objs: objs}
	cgFile, err := os.Open(cgroupPath)
	if err != nil {
		objs.Close()
		t.Fatalf("open cgroup path: %v", err)
	}
	defer cgFile.Close()

	for _, name := range progNames {
		prog := progByName(&objs, name)
		if prog == nil {
			objs.Close()
			t.Fatalf("unknown program name %q", name)
		}
		var lk link.Link
		var attachErr error
		switch name {
		case AkshbpfProgAkshSockops:
			lk, attachErr = link.AttachCgroup(link.CgroupOptions{
				Path:    cgroupPath,
				Attach:  ebpf.AttachCGroupSockOps,
				Program: prog,
			})
		case AkshbpfProgAkshConnect4:
			lk, attachErr = link.AttachCgroup(link.CgroupOptions{
				Path:    cgroupPath,
				Attach:  ebpf.AttachCGroupInet4Connect,
				Program: prog,
			})
		case AkshbpfProgAkshConnect6Deny:
			lk, attachErr = link.AttachCgroup(link.CgroupOptions{
				Path:    cgroupPath,
				Attach:  ebpf.AttachCGroupInet6Connect,
				Program: prog,
			})
		case AkshbpfProgAkshSendmsg4:
			lk, attachErr = link.AttachCgroup(link.CgroupOptions{
				Path:    cgroupPath,
				Attach:  ebpf.AttachCGroupUDP4Sendmsg,
				Program: prog,
			})
		case AkshbpfProgAkshSendmsg6:
			lk, attachErr = link.AttachCgroup(link.CgroupOptions{
				Path:    cgroupPath,
				Attach:  ebpf.AttachCGroupUDP6Sendmsg,
				Program: prog,
			})
		case AkshbpfProgAkshSockCreate:
			lk, attachErr = link.AttachCgroup(link.CgroupOptions{
				Path:    cgroupPath,
				Attach:  ebpf.AttachCGroupInetSockCreate,
				Program: prog,
			})
		}
		if attachErr != nil {
			lp.Close()
			t.Fatalf("attach %s: %v", name, attachErr)
		}
		lp.links = append(lp.links, lk)
	}

	t.Cleanup(lp.Close)
	return lp
}

func progByName(objs *AkshbpfObjects, name string) *ebpf.Program {
	switch name {
	case AkshbpfProgAkshConnect4:
		return objs.AkshConnect4
	case AkshbpfProgAkshConnect6Deny:
		return objs.AkshConnect6Deny
	case AkshbpfProgAkshSendmsg4:
		return objs.AkshSendmsg4
	case AkshbpfProgAkshSendmsg6:
		return objs.AkshSendmsg6
	case AkshbpfProgAkshSockCreate:
		return objs.AkshSockCreate
	case AkshbpfProgAkshSockops:
		return objs.AkshSockops
	default:
		return nil
	}
}

func (lp *loadedProgram) Close() {
	for _, lk := range lp.links {
		_ = lk.Close()
	}
	_ = lp.objs.Close()
}

// cookieOrigDstLen returns the number of entries currently in the
// cookie_orig_dst map, by iterating it -- used to assert empty/non-empty
// state without depending on a specific cookie.
func cookieOrigDstLen(t *testing.T, objs *AkshbpfObjects) int {
	t.Helper()
	var key uint64
	var val AkshbpfOrigDst
	n := 0
	it := objs.CookieOrigDst.Iterate()
	for it.Next(&key, &val) {
		n++
	}
	if err := it.Err(); err != nil {
		t.Fatalf("iterate cookie_orig_dst: %v", err)
	}
	return n
}

func lookupPairOrigDst(t *testing.T, objs *AkshbpfObjects, ip uint32, port uint32) (AkshbpfOrigDst, bool) {
	t.Helper()
	key := AkshbpfPairKey{Ip: ip, Port: port}
	var val AkshbpfOrigDst
	err := objs.PairOrigDst.Lookup(&key, &val)
	if err != nil {
		return AkshbpfOrigDst{}, false
	}
	return val, true
}

func pairOrigDstLen(t *testing.T, objs *AkshbpfObjects) int {
	t.Helper()
	var key AkshbpfPairKey
	var val AkshbpfOrigDst
	n := 0
	it := objs.PairOrigDst.Iterate()
	for it.Next(&key, &val) {
		n++
	}
	if err := it.Err(); err != nil {
		t.Fatalf("iterate pair_orig_dst: %v", err)
	}
	return n
}

// ip4ToUint32 converts a dotted-quad string to a big-endian (network byte
// order) uint32, matching the C source's use of raw struct bpf_sock_addr
// fields which are already network byte order, and the design's
// cfg.dns_ip4 / cfg.listener_ip4 convention (design §6.4.3).
func ip4ToUint32(s string) uint32 {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		panic("not an IPv4 address: " + s)
	}
	return *(*uint32)(unsafe.Pointer(&ip[0]))
}

func htons(port uint16) uint16 {
	return (port << 8) | (port >> 8)
}

const (
	dstIPv4            = 0x01
	flagCaptureEnabled = 0x01
	flagBlockNonTCP    = 0x02
	flagDenyIPv6       = 0x04
)
