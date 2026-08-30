//go:build linux && ebpf_integration

package bpf

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// listenerAddr starts a plain TCP listener the redirect programs point at,
// standing in for the aksh listener process itself (out of scope for this
// addendum -- see design §9). Returns its IPv4 addr:port string and a
// close func.
func listenerAddr(t *testing.T) (ip string, port uint16, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start test listener: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	tcpAddr := ln.Addr().(*net.TCPAddr)
	return tcpAddr.IP.String(), uint16(tcpAddr.Port), func() { ln.Close() }
}

// unreachableTCPTarget returns a non-loopback, non-DNS, TCP destination
// nothing is listening on -- used as the "would connect to the internet"
// destination in redirect scenarios (the redirect happens at connect() time
// before any packet reaches this address, so nothing needs to actually be
// reachable there).
const unreachableTCPTarget = "203.0.113.10:443" // TEST-NET-3, RFC 5737

// unreachableUDPTarget is used for UDP-protocol probes (socket()/connect()
// with proto="udp"); its host, 203.0.113.11, doubles as the configured DNS
// exception IP (cfg.DnsIp4) in some connect4 tests, but the constant itself
// is protocol-neutral in its address, not its name -- see
// dnsIPWrongPortTarget below for the TCP-protocol, wrong-port DNS scenario
// that reuses the same host on a different, non-DNS port.
const unreachableUDPTarget = "203.0.113.11:5353"

// dnsIPWrongPortTarget shares unreachableUDPTarget's host (the configured
// DNS exception IP in these tests) but is used with a TCP connect() to
// confirm the DNS exception is address-AND-port scoped: connecting to the
// right IP on the wrong port must still be redirected.
const dnsIPWrongPortTarget = unreachableUDPTarget

func baseConnect4Cfg(listenerIP string, listenerPort uint16) AkshbpfAkshCfg {
	return AkshbpfAkshCfg{
		ProxyUid:     1500,
		ListenerIp4:  ip4ToUint32(listenerIP),
		ListenerPort: htons(listenerPort),
		Flags:        flagCaptureEnabled,
	}
}

func mustOrigDstEqual(t *testing.T, got AkshbpfOrigDst, wantIP string, wantPort uint16, wantUID uint32) {
	t.Helper()
	if got.Ip != ip4ToUint32(wantIP) {
		t.Fatalf("orig dst ip = %#x, want %#x (%s)", got.Ip, ip4ToUint32(wantIP), wantIP)
	}
	if got.Port != htons(wantPort) {
		t.Fatalf("orig dst port = %#x, want %#x (%d)", got.Port, htons(wantPort), wantPort)
	}
	if got.Flags&dstIPv4 == 0 {
		t.Fatalf("orig dst flags = %#x, want DST_IPV4 bit set", got.Flags)
	}
	if got.Uid != wantUID {
		t.Fatalf("orig dst uid = %d, want %d", got.Uid, wantUID)
	}
}

func waitForPairOrigDst(t *testing.T, objs *AkshbpfObjects, ip uint32, port uint32) AkshbpfOrigDst {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if got, ok := lookupPairOrigDst(t, objs, ip, port); ok {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("pair_orig_dst missing for ip=%#x port=%d after deadline", ip, port)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func splitHostPort(t *testing.T, addr string) (string, uint16) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi(%q): %v", portStr, err)
	}
	return host, uint16(port)
}

func ip4PortKeyFromLocalAddr(t *testing.T, addr string) (uint32, uint32) {
	t.Helper()
	host, port := splitHostPort(t, addr)
	return ip4ToUint32(host), uint32(port)
}

func TestAkshConnect4_NonProxyUID_NonLoopback_NonDNS_TCPConnect_RedirectsToListener(t *testing.T) {
	cg := scratchCgroup(t)
	listenerIP, listenerPort, closeListener := listenerAddr(t)
	defer closeListener()

	cfg := baseConnect4Cfg(listenerIP, listenerPort)
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshConnect4)
	defer lp.Close()

	res := runProbe(t, cg, 65534, "connect", "tcp", unreachableTCPTarget, nil)
	if res.ConnectErrno != 0 {
		t.Fatalf("connect() failed unexpectedly: errno %d", res.ConnectErrno)
	}
	wantPeer := net.JoinHostPort(listenerIP, strconv.Itoa(int(listenerPort)))
	if res.PeerAddr != wantPeer {
		t.Fatalf("getpeername() = %q, want %q (connect was not redirected)", res.PeerAddr, wantPeer)
	}
}

func TestAkshConnect4_RedirectedConnection_CookieOrigDstMapRecordsOriginalDestination(t *testing.T) {
	cg := scratchCgroup(t)
	listenerIP, listenerPort, closeListener := listenerAddr(t)
	defer closeListener()
	cfg := baseConnect4Cfg(listenerIP, listenerPort)
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshConnect4)
	defer lp.Close()

	res := runProbe(t, cg, 65534, "connect", "tcp", unreachableTCPTarget, nil)
	if res.ConnectErrno != 0 {
		t.Fatalf("connect() failed unexpectedly: errno %d", res.ConnectErrno)
	}
	if cookieOrigDstLen(t, &lp.objs) != 1 {
		t.Fatalf("cookie_orig_dst len = %d, want 1", cookieOrigDstLen(t, &lp.objs))
	}
	it := lp.objs.CookieOrigDst.Iterate()
	var cookie uint64
	var got AkshbpfOrigDst
	if !it.Next(&cookie, &got) {
		t.Fatal("cookie_orig_dst had no entry")
	}
	if err := it.Err(); err != nil {
		t.Fatalf("iterate cookie_orig_dst: %v", err)
	}
	host, port := splitHostPort(t, unreachableTCPTarget)
	mustOrigDstEqual(t, got, host, port, 65534)
}

func TestAkshConnect4_ProxyUID_TCPConnect_NotRedirected(t *testing.T) {
	cg := scratchCgroup(t)
	listenerIP, listenerPort, closeListener := listenerAddr(t)
	defer closeListener()
	targetLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen original target: %v", err)
	}
	defer targetLn.Close()
	go func() {
		c, err := targetLn.Accept()
		if err == nil {
			c.Close()
		}
	}()
	cfg := baseConnect4Cfg(listenerIP, listenerPort)
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshConnect4)
	defer lp.Close()

	res := runProbe(t, cg, int(cfg.ProxyUid), "connect", "tcp", targetLn.Addr().String(), nil)
	if res.ConnectErrno != 0 {
		t.Fatalf("connect errno = %d, want 0", res.ConnectErrno)
	}
	if res.PeerAddr != targetLn.Addr().String() {
		t.Fatalf("peer addr = %q, want original destination %q", res.PeerAddr, targetLn.Addr().String())
	}
	if cookieOrigDstLen(t, &lp.objs) != 0 {
		t.Fatalf("cookie_orig_dst len = %d, want 0", cookieOrigDstLen(t, &lp.objs))
	}
}

func TestAkshConnect4_LoopbackDestination_NotRedirected(t *testing.T) {
	cg := scratchCgroup(t)
	listenerIP, listenerPort, closeListener := listenerAddr(t)
	defer closeListener()
	cfg := baseConnect4Cfg(listenerIP, listenerPort)
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshConnect4)
	defer lp.Close()

	ln, err := net.Listen("tcp4", "127.1.2.3:0")
	if err != nil {
		t.Fatalf("listen loopback target: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
		}
	}()
	res := runProbe(t, cg, 65534, "connect", "tcp", ln.Addr().String(), nil)
	if res.ConnectErrno != 0 {
		t.Fatalf("connect() failed unexpectedly: errno %d", res.ConnectErrno)
	}
	if res.PeerAddr != ln.Addr().String() {
		t.Fatalf("peer addr = %q, want original loopback destination %q", res.PeerAddr, ln.Addr().String())
	}
	if cookieOrigDstLen(t, &lp.objs) != 0 {
		t.Fatalf("cookie_orig_dst len = %d, want 0", cookieOrigDstLen(t, &lp.objs))
	}
}

func TestAkshConnect4_DNSExceptionExactAddressAndPort_NotRedirected(t *testing.T) {
	cg := scratchCgroup(t)
	listenerIP, listenerPort, closeListener := listenerAddr(t)
	defer closeListener()
	dnsLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dns target: %v", err)
	}
	defer dnsLn.Close()
	go func() {
		c, err := dnsLn.Accept()
		if err == nil {
			c.Close()
		}
	}()
	dnsAddr := dnsLn.Addr().(*net.TCPAddr)
	cfg := baseConnect4Cfg(listenerIP, listenerPort)
	cfg.DnsIp4 = ip4ToUint32(dnsAddr.IP.String())
	cfg.DnsPort = htons(uint16(dnsAddr.Port))
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshConnect4)
	defer lp.Close()

	res := runProbe(t, cg, 65534, "connect", "tcp", dnsLn.Addr().String(), nil)
	if res.ConnectErrno != 0 {
		t.Fatalf("connect() failed unexpectedly: errno %d", res.ConnectErrno)
	}
	if res.PeerAddr != dnsLn.Addr().String() {
		t.Fatalf("peer addr = %q, want dns target %q", res.PeerAddr, dnsLn.Addr().String())
	}
	if cookieOrigDstLen(t, &lp.objs) != 0 {
		t.Fatalf("cookie_orig_dst len = %d, want 0", cookieOrigDstLen(t, &lp.objs))
	}
}

func TestAkshConnect4_DNSAddressWrongPort_IsRedirected(t *testing.T) {
	cg := scratchCgroup(t)
	listenerIP, listenerPort, closeListener := listenerAddr(t)
	defer closeListener()
	cfg := baseConnect4Cfg(listenerIP, listenerPort)
	cfg.DnsIp4 = ip4ToUint32("203.0.113.11")
	cfg.DnsPort = htons(53)
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshConnect4)
	defer lp.Close()

	res := runProbe(t, cg, 65534, "connect", "tcp", dnsIPWrongPortTarget, nil)
	if res.ConnectErrno != 0 {
		t.Fatalf("connect() failed unexpectedly: errno %d", res.ConnectErrno)
	}
	wantPeer := net.JoinHostPort(listenerIP, strconv.Itoa(int(listenerPort)))
	if res.PeerAddr != wantPeer {
		t.Fatalf("peer addr = %q, want redirected listener %q", res.PeerAddr, wantPeer)
	}
}

func TestAkshConnect4_DNSDisabledZeroAddress_NeverExempts(t *testing.T) {
	cg := scratchCgroup(t)
	listenerIP, listenerPort, closeListener := listenerAddr(t)
	defer closeListener()
	cfg := baseConnect4Cfg(listenerIP, listenerPort)
	cfg.DnsIp4 = 0
	cfg.DnsPort = htons(53)
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshConnect4)
	defer lp.Close()

	// Uses a TEST-NET-3 address (not 0.0.0.0, which the kernel resolves to
	// 127.0.0.1/loopback for a TCP connect -- see the eBPF UT-spec addendum
	// BPF-7 and dev-review iter1's finding) so this test isolates the
	// dns_ip4==0 "disabled" guard from connect4's separate loopback
	// exemption; using 0.0.0.0 would make this test pass even if the
	// dns_ip4!=0 guard were missing entirely, since loopback alone would
	// already prevent a redirect.
	res := runProbe(t, cg, 65534, "connect", "tcp", "203.0.113.50:53", nil)
	if res.ConnectErrno != 0 {
		t.Fatalf("connect() failed unexpectedly: errno %d", res.ConnectErrno)
	}
	wantPeer := net.JoinHostPort(listenerIP, strconv.Itoa(int(listenerPort)))
	if res.PeerAddr != wantPeer {
		t.Fatalf("peer addr = %q, want redirected listener %q", res.PeerAddr, wantPeer)
	}
}

func TestAkshConnect4_UDPConnect_NonProxyUID_BlockNonTCPSet_DeniedWithEPERM(t *testing.T) {
	cg := scratchCgroup(t)
	listenerIP, listenerPort, closeListener := listenerAddr(t)
	defer closeListener()
	cfg := baseConnect4Cfg(listenerIP, listenerPort)
	cfg.Flags |= flagBlockNonTCP
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshConnect4)
	defer lp.Close()

	res := runProbe(t, cg, 65534, "connect", "udp", unreachableUDPTarget, nil)
	if res.ConnectErrno != int(unix.EPERM) {
		t.Fatalf("udp connect errno = %d, want %d", res.ConnectErrno, unix.EPERM)
	}
}

func TestAkshConnect4_UDPConnect_ProxyUID_Allowed(t *testing.T) {
	cg := scratchCgroup(t)
	listenerIP, listenerPort, closeListener := listenerAddr(t)
	defer closeListener()
	cfg := baseConnect4Cfg(listenerIP, listenerPort)
	cfg.Flags |= flagBlockNonTCP
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshConnect4)
	defer lp.Close()

	res := runProbe(t, cg, int(cfg.ProxyUid), "connect", "udp", unreachableUDPTarget, nil)
	if res.ConnectErrno != 0 {
		t.Fatalf("udp connect errno = %d, want 0", res.ConnectErrno)
	}
	if res.ConnectAddr != unreachableUDPTarget {
		t.Fatalf("connect addr = %q, want %q", res.ConnectAddr, unreachableUDPTarget)
	}
}

func TestAkshConnect4_UDPConnect_DNSException_Allowed(t *testing.T) {
	cg := scratchCgroup(t)
	listenerIP, listenerPort, closeListener := listenerAddr(t)
	defer closeListener()
	cfg := baseConnect4Cfg(listenerIP, listenerPort)
	cfg.Flags |= flagBlockNonTCP
	cfg.DnsIp4 = ip4ToUint32("203.0.113.11")
	cfg.DnsPort = htons(5353)
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshConnect4)
	defer lp.Close()

	res := runProbe(t, cg, 65534, "connect", "udp", unreachableUDPTarget, nil)
	if res.ConnectErrno != 0 {
		t.Fatalf("udp connect errno = %d, want 0", res.ConnectErrno)
	}
}

func TestAkshConnect4_UDPConnect_BlockNonTCPFlagClear_Allowed(t *testing.T) {
	cg := scratchCgroup(t)
	listenerIP, listenerPort, closeListener := listenerAddr(t)
	defer closeListener()
	cfg := baseConnect4Cfg(listenerIP, listenerPort)
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshConnect4)
	defer lp.Close()

	res := runProbe(t, cg, 65534, "connect", "udp", unreachableUDPTarget, nil)
	if res.ConnectErrno != 0 {
		t.Fatalf("udp connect errno = %d, want 0", res.ConnectErrno)
	}
}

func TestAkshConnect4_CaptureDisabledFlag_NeverRedirects(t *testing.T) {
	cg := scratchCgroup(t)
	listenerIP, listenerPort, closeListener := listenerAddr(t)
	defer closeListener()
	cfg := baseConnect4Cfg(listenerIP, listenerPort)
	cfg.Flags = 0
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen capture-disabled target: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
		}
	}()
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshConnect4)
	defer lp.Close()

	res := runProbe(t, cg, 65534, "connect", "tcp", ln.Addr().String(), nil)
	if res.ConnectErrno != 0 {
		t.Fatalf("connect() failed unexpectedly: errno %d", res.ConnectErrno)
	}
	if res.PeerAddr != ln.Addr().String() {
		t.Fatalf("peer addr = %q, want original %q", res.PeerAddr, ln.Addr().String())
	}
}

func TestAkshConnect4_CookieMapUpdateFailure_FailsClosedWithEPERM(t *testing.T) {
	cg := scratchCgroup(t)
	listenerIP, listenerPort, closeListener := listenerAddr(t)
	defer closeListener()
	cfg := baseConnect4Cfg(listenerIP, listenerPort)
	lp := loadAndAttach(t, cg, cfg, func(spec *ebpf.CollectionSpec) {
		spec.Maps[AkshbpfMapCookieOrigDst].Type = ebpf.Hash
		spec.Maps[AkshbpfMapCookieOrigDst].MaxEntries = 1
	}, AkshbpfProgAkshConnect4)
	defer lp.Close()
	if err := lp.objs.CookieOrigDst.Update(uint64(1234), AkshbpfOrigDst{Ip: ip4ToUint32("198.51.100.1"), Port: htons(80), Flags: dstIPv4, Uid: 1}, ebpf.UpdateAny); err != nil {
		t.Fatalf("pre-fill cookie_orig_dst: %v", err)
	}

	res := runProbe(t, cg, 65534, "connect", "tcp", unreachableTCPTarget, nil)
	if res.ConnectErrno != int(unix.EPERM) {
		t.Fatalf("connect errno = %d, want %d", res.ConnectErrno, unix.EPERM)
	}
	if res.PeerAddr != "" {
		t.Fatalf("peer addr = %q, want empty on failed closed connect", res.PeerAddr)
	}
	if cookieOrigDstLen(t, &lp.objs) != 1 {
		t.Fatalf("cookie_orig_dst len = %d, want 1 prefilled entry retained", cookieOrigDstLen(t, &lp.objs))
	}
}

func TestAkshConnect4_MissingConfigMap_NullBranchIsVerifierOnly_DocumentedNotExercised(t *testing.T) {
	spec, err := LoadAkshbpf()
	if err != nil {
		t.Fatalf("LoadAkshbpf() error = %v", err)
	}
	if got := spec.Maps[AkshbpfMapAkshConfig].Type; got != ebpf.Array {
		t.Fatalf("aksh_config map type = %v, want %v", got, ebpf.Array)
	}
	t.Log("aksh_config is a BPF_MAP_TYPE_ARRAY with max_entries=1, so aksh_cfg_get() cannot return NULL at runtime for key 0; this branch is verifier-only and intentionally not runtime-exercised")
}

func TestAkshSockops_ActiveEstablishedAfterConnect4Redirect_RekeysIntoPairOrigDst(t *testing.T) {
	cg := scratchCgroup(t)
	listenerIP, listenerPort, closeListener := listenerAddr(t)
	defer closeListener()
	cfg := baseConnect4Cfg(listenerIP, listenerPort)
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshConnect4, AkshbpfProgAkshSockops)
	defer lp.Close()

	res := runProbe(t, cg, 65534, "connect", "tcp", unreachableTCPTarget, nil)
	if res.ConnectErrno != 0 {
		t.Fatalf("connect errno = %d, want 0", res.ConnectErrno)
	}
	keyIP, keyPort := ip4PortKeyFromLocalAddr(t, res.LocalAddr)
	got := waitForPairOrigDst(t, &lp.objs, keyIP, keyPort)
	host, port := splitHostPort(t, unreachableTCPTarget)
	mustOrigDstEqual(t, got, host, port, 65534)
	if cookieOrigDstLen(t, &lp.objs) != 0 {
		t.Fatalf("cookie_orig_dst len = %d, want 0", cookieOrigDstLen(t, &lp.objs))
	}
}

func TestAkshSockops_NonActiveEstablishedOp_Ignored(t *testing.T) {
	cg := scratchCgroup(t)
	listenerIP, listenerPort, closeListener := listenerAddr(t)
	defer closeListener()
	cfg := baseConnect4Cfg(listenerIP, listenerPort)
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshConnect4)
	defer lp.Close()

	res := runProbe(t, cg, 65534, "connect", "tcp", unreachableTCPTarget, nil)
	if res.ConnectErrno != 0 {
		t.Fatalf("connect errno = %d, want 0", res.ConnectErrno)
	}
	time.Sleep(100 * time.Millisecond)
	if pairOrigDstLen(t, &lp.objs) != 0 {
		t.Fatalf("pair_orig_dst len = %d, want 0 without sockops attached", pairOrigDstLen(t, &lp.objs))
	}
	if cookieOrigDstLen(t, &lp.objs) != 1 {
		t.Fatalf("cookie_orig_dst len = %d, want 1 without sockops rekey", cookieOrigDstLen(t, &lp.objs))
	}
}

func TestAkshSockops_NonAF_INETFamily_Ignored(t *testing.T) {
	cg := scratchCgroup(t)
	cfg := AkshbpfAkshCfg{Flags: flagDenyIPv6, ProxyUid: 1500}
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshConnect6Deny, AkshbpfProgAkshSockops)
	defer lp.Close()

	res := runProbe(t, cg, 65534, "connect", "tcp6", "[2001:db8::1]:443", nil)
	if res.ConnectErrno != int(unix.EPERM) {
		t.Fatalf("ipv6 connect errno = %d, want %d", res.ConnectErrno, unix.EPERM)
	}
	time.Sleep(100 * time.Millisecond)
	if pairOrigDstLen(t, &lp.objs) != 0 {
		t.Fatalf("pair_orig_dst len = %d, want 0 for non-AF_INET family", pairOrigDstLen(t, &lp.objs))
	}
}

func TestAkshSockops_NoCookieOrigDstEntry_NoOpNoPanic(t *testing.T) {
	cg := scratchCgroup(t)
	listenerIP, listenerPort, closeListener := listenerAddr(t)
	defer closeListener()
	targetLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen original target: %v", err)
	}
	defer targetLn.Close()
	go func() {
		c, err := targetLn.Accept()
		if err == nil {
			c.Close()
		}
	}()
	cfg := baseConnect4Cfg(listenerIP, listenerPort)
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshConnect4, AkshbpfProgAkshSockops)
	defer lp.Close()

	res := runProbe(t, cg, int(cfg.ProxyUid), "connect", "tcp", targetLn.Addr().String(), nil)
	if res.ConnectErrno != 0 {
		t.Fatalf("connect errno = %d, want 0", res.ConnectErrno)
	}
	time.Sleep(100 * time.Millisecond)
	if cookieOrigDstLen(t, &lp.objs) != 0 {
		t.Fatalf("cookie_orig_dst len = %d, want 0", cookieOrigDstLen(t, &lp.objs))
	}
	if pairOrigDstLen(t, &lp.objs) != 0 {
		t.Fatalf("pair_orig_dst len = %d, want 0", pairOrigDstLen(t, &lp.objs))
	}
}

func TestAkshSockops_ReusedLocalAddrPort_OverwritesStalePairEntry(t *testing.T) {
	cg := scratchCgroup(t)
	listenerIP, listenerPort, closeListener := listenerAddr(t)
	defer closeListener()
	cfg := baseConnect4Cfg(listenerIP, listenerPort)
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshConnect4, AkshbpfProgAkshSockops)
	defer lp.Close()

	keyIP := ip4ToUint32("127.0.0.1")
	keyPort := uint32(40000)
	key := AkshbpfPairKey{Ip: keyIP, Port: keyPort}
	stale := AkshbpfOrigDst{Ip: ip4ToUint32("198.51.100.20"), Port: htons(8080), Flags: dstIPv4, Uid: 42}
	if err := lp.objs.PairOrigDst.Update(&key, stale, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed stale pair_orig_dst: %v", err)
	}
	res := runProbe(t, cg, 65534, "connect", "tcp", unreachableTCPTarget, map[string]string{
		"LOCAL_PORT": strconv.Itoa(int(keyPort)),
	})
	if res.ConnectErrno != 0 {
		t.Fatalf("connect errno = %d, want 0", res.ConnectErrno)
	}
	got := waitForPairOrigDst(t, &lp.objs, keyIP, keyPort)
	host, port := splitHostPort(t, unreachableTCPTarget)
	mustOrigDstEqual(t, got, host, port, 65534)
}

func TestAkshSockCreate_NonProxyUID_SOCK_STREAM_TCP_Allowed(t *testing.T) {
	cg := scratchCgroup(t)
	cfg := AkshbpfAkshCfg{ProxyUid: 1500, Flags: flagBlockNonTCP}
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshSockCreate)
	defer lp.Close()

	res := runProbe(t, cg, 65534, "socket", "tcp", "", nil)
	if res.SocketErrno != 0 {
		t.Fatalf("socket errno = %d, want 0", res.SocketErrno)
	}
}

func TestAkshSockCreate_NonProxyUID_SOCK_STREAM_SCTP_DeniedWithEPERM(t *testing.T) {
	cg := scratchCgroup(t)
	cfg := AkshbpfAkshCfg{ProxyUid: 1500, Flags: flagBlockNonTCP}
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshSockCreate)
	defer lp.Close()

	res := runProbe(t, cg, 65534, "socket", "tcp", "", map[string]string{"SOCKTYPE": "sctp_stream"})
	if res.SocketErrno != int(unix.EPERM) {
		t.Fatalf("socket errno = %d, want %d", res.SocketErrno, unix.EPERM)
	}
}

// TestAkshSockCreate_NonProxyUID_SOCK_DGRAM_UDP_Allowed pins the DEV-01
// socket-creation half. sock_create sees no destination, so it cannot scope a
// UDP socket to the DNS server; denying SOCK_DGRAM here made the
// address-and-port-scoped carve-out in connect4/sendmsg4 unreachable and left
// captured workloads unable to resolve any name. Creation is now permitted and
// the destination checks below are what bound it.
func TestAkshSockCreate_NonProxyUID_SOCK_DGRAM_UDP_Allowed(t *testing.T) {
	cg := scratchCgroup(t)
	cfg := AkshbpfAkshCfg{ProxyUid: 1500, Flags: flagBlockNonTCP}
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshSockCreate)
	defer lp.Close()

	res := runProbe(t, cg, 65534, "socket", "tcp", "", map[string]string{"SOCKTYPE": "dgram"})
	if res.SocketErrno != 0 {
		t.Fatalf("socket errno = %d, want 0; a UDP datagram socket must be creatable or the DNS carve-out is unreachable again", res.SocketErrno)
	}
}

// TestAkshSockCreate_NonProxyUID_SOCK_DGRAM_ICMP_DeniedWithEPERM proves the
// relaxation above is scoped by protocol, not by type alone. An IPPROTO_ICMP
// datagram socket is SOCK_DGRAM but never reaches cgroup/sendmsg4, so allowing
// it would be an unmediated egress channel of exactly the kind sock_create
// exists to block.
func TestAkshSockCreate_NonProxyUID_SOCK_DGRAM_ICMP_DeniedWithEPERM(t *testing.T) {
	cg := scratchCgroup(t)
	cfg := AkshbpfAkshCfg{ProxyUid: 1500, Flags: flagBlockNonTCP}
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshSockCreate)
	defer lp.Close()

	res := runProbe(t, cg, 65534, "socket", "tcp", "", map[string]string{"SOCKTYPE": "dgram_icmp"})
	// An IPPROTO_ICMP datagram socket is gated by the net.ipv4.ping_group_range
	// sysctl inside inet_create(), via sk_prot->init(), which runs *before* the
	// cgroup/sock_create BPF hook. Where the probe UID falls outside that range
	// the kernel returns EACCES and our program is never consulted, so the
	// socket is still denied but not by us -- and this test cannot prove the
	// enforcement it exists to prove. Skip rather than assert a conclusion the
	// environment does not support, matching the CAP_NET_RAW control arm below.
	if res.SocketErrno == int(unix.EACCES) {
		t.Skipf("ICMP datagram socket denied by the kernel with EACCES before cgroup/sock_create runs " +
			"(uid 65534 is outside net.ipv4.ping_group_range on this host); cannot attribute the deny to the BPF program here")
	}
	if res.SocketErrno != int(unix.EPERM) {
		t.Fatalf("ICMP datagram socket errno = %d, want %d", res.SocketErrno, unix.EPERM)
	}
}

func TestAkshSockCreate_NonProxyUID_SOCK_SEQPACKET_DeniedWithEPERM(t *testing.T) {
	cg := scratchCgroup(t)
	cfg := AkshbpfAkshCfg{ProxyUid: 1500, Flags: flagBlockNonTCP}
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshSockCreate)
	defer lp.Close()

	res := runProbe(t, cg, 65534, "socket", "tcp", "", map[string]string{"SOCKTYPE": "seqpacket"})
	if res.SocketErrno != int(unix.EPERM) {
		t.Fatalf("seqpacket socket errno = %d, want %d", res.SocketErrno, unix.EPERM)
	}
}

// TestAkshSockCreate_NonProxyUID_SOCK_RAW_DeniedWithEPERM always exercises the
// non-proxy raw-socket deny path, independent of whether the container has
// CAP_NET_RAW. This is split from the proxy-UID positive-control check below
// so a missing capability in CI never skips coverage of the deny enforcement
// itself (dev-review iter2 finding).
func TestAkshSockCreate_NonProxyUID_SOCK_RAW_DeniedWithEPERM(t *testing.T) {
	cg := scratchCgroup(t)
	cfg := AkshbpfAkshCfg{ProxyUid: 1500, Flags: flagBlockNonTCP}
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshSockCreate)
	defer lp.Close()

	res := runProbe(t, cg, 65534, "socket", "tcp", "", map[string]string{"SOCKTYPE": "raw"})
	if res.SocketErrno != int(unix.EPERM) {
		t.Fatalf("non-proxy raw socket errno = %d, want %d", res.SocketErrno, unix.EPERM)
	}
}

// TestAkshSockCreate_ProxyUID_SOCK_RAW_AllowedControlArm is a positive control
// proving the proxy UID is unaffected by the raw-socket deny path -- but it
// requires CAP_NET_RAW to distinguish "BPF allows" from "kernel denies for an
// unrelated reason", which this container lacks, so it documents the skip
// rather than asserting a false premise. Split out of the always-running deny
// test above so a missing capability never hides a deny-path regression.
func TestAkshSockCreate_ProxyUID_SOCK_RAW_AllowedControlArm(t *testing.T) {
	cg := scratchCgroup(t)
	cfg := AkshbpfAkshCfg{ProxyUid: 1500, Flags: flagBlockNonTCP}
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshSockCreate)
	defer lp.Close()

	res := runProbe(t, cg, int(cfg.ProxyUid), "socket", "tcp", "", map[string]string{"SOCKTYPE": "raw"})
	if res.SocketErrno != 0 {
		t.Skipf("proxy raw socket control arm lacks CAP_NET_RAW in this container (errno=%d); cannot distinguish kernel capability EPERM from BPF EPERM here", res.SocketErrno)
	}
}

func TestAkshSockCreate_ProxyUID_SOCK_DGRAM_Allowed(t *testing.T) {
	cg := scratchCgroup(t)
	cfg := AkshbpfAkshCfg{ProxyUid: 1500, Flags: flagBlockNonTCP}
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshSockCreate)
	defer lp.Close()

	res := runProbe(t, cg, int(cfg.ProxyUid), "socket", "tcp", "", map[string]string{"SOCKTYPE": "dgram"})
	if res.SocketErrno != 0 {
		t.Fatalf("socket errno = %d, want 0", res.SocketErrno)
	}
}

func TestAkshSockCreate_BlockNonTCPFlagClear_AllowsSOCK_DGRAM(t *testing.T) {
	cg := scratchCgroup(t)
	cfg := AkshbpfAkshCfg{ProxyUid: 1500, Flags: 0}
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshSockCreate)
	defer lp.Close()

	res := runProbe(t, cg, 65534, "socket", "tcp", "", map[string]string{"SOCKTYPE": "dgram"})
	if res.SocketErrno != 0 {
		t.Fatalf("socket errno = %d, want 0", res.SocketErrno)
	}
}

// TestAkshSendmsg4_NonProxyUID_DNSException_SendtoSucceeds is the DEV-01
// regression test. It previously asserted the opposite -- that socket creation
// was denied first and the carve-out was therefore unreachable -- which encoded
// the defect as the specification. A captured workload must be able to reach
// the configured resolver, and only the configured resolver.
func TestAkshSendmsg4_NonProxyUID_DNSException_SendtoSucceeds(t *testing.T) {
	cg := scratchCgroup(t)
	cfg := AkshbpfAkshCfg{
		ProxyUid: 1500,
		Flags:    flagBlockNonTCP,
		DnsIp4:   ip4ToUint32("127.0.0.1"),
		DnsPort:  htons(53),
	}
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshSockCreate, AkshbpfProgAkshSendmsg4)
	defer lp.Close()

	res := runProbe(t, cg, 65534, "sendto_unconnected", "udp", "127.0.0.1:53", nil)
	if res.SocketErrno != 0 {
		t.Fatalf("socket errno = %d, want 0", res.SocketErrno)
	}
	if res.SendtoErrno != 0 {
		t.Fatalf("sendto errno = %d, want 0; the non-proxy DNS carve-out must be reachable", res.SendtoErrno)
	}
}

// TestAkshSendmsg4_NonProxyUID_NonDNSDestination_SendtoDeniedWithEPERM is the
// security half of the change above: permitting UDP socket creation must not
// widen where a non-proxy UID can actually send.
func TestAkshSendmsg4_NonProxyUID_NonDNSDestination_SendtoDeniedWithEPERM(t *testing.T) {
	cg := scratchCgroup(t)
	cfg := AkshbpfAkshCfg{
		ProxyUid: 1500,
		Flags:    flagBlockNonTCP,
		DnsIp4:   ip4ToUint32("127.0.0.1"),
		DnsPort:  htons(53),
	}
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshSockCreate, AkshbpfProgAkshSendmsg4)
	defer lp.Close()

	res := runProbe(t, cg, 65534, "sendto_unconnected", "udp", unreachableUDPTarget, nil)
	if res.SocketErrno != 0 {
		t.Fatalf("socket errno = %d, want 0", res.SocketErrno)
	}
	if res.SendtoErrno != int(unix.EPERM) {
		t.Fatalf("sendto errno = %d, want %d; a non-DNS destination must stay denied", res.SendtoErrno, unix.EPERM)
	}
}

// TestAkshSendmsg4_NonProxyUID_DNSAddressWrongPort_SendtoDeniedWithEPERM proves
// the carve-out is scoped by address AND port, not by address alone.
func TestAkshSendmsg4_NonProxyUID_DNSAddressWrongPort_SendtoDeniedWithEPERM(t *testing.T) {
	cg := scratchCgroup(t)
	cfg := AkshbpfAkshCfg{
		ProxyUid: 1500,
		Flags:    flagBlockNonTCP,
		DnsIp4:   ip4ToUint32("127.0.0.1"),
		DnsPort:  htons(53),
	}
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshSockCreate, AkshbpfProgAkshSendmsg4)
	defer lp.Close()

	res := runProbe(t, cg, 65534, "sendto_unconnected", "udp", "127.0.0.1:5353", nil)
	if res.SocketErrno != 0 {
		t.Fatalf("socket errno = %d, want 0", res.SocketErrno)
	}
	if res.SendtoErrno != int(unix.EPERM) {
		t.Fatalf("sendto errno = %d, want %d; the DNS address on a non-DNS port must stay denied", res.SendtoErrno, unix.EPERM)
	}
}

// TestAkshSendmsg4_NonProxyUID_NoDNSConfigured_SendtoDeniedWithEPERM covers the
// default posture. With dns_ip4 == 0 the carve-out is disabled, so a UDP socket
// can be created but can reach nothing -- egress is exactly as closed as it was
// before sock_create was relaxed.
func TestAkshSendmsg4_NonProxyUID_NoDNSConfigured_SendtoDeniedWithEPERM(t *testing.T) {
	cg := scratchCgroup(t)
	cfg := AkshbpfAkshCfg{ProxyUid: 1500, Flags: flagBlockNonTCP}
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshSockCreate, AkshbpfProgAkshSendmsg4)
	defer lp.Close()

	res := runProbe(t, cg, 65534, "sendto_unconnected", "udp", "127.0.0.1:53", nil)
	if res.SocketErrno != 0 {
		t.Fatalf("socket errno = %d, want 0", res.SocketErrno)
	}
	if res.SendtoErrno != int(unix.EPERM) {
		t.Fatalf("sendto errno = %d, want %d; with no DNS server configured nothing may be sent", res.SendtoErrno, unix.EPERM)
	}
}

func TestAkshSendmsg4_ProxyUID_DNSException_SendtoSucceeds(t *testing.T) {
	cg := scratchCgroup(t)
	cfg := AkshbpfAkshCfg{
		ProxyUid: 1500,
		Flags:    flagBlockNonTCP,
		DnsIp4:   ip4ToUint32("127.0.0.1"),
		DnsPort:  htons(53),
	}
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshSockCreate, AkshbpfProgAkshSendmsg4)
	defer lp.Close()

	res := runProbe(t, cg, int(cfg.ProxyUid), "sendto_unconnected", "udp", "127.0.0.1:53", nil)
	if res.SocketErrno != 0 {
		t.Fatalf("socket errno = %d, want 0", res.SocketErrno)
	}
	if res.SendtoErrno != 0 {
		t.Fatalf("sendto errno = %d, want 0", res.SendtoErrno)
	}
}

func TestAkshSendmsg4_ProxyUID_NonDNSDestination_SendtoSucceeds(t *testing.T) {
	cg := scratchCgroup(t)
	cfg := AkshbpfAkshCfg{
		ProxyUid: 1500,
		Flags:    flagBlockNonTCP,
		DnsIp4:   ip4ToUint32("127.0.0.1"),
		DnsPort:  htons(53),
	}
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshSockCreate, AkshbpfProgAkshSendmsg4)
	defer lp.Close()

	res := runProbe(t, cg, int(cfg.ProxyUid), "sendto_unconnected", "udp", unreachableUDPTarget, nil)
	if res.SocketErrno != 0 {
		t.Fatalf("socket errno = %d, want 0", res.SocketErrno)
	}
	if res.SendtoErrno != 0 {
		t.Fatalf("sendto errno = %d, want 0", res.SendtoErrno)
	}
}

func TestAkshSendmsg4_MissingConfigMap_NullBranchIsVerifierOnly_DocumentedNotExercised(t *testing.T) {
	spec, err := LoadAkshbpf()
	if err != nil {
		t.Fatalf("LoadAkshbpf() error = %v", err)
	}
	if got := spec.Maps[AkshbpfMapAkshConfig].Type; got != ebpf.Array {
		t.Fatalf("aksh_config map type = %v, want %v", got, ebpf.Array)
	}
	t.Log("aksh_config is a BPF_MAP_TYPE_ARRAY with max_entries=1, so sendmsg4's missing-config NULL branch is verifier-only and intentionally not runtime-exercised")
}

func TestAkshConnect6Deny_NonProxyUID_TCPConnectToIPv6_DeniedWithEPERM(t *testing.T) {
	cg := scratchCgroup(t)
	cfg := AkshbpfAkshCfg{ProxyUid: 1500, Flags: flagDenyIPv6}
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshConnect6Deny)
	defer lp.Close()

	res := runProbe(t, cg, 65534, "connect", "tcp6", "[2001:db8::1]:443", nil)
	if res.ConnectErrno != int(unix.EPERM) {
		t.Fatalf("ipv6 connect errno = %d, want %d", res.ConnectErrno, unix.EPERM)
	}
}

func TestAkshConnect6Deny_ProxyUID_TCPConnectToIPv6_Allowed(t *testing.T) {
	cg := scratchCgroup(t)
	cfg := AkshbpfAkshCfg{ProxyUid: 1500, Flags: flagDenyIPv6}
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshConnect6Deny)
	defer lp.Close()

	res := runProbe(t, cg, int(cfg.ProxyUid), "connect", "tcp6", "[2001:db8::1]:443", nil)
	if res.ConnectErrno == int(unix.EPERM) {
		t.Fatalf("ipv6 connect errno = %d, want != %d", res.ConnectErrno, unix.EPERM)
	}
}

func TestAkshConnect6Deny_DenyIPv6FlagClear_AllowsConnect(t *testing.T) {
	cg := scratchCgroup(t)
	cfg := AkshbpfAkshCfg{ProxyUid: 1500, Flags: 0}
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshConnect6Deny)
	defer lp.Close()

	res := runProbe(t, cg, 65534, "connect", "tcp6", "[2001:db8::1]:443", nil)
	if res.ConnectErrno == int(unix.EPERM) {
		t.Fatalf("ipv6 connect errno = %d, want != %d", res.ConnectErrno, unix.EPERM)
	}
}

func TestAkshConnect6Deny_MissingConfigMap_NullBranchIsVerifierOnly_DocumentedNotExercised(t *testing.T) {
	spec, err := LoadAkshbpf()
	if err != nil {
		t.Fatalf("LoadAkshbpf() error = %v", err)
	}
	if got := spec.Maps[AkshbpfMapAkshConfig].Type; got != ebpf.Array {
		t.Fatalf("aksh_config map type = %v, want %v", got, ebpf.Array)
	}
	t.Log("aksh_config is a BPF_MAP_TYPE_ARRAY with max_entries=1, so connect6_deny's missing-config NULL branch is verifier-only and intentionally not runtime-exercised")
}

func TestAkshSendmsg6_NonProxyUID_BothFlagsSet_UDPSendDenied(t *testing.T) {
	cg := scratchCgroup(t)
	cfg := AkshbpfAkshCfg{ProxyUid: 1500, Flags: flagBlockNonTCP | flagDenyIPv6}
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshSendmsg6)
	defer lp.Close()

	res := runProbe(t, cg, 65534, "sendto_unconnected", "udp6", "[2001:db8::1]:5353", nil)
	if res.SocketErrno != 0 {
		t.Fatalf("socket errno = %d, want 0", res.SocketErrno)
	}
	if res.SendtoErrno != int(unix.EPERM) {
		t.Fatalf("sendto errno = %d, want %d", res.SendtoErrno, unix.EPERM)
	}
}

func TestAkshSendmsg6_ProxyUID_BothFlagsSet_UDPSendAllowed(t *testing.T) {
	cg := scratchCgroup(t)
	cfg := AkshbpfAkshCfg{ProxyUid: 1500, Flags: flagBlockNonTCP | flagDenyIPv6}
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshSendmsg6)
	defer lp.Close()

	res := runProbe(t, cg, int(cfg.ProxyUid), "sendto_unconnected", "udp6", "[2001:db8::1]:5353", nil)
	if res.SocketErrno != 0 {
		t.Fatalf("socket errno = %d, want 0", res.SocketErrno)
	}
	if res.SendtoErrno == int(unix.EPERM) {
		t.Fatalf("sendto errno = %d, want != %d", res.SendtoErrno, unix.EPERM)
	}
}

func TestAkshSendmsg6_BothFlagsClear_NonProxyUID_UDPSendAllowed(t *testing.T) {
	cg := scratchCgroup(t)
	cfg := AkshbpfAkshCfg{ProxyUid: 1500, Flags: 0}
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshSendmsg6)
	defer lp.Close()

	res := runProbe(t, cg, 65534, "sendto_unconnected", "udp6", "[2001:db8::1]:5353", nil)
	if res.SocketErrno != 0 {
		t.Fatalf("socket errno = %d, want 0", res.SocketErrno)
	}
	if res.SendtoErrno == int(unix.EPERM) {
		t.Fatalf("sendto errno = %d, want != %d", res.SendtoErrno, unix.EPERM)
	}
}

func TestAkshSendmsg6_OnlyBlockNonTCPFlagSet_NonProxyUID_UDPSendDenied(t *testing.T) {
	cg := scratchCgroup(t)
	cfg := AkshbpfAkshCfg{ProxyUid: 1500, Flags: flagBlockNonTCP}
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshSendmsg6)
	defer lp.Close()

	res := runProbe(t, cg, 65534, "sendto_unconnected", "udp6", "[2001:db8::1]:5353", nil)
	if res.SocketErrno != 0 {
		t.Fatalf("socket errno = %d, want 0", res.SocketErrno)
	}
	if res.SendtoErrno != int(unix.EPERM) {
		t.Fatalf("sendto errno = %d, want %d", res.SendtoErrno, unix.EPERM)
	}
}

func TestAkshSendmsg6_MissingConfigMap_NullBranchIsVerifierOnly_DocumentedNotExercised(t *testing.T) {
	spec, err := LoadAkshbpf()
	if err != nil {
		t.Fatalf("LoadAkshbpf() error = %v", err)
	}
	if got := spec.Maps[AkshbpfMapAkshConfig].Type; got != ebpf.Array {
		t.Fatalf("aksh_config map type = %v, want %v", got, ebpf.Array)
	}
	t.Log("aksh_config is a BPF_MAP_TYPE_ARRAY with max_entries=1, so sendmsg6's missing-config NULL branch is verifier-only and intentionally not runtime-exercised")
}

func TestAllSixPrograms_AttachedTogether_ProxyUIDCanReachAnyDestinationUnredirected(t *testing.T) {
	cg := scratchCgroup(t)
	listenerIP, listenerPort, closeListener := listenerAddr(t)
	defer closeListener()
	targetLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen original target: %v", err)
	}
	defer targetLn.Close()
	go func() {
		c, err := targetLn.Accept()
		if err == nil {
			c.Close()
		}
	}()
	cfg := baseConnect4Cfg(listenerIP, listenerPort)
	cfg.Flags = flagCaptureEnabled | flagBlockNonTCP | flagDenyIPv6
	cfg.DnsIp4 = ip4ToUint32("127.0.0.1")
	cfg.DnsPort = htons(53)
	lp := loadAndAttach(t, cg, cfg, nil,
		AkshbpfProgAkshConnect4,
		AkshbpfProgAkshSockops,
		AkshbpfProgAkshSockCreate,
		AkshbpfProgAkshSendmsg4,
		AkshbpfProgAkshConnect6Deny,
		AkshbpfProgAkshSendmsg6,
	)
	defer lp.Close()

	res := runProbe(t, cg, int(cfg.ProxyUid), "connect", "tcp", targetLn.Addr().String(), nil)
	if res.ConnectErrno != 0 {
		t.Fatalf("tcp connect errno = %d, want 0", res.ConnectErrno)
	}
	if res.PeerAddr != targetLn.Addr().String() {
		t.Fatalf("peer addr = %q, want %q", res.PeerAddr, targetLn.Addr().String())
	}
	res = runProbe(t, cg, int(cfg.ProxyUid), "socket", "tcp", "", map[string]string{"SOCKTYPE": "dgram"})
	if res.SocketErrno != 0 {
		t.Fatalf("udp socket errno = %d, want 0", res.SocketErrno)
	}
	res = runProbe(t, cg, int(cfg.ProxyUid), "sendto_unconnected", "udp", unreachableUDPTarget, nil)
	if res.SocketErrno != 0 {
		t.Fatalf("udp send socket errno = %d, want 0", res.SocketErrno)
	}
	if res.SendtoErrno != 0 {
		t.Fatalf("udp sendto errno = %d, want 0", res.SendtoErrno)
	}
}

func TestAllSixPrograms_AttachedTogether_NonProxyUIDFullLifecycle_TCPRedirectedUDPBlocked(t *testing.T) {
	cg := scratchCgroup(t)
	listenerIP, listenerPort, closeListener := listenerAddr(t)
	defer closeListener()
	cfg := baseConnect4Cfg(listenerIP, listenerPort)
	cfg.Flags = flagCaptureEnabled | flagBlockNonTCP | flagDenyIPv6
	cfg.DnsIp4 = ip4ToUint32("127.0.0.1")
	cfg.DnsPort = htons(53)
	lp := loadAndAttach(t, cg, cfg, nil,
		AkshbpfProgAkshConnect4,
		AkshbpfProgAkshSockops,
		AkshbpfProgAkshSockCreate,
		AkshbpfProgAkshSendmsg4,
		AkshbpfProgAkshConnect6Deny,
		AkshbpfProgAkshSendmsg6,
	)
	defer lp.Close()

	res := runProbe(t, cg, 65534, "connect", "tcp", unreachableTCPTarget, nil)
	if res.ConnectErrno != 0 {
		t.Fatalf("tcp connect errno = %d, want 0", res.ConnectErrno)
	}
	wantPeer := net.JoinHostPort(listenerIP, strconv.Itoa(int(listenerPort)))
	if res.PeerAddr != wantPeer {
		t.Fatalf("peer addr = %q, want %q", res.PeerAddr, wantPeer)
	}
	keyIP, keyPort := ip4PortKeyFromLocalAddr(t, res.LocalAddr)
	got := waitForPairOrigDst(t, &lp.objs, keyIP, keyPort)
	host, port := splitHostPort(t, unreachableTCPTarget)
	mustOrigDstEqual(t, got, host, port, 65534)
	if cookieOrigDstLen(t, &lp.objs) != 0 {
		t.Fatalf("cookie_orig_dst len = %d, want 0", cookieOrigDstLen(t, &lp.objs))
	}
	res = runProbe(t, cg, 65534, "sendto_unconnected", "udp", unreachableUDPTarget, nil)
	if res.SocketErrno != 0 {
		t.Fatalf("udp socket errno = %d, want 0", res.SocketErrno)
	}
	if res.SendtoErrno != int(unix.EPERM) {
		t.Fatalf("udp sendto errno = %d, want %d; non-DNS UDP egress must stay blocked with all six programs attached", res.SendtoErrno, unix.EPERM)
	}
}

// TestAllSixPrograms_AttachedTogether_DNSUDPPathWorksForCapturedAndProxyUIDs
// was previously ..._DNSUDPPathWorksOnlyForProxyUID and asserted that a
// captured workload could not create a UDP socket at all. That was the DEV-01
// defect stated as a requirement: a workload that cannot reach a resolver
// cannot resolve a name, so the sidecar could not be used. The DNS path is now
// reachable for captured UIDs too, scoped to the configured resolver.
func TestAllSixPrograms_AttachedTogether_DNSUDPPathWorksForCapturedAndProxyUIDs(t *testing.T) {
	cg := scratchCgroup(t)
	listenerIP, listenerPort, closeListener := listenerAddr(t)
	defer closeListener()
	cfg := baseConnect4Cfg(listenerIP, listenerPort)
	cfg.Flags = flagCaptureEnabled | flagBlockNonTCP | flagDenyIPv6
	cfg.DnsIp4 = ip4ToUint32("127.0.0.1")
	cfg.DnsPort = htons(53)
	lp := loadAndAttach(t, cg, cfg, nil,
		AkshbpfProgAkshConnect4,
		AkshbpfProgAkshSockops,
		AkshbpfProgAkshSockCreate,
		AkshbpfProgAkshSendmsg4,
		AkshbpfProgAkshConnect6Deny,
		AkshbpfProgAkshSendmsg6,
	)
	defer lp.Close()

	res := runProbe(t, cg, int(cfg.ProxyUid), "sendto_unconnected", "udp", "127.0.0.1:53", nil)
	if res.SocketErrno != 0 || res.SendtoErrno != 0 {
		t.Fatalf("proxy dns path got socket errno=%d sendto errno=%d, want both 0", res.SocketErrno, res.SendtoErrno)
	}
	res = runProbe(t, cg, 65534, "sendto_unconnected", "udp", "127.0.0.1:53", nil)
	if res.SocketErrno != 0 || res.SendtoErrno != 0 {
		t.Fatalf("captured dns path got socket errno=%d sendto errno=%d, want both 0", res.SocketErrno, res.SendtoErrno)
	}
	res = runProbe(t, cg, 65534, "sendto_unconnected", "udp", "127.0.0.1:5353", nil)
	if res.SendtoErrno != int(unix.EPERM) {
		t.Fatalf("captured non-DNS port sendto errno = %d, want %d", res.SendtoErrno, unix.EPERM)
	}
}
