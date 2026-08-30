//go:build linux && ebpf_integration

package bpf

import (
	"encoding/binary"
	"net"
	"strconv"
	"testing"

	"github.com/cilium/ebpf"
)

// Tests for the capture bypass prefix list (issue #80).
//
// The bypass exists because a real agent pod must reach its own in-cluster
// control plane over plaintext, which the capture layer would otherwise
// redirect and the listener would reject T9. Every entry is therefore a
// destination that is deliberately NOT policed, which makes these tests
// security tests, not feature tests: what matters is that a prefix bypasses
// exactly what it names and nothing else.
//
// Each case is differential. Asserting only "the bypassed connect was not
// redirected" would pass just as well against a program that had stopped
// redirecting anything, so every bypass assertion is paired with a control that
// proves capture is still live in the same configuration.

// addBypass writes prefixes into bypass_cidr4. prefix strings are "a.b.c.d/len".
//
// The key is written as raw bytes rather than through AkshbpfBypassKey. That
// struct's Addr is a uint32, which cilium/ebpf marshals in host order, and an
// LPM trie matches on the key's bytes from the most significant bit down -- so
// a little-endian uint32 would have the trie comparing 0.113.0.203 against
// 203.0.113.0 and never matching. The production loader has the same
// requirement and satisfies it with a [4]byte field (capture.bypassKey).
func addBypass(t *testing.T, objs *AkshbpfObjects, prefixes ...string) {
	t.Helper()
	for _, p := range prefixes {
		_, ipnet, err := net.ParseCIDR(p)
		if err != nil {
			t.Fatalf("parse bypass prefix %q: %v", p, err)
		}
		ones, _ := ipnet.Mask.Size()
		v4 := ipnet.IP.To4()
		if v4 == nil {
			t.Fatalf("bypass prefix %q is not IPv4", p)
		}
		key := make([]byte, 8)
		binary.NativeEndian.PutUint32(key[0:4], uint32(ones))
		copy(key[4:8], v4)
		if err := objs.BypassCidr4.Update(key, uint8(1), ebpf.UpdateAny); err != nil {
			t.Fatalf("write bypass prefix %q: %v", p, err)
		}
	}
}

// assertRedirected asserts a connect to target landed on the listener, i.e.
// capture is live for that destination.
//
// The peer address is the assertion, not the cookie_orig_dst count. A scratch
// cgroup2 mount is another view of the single unified hierarchy's root cgroup,
// so the attached program observes every connect in the container, not only the
// probe's; the destination maps therefore carry unrelated entries and cannot be
// used as a per-probe signal. Where the connect ended up is unambiguous.
func assertRedirected(t *testing.T, cg, target, listenerIP string, listenerPort uint16) {
	t.Helper()
	res := runProbe(t, cg, 65534, "connect", "tcp", target, nil)
	if res.ConnectErrno != 0 {
		t.Fatalf("connect(%s) failed unexpectedly: errno %d", target, res.ConnectErrno)
	}
	want := net.JoinHostPort(listenerIP, strconv.Itoa(int(listenerPort)))
	if res.PeerAddr != want {
		t.Fatalf("connect(%s) peer = %q, want listener %q (not redirected)", target, res.PeerAddr, want)
	}
}

// assertNotRedirected asserts a connect to an unreachable target was left
// alone. A redirected connect would have landed on the live listener and
// returned errno 0 with the listener as its peer, so a failed connect with no
// peer is proof the redirect did not happen.
func assertNotRedirected(t *testing.T, cg, target string) {
	t.Helper()
	res := runProbe(t, cg, 65534, "connect", "tcp", target, nil)
	if res.ConnectErrno == 0 {
		t.Fatalf("connect(%s) succeeded with peer %q; a bypassed connect to an unreachable target must not connect",
			target, res.PeerAddr)
	}
}

func TestAkshConnect4_BypassPrefixCoversDestination_NotRedirected(t *testing.T) {
	cg := scratchCgroup(t)
	listenerIP, listenerPort, closeListener := listenerAddr(t)
	defer closeListener()
	cfg := baseConnect4Cfg(listenerIP, listenerPort)
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshConnect4)
	defer lp.Close()

	// Control first, with the map still empty: this exact destination is
	// captured today, so the bypass below is the only thing that changes.
	assertRedirected(t, cg, unreachableTCPTarget, listenerIP, listenerPort)

	addBypass(t, &lp.objs, "203.0.113.0/24")
	assertNotRedirected(t, cg, unreachableTCPTarget)
}

func TestAkshConnect4_BypassPrefixDoesNotCoverDestination_StillRedirected(t *testing.T) {
	cg := scratchCgroup(t)
	listenerIP, listenerPort, closeListener := listenerAddr(t)
	defer closeListener()
	cfg := baseConnect4Cfg(listenerIP, listenerPort)
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshConnect4)
	defer lp.Close()

	// A neighbouring /24 in the same TEST-NET-3 /16. If the trie matched on
	// anything coarser than the configured prefix length this would wrongly
	// bypass, so this is the test that a bypass does not leak sideways.
	addBypass(t, &lp.objs, "203.0.112.0/24")
	assertRedirected(t, cg, unreachableTCPTarget, listenerIP, listenerPort)
}

func TestAkshConnect4_EmptyBypassMap_EverythingStillRedirected(t *testing.T) {
	cg := scratchCgroup(t)
	listenerIP, listenerPort, closeListener := listenerAddr(t)
	defer closeListener()
	cfg := baseConnect4Cfg(listenerIP, listenerPort)
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshConnect4)
	defer lp.Close()

	// The default deployment has no bypass configured, so this is the case
	// that must be bit-for-bit the pre-#80 behaviour.
	assertRedirected(t, cg, unreachableTCPTarget, listenerIP, listenerPort)
}

func TestAkshConnect4_BypassHostRoute_OnlyThatAddressIsBypassed(t *testing.T) {
	cg := scratchCgroup(t)
	listenerIP, listenerPort, closeListener := listenerAddr(t)
	defer closeListener()
	cfg := baseConnect4Cfg(listenerIP, listenerPort)
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshConnect4)
	defer lp.Close()

	addBypass(t, &lp.objs, "203.0.113.10/32")
	assertNotRedirected(t, cg, unreachableTCPTarget)
	// The adjacent address in the same /24 must be unaffected: a /32 that
	// bypassed its neighbours would be a silent hole 255 addresses wide.
	assertRedirected(t, cg, "203.0.113.11:443", listenerIP, listenerPort)
}

func TestAkshConnect4_BypassIsPortIndependent(t *testing.T) {
	cg := scratchCgroup(t)
	listenerIP, listenerPort, closeListener := listenerAddr(t)
	defer closeListener()
	cfg := baseConnect4Cfg(listenerIP, listenerPort)
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshConnect4)
	defer lp.Close()

	// Unlike the DNS carve-out, which is an exact {addr, port} pair, a bypass
	// prefix covers every port. The in-cluster control plane a pod must reach
	// does not sit on one well-known port.
	addBypass(t, &lp.objs, "203.0.113.0/24")
	assertNotRedirected(t, cg, unreachableTCPTarget)
	assertNotRedirected(t, cg, "203.0.113.10:8083")
}

func TestAkshConnect4_BypassLongestPrefixWins(t *testing.T) {
	cg := scratchCgroup(t)
	listenerIP, listenerPort, closeListener := listenerAddr(t)
	defer closeListener()
	cfg := baseConnect4Cfg(listenerIP, listenerPort)
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshConnect4)
	defer lp.Close()

	// Overlapping prefixes are legal input, and an LPM trie answers with the
	// longest match. Both cover the target here, so the lookup must succeed
	// rather than be confused by the overlap.
	addBypass(t, &lp.objs, "203.0.0.0/8", "203.0.113.0/24")
	assertNotRedirected(t, cg, unreachableTCPTarget)
}

func TestAkshConnect4_BypassDoesNotOverrideProxyUIDOrCaptureDisabled(t *testing.T) {
	cg := scratchCgroup(t)
	listenerIP, listenerPort, closeListener := listenerAddr(t)
	defer closeListener()
	cfg := baseConnect4Cfg(listenerIP, listenerPort)
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshConnect4)
	defer lp.Close()

	// The proxy's own uid is exempt before the bypass check is ever reached,
	// so adding a bypass must not change the proxy's behaviour: it still
	// connects out unredirected. This pins the ordering of the checks.
	addBypass(t, &lp.objs, "203.0.113.0/24")
	res := runProbe(t, cg, int(cfg.ProxyUid), "connect", "tcp", unreachableTCPTarget, nil)
	if res.ConnectErrno == 0 {
		t.Fatalf("proxy connect to an unreachable target succeeded with peer %q, want failure", res.PeerAddr)
	}
	// And a destination outside the bypass is still captured, so the failure
	// above is the proxy exemption and not a dead redirect.
	assertRedirected(t, cg, "203.0.112.10:443", listenerIP, listenerPort)
}

func TestAkshConnect4_BypassMapCanBeFrozen(t *testing.T) {
	cg := scratchCgroup(t)
	listenerIP, listenerPort, closeListener := listenerAddr(t)
	defer closeListener()
	cfg := baseConnect4Cfg(listenerIP, listenerPort)
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshConnect4)
	defer lp.Close()

	// The loader freezes this map after writing it, so that a proxy holding
	// CAP_BPF cannot grant itself a wider bypass at run time. Prove both
	// halves on a real kernel: the freeze succeeds, and a later write fails.
	addBypass(t, &lp.objs, "203.0.113.0/24")
	if err := lp.objs.BypassCidr4.Freeze(); err != nil {
		t.Fatalf("freeze bypass_cidr4: %v", err)
	}
	key := make([]byte, 8)
	binary.NativeEndian.PutUint32(key[0:4], 8)
	copy(key[4:8], net.IPv4(10, 0, 0, 0).To4())
	if err := lp.objs.BypassCidr4.Update(key, uint8(1), ebpf.UpdateAny); err == nil {
		t.Fatal("update after freeze succeeded; a frozen bypass map must reject writes")
	}
	// The entry written before the freeze must still be honoured, i.e. the
	// freeze locks userspace out without breaking the datapath read.
	assertNotRedirected(t, cg, unreachableTCPTarget)
}
