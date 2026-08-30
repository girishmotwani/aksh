//go:build linux && ebpf_integration

package bpf

// Regression tests for issue #82: the test harness must attach its BPF
// programs to a cgroup containing only the probe process.
//
// These tests assert a property of the harness rather than of the C
// programs. They exist because the previous harness attached at a cgroup2
// mount point, which is the root of the (host-wide, under --privileged)
// unified hierarchy rather than a private hierarchy. That silently scoped
// every connect4 program to every process on the machine, which both
// corrupted per-test map assertions and rewrote destinations for unrelated
// processes. Neither symptom was visible from the tests themselves -- they
// merely became flaky -- so the containment property is asserted directly.

import (
	"net"
	"testing"
	"time"
)

// TestHarness_AttachScopeExcludesProcessesOutsideTheCgroup verifies that a
// process which is not a member of the attach cgroup is unaffected by the
// attached program.
//
// The Go test process is deliberately used as the outsider: it runs as uid 0,
// which is not cfg.ProxyUid, so if it were inside the attach scope connect4
// would redirect it to the test listener and the dial to an unreachable
// TEST-NET-3 address would "succeed" against loopback. This is deterministic
// -- it does not depend on ambient traffic existing.
func TestHarness_AttachScopeExcludesProcessesOutsideTheCgroup(t *testing.T) {
	cg := scratchCgroup(t)
	listenerIP, listenerPort, closeListener := listenerAddr(t)
	defer closeListener()
	cfg := baseConnect4Cfg(listenerIP, listenerPort)
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshConnect4)
	defer lp.Close()

	if pids := cgroupProcs(t, cg); len(pids) != 0 {
		t.Fatalf("attach cgroup %s holds %s, want none: the program is "+
			"scoped to processes this test did not create", cg, describePids(pids))
	}

	dialer := net.Dialer{Timeout: 750 * time.Millisecond}
	conn, err := dialer.Dial("tcp4", unreachableTCPTarget)
	if err == nil {
		peer := conn.RemoteAddr().String()
		_ = conn.Close()
		t.Fatalf("dial %s from outside the attach cgroup succeeded with peer %s; "+
			"connect4 redirected a process that is not in its cgroup, so the "+
			"program is attached too broadly (issue #82)", unreachableTCPTarget, peer)
	}

	if n := cookieOrigDstLen(t, &lp.objs); n != 0 {
		t.Fatalf("cookie_orig_dst len = %d, want 0: connect4 recorded a connect "+
			"made outside its attach cgroup (issue #82)", n)
	}
}

// TestHarness_IdleAttachRecordsNoAmbientTraffic verifies that an attached
// program with no probe running records nothing at all.
//
// Unlike the test above this one is opportunistic: it only detects a scoping
// error when some other process on the machine happens to connect during the
// window, which is why it is not the primary regression test. It is cheap,
// cannot produce a false failure, and is the exact condition that made the
// suite flaky -- it fires reliably when a kind cluster is running.
func TestHarness_IdleAttachRecordsNoAmbientTraffic(t *testing.T) {
	cg := scratchCgroup(t)
	listenerIP, listenerPort, closeListener := listenerAddr(t)
	defer closeListener()
	cfg := baseConnect4Cfg(listenerIP, listenerPort)
	lp := loadAndAttach(t, cg, cfg, nil, AkshbpfProgAkshConnect4)
	defer lp.Close()

	time.Sleep(time.Second)

	if n := cookieOrigDstLen(t, &lp.objs); n != 0 {
		t.Fatalf("cookie_orig_dst len = %d, want 0: entries appeared with no probe "+
			"running, so processes outside the attach cgroup are in scope (issue #82)", n)
	}
	if n := pairOrigDstLen(t, &lp.objs); n != 0 {
		t.Fatalf("pair_orig_dst len = %d, want 0 with no probe running", n)
	}
}
