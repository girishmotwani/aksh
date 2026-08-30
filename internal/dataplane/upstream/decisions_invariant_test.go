package upstream_test

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/dataplane/listener"
	"github.com/girishmotwani/aksh/internal/dataplane/upstream"
)

// TestDialUpstream_DecisionMetricInvariant pins the contract DialUpstream's
// doc comment declares and that requestpath.ensureUpstream depends on:
//
//	exactly one deny decision on every error return, and none on success.
//
// This is load-bearing for issue #89. The relay claims the connection's
// decision latch after a failed dial *without recording anything*, on the
// grounds that the dialer already recorded a strictly more informative
// reason. If any error path here stopped recording, that connection would
// emit no decision sample at all -- a silent hole rather than a visible
// double count. Equally, if the success path started recording again, every
// allowed request would double count against the listener's rollup, which is
// the original #89 defect.
//
// Each case is driven through the real DirectDialer; nothing is stubbed
// except the metrics recorder and the upstream server.
func TestDialUpstream_DecisionMetricInvariant(t *testing.T) {
	t.Run("EveryErrorPath_RecordsExactlyOneDeny", func(t *testing.T) {
		// A hanging TLS server gives a deterministic handshake failure,
		// and a refused port gives a deterministic dial failure, so every
		// error return of DialUpstream is covered without stubbing.
		hangAddr, _, _, closeHang := newTLSTestServer(t, "svc.example", true)
		defer closeHang()

		cases := []struct {
			name       string
			addr       netip.AddrPort
			serverName string
			// setup optionally prepares dialer-scoped state (e.g. the
			// self-dial registry) before the call.
			setup func(t *testing.T, reg *listener.SelfDialRegistry, addr netip.AddrPort)
			// shortHandshake trims the handshake timeout so the hanging
			// server case fails fast instead of waiting the default.
			shortHandshake bool
		}{
			{
				name:       "InvalidAddr",
				addr:       netip.AddrPort{},
				serverName: "svc.example",
			},
			{
				name:       "UnsupportedAddrFamily",
				addr:       netip.MustParseAddrPort("[::1]:443"),
				serverName: "svc.example",
			},
			{
				name:       "EmptyServerName",
				addr:       netip.MustParseAddrPort("10.0.0.5:443"),
				serverName: "",
			},
			{
				name:       "LoopGuard",
				addr:       netip.MustParseAddrPort("127.0.0.1:54321"),
				serverName: "svc.example",
				setup: func(t *testing.T, reg *listener.SelfDialRegistry, addr netip.AddrPort) {
					t.Helper()
					if err := reg.Add(addr); err != nil {
						t.Fatalf("reg.Add() error = %v", err)
					}
				},
			},
			{
				name:       "DialFailed",
				addr:       netip.MustParseAddrPort("127.0.0.1:1"),
				serverName: "svc.example",
			},
			{
				name:           "HandshakeFailed",
				addr:           hangAddr,
				serverName:     "svc.example",
				shortHandshake: true,
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				reg := listener.NewSelfDialRegistry()
				m := &fakeMetrics{}
				opts := validUpstreamOptions()
				opts.ListenerPort = 15001
				if tc.shortHandshake {
					opts.HandshakeTimeout = 250 * time.Millisecond
				}
				d, err := upstream.NewDirectDialer(opts, reg, m)
				if err != nil {
					t.Fatalf("NewDirectDialer() error = %v", err)
				}
				if tc.setup != nil {
					tc.setup(t, reg, tc.addr)
				}

				conn, err := d.DialUpstream(context.Background(), tc.addr, tc.serverName, "")
				if err == nil {
					if conn != nil {
						_ = conn.Close()
					}
					t.Fatalf("DialUpstream() error = nil, want an error for case %s", tc.name)
				}

				got := m.decisions()
				if len(got) != 1 {
					t.Fatalf("DialUpstream() recorded %d decisions %v, want exactly 1; "+
						"requestpath.ensureUpstream marks the decision latch without recording "+
						"on a failed dial, so anything other than exactly one here either "+
						"loses the sample entirely or double counts it (issue #89)",
						len(got), got)
				}
				if !strings.HasPrefix(got[0], "deny/") {
					t.Fatalf("DialUpstream() recorded %q, want a deny/* decision", got[0])
				}
			})
		}
	})

	t.Run("SuccessfulDial_RecordsNoDecision", func(t *testing.T) {
		addr, pool, _, closeSrv := newTLSTestServer(t, "svc.example", false)
		defer closeSrv()

		opts := validUpstreamOptions()
		opts.ListenerPort = 15001
		opts.RootCAs = pool
		reg := listener.NewSelfDialRegistry()
		m := &fakeMetrics{}
		d, err := upstream.NewDirectDialer(opts, reg, m)
		if err != nil {
			t.Fatalf("NewDirectDialer() error = %v", err)
		}

		conn, err := d.DialUpstream(context.Background(), addr, "svc.example", "")
		if err != nil {
			t.Fatalf("DialUpstream() error = %v, want nil", err)
		}
		defer conn.Close()

		if got := m.decisions(); len(got) != 0 {
			t.Fatalf("DialUpstream() recorded %v on success, want none. A successful dial is a "+
				"connection-lifecycle event, not a terminal disposition -- the request it serves "+
				"may still be denied. Recording an allow here made every allowed request count "+
				"twice, once here and once in the listener rollup (issue #89)", got)
		}
	})
}
