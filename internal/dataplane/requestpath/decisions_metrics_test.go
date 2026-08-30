package requestpath

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/netip"
	"testing"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/pipeline"
	dto "github.com/prometheus/client_model/go"

	"github.com/prometheus/client_golang/prometheus"
)

// famDecisions returns the gathered "aksh_decisions_total" metric family, or
// nil if it has not been registered/observed. Mirrors the helper of the same
// shape in internal/audit/prom_test.go (unexported there, so duplicated here
// for this package's black-box tests).
func famDecisions(t *testing.T, reg *prometheus.Registry) *dto.MetricFamily {
	t.Helper()
	fams, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}
	for _, f := range fams {
		if f.GetName() == "aksh_decisions_total" {
			return f
		}
	}
	return nil
}

func counterWithLabels(fam *dto.MetricFamily, want map[string]string) float64 {
	if fam == nil {
		return -1
	}
	for _, m := range fam.GetMetric() {
		got := map[string]string{}
		for _, lp := range m.GetLabel() {
			got[lp.GetName()] = lp.GetValue()
		}
		if len(got) != len(want) {
			continue
		}
		match := true
		for k, v := range want {
			if got[k] != v {
				match = false
				break
			}
		}
		if match {
			return m.GetCounter().GetValue()
		}
	}
	return -1
}

// TestServe_PolicyDenyNoMatch_IncrementsDecisionsTotal proves that a
// policy-denied request (the disposition operators most need to alert on)
// increments aksh_decisions_total{disposition="deny",reason="policy_no_match"}.
// Regression test for #60: previously no metric was emitted on this path at
// all, so aksh_decisions_total never reflected policy verdicts.
func TestServe_PolicyDenyNoMatch_IncrementsDecisionsTotal(t *testing.T) {
	sink := &recordingSink{}
	reg := prometheus.NewRegistry()
	metrics, err := audit.NewPromMetricsRecorder(reg)
	if err != nil {
		t.Fatalf("NewPromMetricsRecorder() error = %v", err)
	}
	dialer := &scriptedDialer{fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
		t.Fatal("DialUpstream must not be called for a denied request")
		return nil, nil
	}}

	handler, err := NewHandler(denyPipeline(sink, pipeline.ReasonNoMatch), dialer, sink, metrics, DefaultOptions())
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	downstream, client := net.Pipe()
	done := serveHandler(t, handler, downstream)
	br := bufio.NewReader(client)

	writeRequest(t, client, "GET /deny HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	resp := mustReadResponse(t, br, nil)
	client.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("StatusCode = %d, want 403", resp.StatusCode)
	}
	waitServeDone(t, done)

	fam := famDecisions(t, reg)
	want := map[string]string{
		"disposition": "deny",
		"reason":      "policy_no_match",
		"fault":       "false",
		"transport":   "tls",
	}
	if got := counterWithLabels(fam, want); got != 1 {
		t.Fatalf("aksh_decisions_total%v = %v, want 1", want, got)
	}
}

// TestServe_DecisionDenyIdentityMismatch_IncrementsDecisionsTotal proves the
// identity-mismatch early return (which skips the uniform-403 response body
// for ADR-S0-13 reasons) still records the denial for operators.
func TestServe_DecisionDenyIdentityMismatch_IncrementsDecisionsTotal(t *testing.T) {
	sink := &recordingSink{}
	reg := prometheus.NewRegistry()
	metrics, err := audit.NewPromMetricsRecorder(reg)
	if err != nil {
		t.Fatalf("NewPromMetricsRecorder() error = %v", err)
	}
	dialer := &scriptedDialer{fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
		t.Fatal("DialUpstream must not be called for identity mismatch")
		return nil, nil
	}}

	handler, err := NewHandler(denyPipeline(sink, pipeline.ReasonIdentityMismatch), dialer, sink, metrics, DefaultOptions())
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	downstream, client := net.Pipe()
	done := serveHandler(t, handler, downstream)

	writeRequestAsync(client, "GET /deny HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	_ = readUntilEOF(client)
	client.Close()
	waitServeDone(t, done)

	fam := famDecisions(t, reg)
	want := map[string]string{
		"disposition": "deny",
		"reason":      "identity_mismatch",
		"fault":       "false",
		"transport":   "tls",
	}
	if got := counterWithLabels(fam, want); got != 1 {
		t.Fatalf("aksh_decisions_total%v = %v, want 1", want, got)
	}
}

// TestServe_DecisionAllow_DoesNotDoubleCountPolicyAllows verifies the fix
// does not add a second, request-granularity "allow" series alongside the
// existing connection-granularity allow metric recorded by the listener and
// upstream dialer layers. Only denials are genuinely missing (#60); allows
// are already observable at the connection layer, so a per-request handler
// allow would misleadingly inflate the allow bucket relative to deny.
func TestServe_DecisionAllow_DoesNotDoubleCountPolicyAllows(t *testing.T) {
	sink := &recordingSink{}
	reg := prometheus.NewRegistry()
	metrics, err := audit.NewPromMetricsRecorder(reg)
	if err != nil {
		t.Fatalf("NewPromMetricsRecorder() error = %v", err)
	}
	dialer := &scriptedDialer{
		fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
			handlerConn, upstreamConn := net.Pipe()
			go func() {
				defer upstreamConn.Close()
				if _, err := http.ReadRequest(bufio.NewReader(upstreamConn)); err != nil {
					return
				}
				_, _ = upstreamConn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
			}()
			return handlerConn, nil
		},
	}

	handler, err := NewHandler(allowRelayPipeline(sink, "cred-1"), dialer, sink, metrics, DefaultOptions())
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	downstream, client := net.Pipe()
	done := serveHandler(t, handler, downstream)
	br := bufio.NewReader(client)

	writeRequest(t, client, "GET /resource HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	resp := mustReadResponse(t, br, nil)
	_ = readBody(t, resp)
	client.Close()
	waitServeDone(t, done)

	fam := famDecisions(t, reg)
	if got := counterWithLabels(fam, map[string]string{
		"disposition": "allow",
		"reason":      "unspecified",
		"fault":       "false",
		"transport":   "tls",
	}); got > 0 {
		t.Fatalf("handler recorded a request-level allow decision (got %v); allow is already tracked at the connection layer (listener/upstream), so this would double count", got)
	}
}
