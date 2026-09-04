// Package probe implements the keepalive/liveness probe for the demo.
//
// It is meant to run in a SEPARATE sidecar container from the MCP server. Its
// only job is to periodically emit captured egress to the real telemetry host
// so the aksh sidecar's Phase-B accept probe sees a redirected connection from
// the first seconds of pod life, before the agent ever calls the tool. It hits
// the telemetry host at /__aksh_probe — never the MCP server's loopback
// endpoint, which is inbound in-pod traffic and is not the egress under test.
//
// It uses the identical IPv4-only, combined-CA-bundle client as the uploader,
// so what keeps the connection warm is the same flow aksh polices.
package probe

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/girishmotwani/aksh/demo/agentcon-japan/diagnostics-mcp/internal/upload"
)

// Config configures the probe loop.
type Config struct {
	// URL is the telemetry probe endpoint, e.g.
	// https://telemetry.ops-insights.example/__aksh_probe
	URL string
	// CABundlePath is the combined CA bundle (collector CA + aksh pod CA).
	CABundlePath string
	// Interval between probes.
	Interval time.Duration
	// Timeout bounds a single probe request.
	Timeout time.Duration

	// Logf and client are injectable for tests.
	Logf   func(format string, args ...any)
	client *http.Client
}

// Prober performs one probe per Do() call.
type Prober struct {
	url    string
	client *http.Client
	logf   func(format string, args ...any)
}

// New validates the config, refuses a loopback/MCP target, and builds a Prober
// using the same IPv4-only, CA-pinned client as the uploader.
func New(cfg Config) (*Prober, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("probe URL is required")
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("parse probe URL: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("probe URL must be https, got %q", u.Scheme)
	}
	if upload.IsLoopbackName(u.Hostname()) {
		return nil, fmt.Errorf("probe must target the real telemetry host, not loopback %q", u.Hostname())
	}
	if u.Path != "/__aksh_probe" {
		return nil, fmt.Errorf("probe path must be /__aksh_probe, got %q", u.Path)
	}
	logf := cfg.Logf
	if logf == nil {
		logf = log.Printf
	}
	client := cfg.client
	if client == nil {
		client, err = upload.NewIPv4Client(cfg.CABundlePath, cfg.Timeout, nil, nil)
		if err != nil {
			return nil, err
		}
	}
	return &Prober{url: cfg.URL, client: client, logf: logf}, nil
}

// Do performs a single probe request and returns the HTTP status code. Any
// status (including non-2xx) is a successful probe from the demo's point of
// view — the goal is to produce a captured connection, not to succeed at the
// application layer. A transport error is returned as err.
func (p *Prober) Do(ctx context.Context) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "aksh-diagnostics-probe/1")
	resp, err := p.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, nil
}

// Run loops until ctx is cancelled, probing every Interval. It never exits on a
// probe error — a keepalive that gave up on the first failure would defeat its
// purpose — it logs and continues.
func (p *Prober) Run(ctx context.Context, interval, timeout time.Duration) {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		p.once(ctx, timeout)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (p *Prober) once(ctx context.Context, timeout time.Duration) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	code, err := p.Do(cctx)
	if err != nil {
		p.logf("[probe] %s -> error: %v", p.url, err)
		return
	}
	p.logf("[probe] %s -> HTTP %d", p.url, code)
}
