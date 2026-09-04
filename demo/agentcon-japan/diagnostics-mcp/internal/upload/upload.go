// Package upload POSTs the diagnostics envelope to the telemetry endpoint over
// an IPv4-only, SNI-preserving TLS connection whose trust anchor is a single
// operator-supplied combined CA bundle.
//
// Why IPv4-only and why the real hostname is preserved: in the demo the aksh
// sidecar captures the pod's egress at the socket layer. It only hooks IPv4
// connect() and denies IPv6, and it selects policy on the TLS SNI of the
// captured connection. So to be captured, policed and audited the client MUST
// dial the real telemetry hostname over IPv4 and present that hostname as SNI.
// Dialing localhost/::1 would bypass capture entirely, so it is refused.
package upload

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const defaultTimeout = 10 * time.Second
const defaultAllowedHost = "telemetry.ops-insights.example"

// LookupIPFunc resolves a host to IPs. Injectable for tests.
type LookupIPFunc func(ctx context.Context, host string) ([]net.IP, error)

// contextDialer is the slice of net.Dialer we need; a fake implements it in
// tests to assert the network/address the resolver hands to the dial.
type contextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Config configures an Uploader.
type Config struct {
	// Endpoint is the full telemetry URL, e.g.
	// https://telemetry.ops-insights.example/api/v1/cluster-diagnostics
	Endpoint string
	// AllowedHost is the only hostname a prompt-supplied endpoint may target.
	// Empty selects the reserved demo hostname.
	AllowedHost string
	// CABundlePath is the combined CA bundle (collector CA + aksh pod CA). It
	// is the ONLY trust anchor; system roots are intentionally not used.
	CABundlePath string
	// Timeout bounds a single upload attempt.
	Timeout time.Duration
	// AuthorizationBearer, when non-empty, is sent as `Authorization: Bearer
	// <value>` on the request. This is the credential "slot" aksh brokers: on a
	// captured egress aksh strips it and injects a credential only for an
	// approved destination, so an allowed-but-unbrokered destination receives an
	// empty Authorization. Used by the credential-handoff tool to demonstrate
	// that strip/inject boundary.
	AuthorizationBearer string

	// The following are injected in tests; production leaves them nil.
	lookupIP    LookupIPFunc
	dialContext func(ctx context.Context, network, address string) (net.Conn, error)
}

// Result is the verbatim outcome of a single upload attempt.
type Result struct {
	StatusCode int
	// Status is the verbatim HTTP status line reason, e.g. "403 Forbidden".
	Status string
}

// OK reports whether the status was 2xx.
func (r Result) OK() bool { return r.StatusCode >= 200 && r.StatusCode < 300 }

// Message renders the operator-facing, verbatim status line.
func (r Result) Message() string {
	if r.OK() {
		return fmt.Sprintf("upload succeeded: HTTP %s", r.Status)
	}
	return fmt.Sprintf("upload failed: HTTP %s", r.Status)
}

// Uploader performs exactly one POST per Upload call. It never retries — a
// denied request must surface, not be re-attempted.
type Uploader struct {
	endpoint   string
	client     *http.Client
	authBearer string
}

// New builds an Uploader, loading and validating the CA bundle up front so a
// misconfigured trust store fails loudly before any request is attempted.
func New(cfg Config) (*Uploader, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("telemetry endpoint is required")
	}
	endpoint, err := ValidateEndpoint(cfg.Endpoint, cfg.AllowedHost)
	if err != nil {
		return nil, err
	}

	client, err := NewIPv4Client(cfg.CABundlePath, cfg.Timeout, cfg.lookupIP, cfg.dialContext)
	if err != nil {
		return nil, err
	}
	return &Uploader{endpoint: endpoint, client: client, authBearer: cfg.AuthorizationBearer}, nil
}

// ValidateEndpoint bounds the URL supplied through the chat prompt to the
// controlled demo collector. This keeps the presentation prompt-driven without
// turning the tool into a general SSRF primitive.
func ValidateEndpoint(raw, allowedHost string) (string, error) {
	if allowedHost == "" {
		allowedHost = defaultAllowedHost
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse telemetry endpoint: %w", err)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("telemetry endpoint must be https")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
		return "", fmt.Errorf("telemetry endpoint must not contain userinfo, query, fragment, or encoded path")
	}
	if !strings.EqualFold(u.Hostname(), allowedHost) {
		return "", fmt.Errorf("telemetry host %q is not the configured demo host", u.Hostname())
	}
	if net.ParseIP(u.Hostname()) != nil || IsLoopbackName(u.Hostname()) {
		return "", fmt.Errorf("telemetry endpoint must use the configured DNS hostname")
	}
	if port := u.Port(); port != "" && port != "443" {
		return "", fmt.Errorf("telemetry endpoint port must be 443")
	}
	if u.Path != "/api/v1/cluster-diagnostics" {
		return "", fmt.Errorf("telemetry endpoint path must be /api/v1/cluster-diagnostics")
	}
	u.Host = allowedHost
	if u.Port() == "443" {
		u.Host = net.JoinHostPort(allowedHost, "443")
	}
	return u.String(), nil
}

// NewIPv4Client builds an *http.Client whose only trust anchor is the combined
// CA bundle at caPath and whose dialer is IPv4-only, refuses loopback, and
// preserves the request hostname as TLS SNI. It is shared by the uploader and
// the keepalive probe so both egress paths behave identically under aksh
// capture. lookup and dial are nil in production.
func NewIPv4Client(caPath string, timeout time.Duration, lookup LookupIPFunc, dial func(context.Context, string, string) (net.Conn, error)) (*http.Client, error) {
	pool, err := loadCABundle(caPath)
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip4", host)
		}
	}
	if dial == nil {
		dial = IPv4DialContext(&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}, lookup)
	}
	transport := &http.Transport{
		DialContext: dial,
		// ForceAttemptHTTP2 off + no h2: the aksh request path is HTTP/1.x.
		ForceAttemptHTTP2:   false,
		TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: timeout,
		MaxIdleConns:        4,
		IdleConnTimeout:     30 * time.Second,
		// SNI is derived from the request URL host by the transport, so the
		// real telemetry hostname is presented even though DialContext
		// connects to a resolved IPv4 literal.
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		// A redirect must never turn one validated prompt destination into a
		// second request to another host or replay the diagnostic POST.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

// Upload POSTs body exactly once and returns the verbatim result. A transport
// error (timeout, TLS/CA failure, no IPv4) is returned as err; an HTTP response
// — including non-2xx — is returned as a Result with nil err.
func (u *Uploader) Upload(ctx context.Context, body []byte) (Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.endpoint, bytes.NewReader(body))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "aksh-diagnostics-mcp/1")
	if u.authBearer != "" {
		// The credential slot aksh sanitises/brokers. On a captured egress this
		// is stripped; only an approved destination gets a credential injected.
		req.Header.Set("Authorization", "Bearer "+u.authBearer)
	}
	req.ContentLength = int64(len(body))

	resp, err := u.client.Do(req)
	if err != nil {
		return Result{}, classifyErr(err)
	}
	defer resp.Body.Close()
	// Drain a bounded amount so the connection can be reused; the body is not
	// otherwise used.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))

	status := strings.TrimSpace(strings.TrimPrefix(resp.Status, fmt.Sprintf("%d", resp.StatusCode)))
	if status == "" {
		status = http.StatusText(resp.StatusCode)
	}
	return Result{StatusCode: resp.StatusCode, Status: fmt.Sprintf("%d %s", resp.StatusCode, status)}, nil
}

func classifyErr(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("upload timed out: %w", err)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return fmt.Errorf("upload timed out: %w", err)
	}
	var caErr x509.UnknownAuthorityError
	if errors.As(err, &caErr) {
		return fmt.Errorf("telemetry TLS certificate not trusted by configured CA bundle: %w", err)
	}
	var hostErr x509.HostnameError
	if errors.As(err, &hostErr) {
		return fmt.Errorf("telemetry TLS certificate hostname mismatch: %w", err)
	}
	return err
}

func loadCABundle(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, errors.New("CA bundle path is required (combined collector CA + aksh pod CA)")
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA bundle %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("CA bundle %s contained no valid certificates", path)
	}
	return pool, nil
}

// IsLoopbackName reports whether host is a loopback name/literal that must
// never be dialed for telemetry (it would bypass aksh capture).
func IsLoopbackName(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	switch h {
	case "localhost", "ip6-localhost", "ip6-loopback":
		return true
	}
	if strings.HasSuffix(h, ".localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback() || ip.IsUnspecified()
	}
	return false
}

// SelectIPv4 filters ips to routable IPv4 addresses, dropping IPv6, loopback
// and unspecified entries. It returns an error if none remain.
func SelectIPv4(host string, ips []net.IP) ([]net.IP, error) {
	var v4 []net.IP
	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 == nil {
			continue // IPv6 — never used
		}
		if ip4.IsLoopback() || ip4.IsUnspecified() {
			continue
		}
		v4 = append(v4, ip4)
	}
	if len(v4) == 0 {
		return nil, fmt.Errorf("no routable IPv4 address for %q (IPv4-only egress; localhost/::1 refused)", host)
	}
	return v4, nil
}

// IPv4DialContext returns a DialContext that resolves the host to IPv4 only,
// refuses loopback, and always dials over "tcp4". It leaves TLS/SNI to the
// caller (the transport), so the original hostname is preserved as SNI.
func IPv4DialContext(d contextDialer, lookup LookupIPFunc) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if IsLoopbackName(host) {
			return nil, fmt.Errorf("refusing to dial loopback host %q: telemetry must egress to the real host over IPv4", host)
		}
		var ips []net.IP
		if lit := net.ParseIP(host); lit != nil {
			ips = []net.IP{lit}
		} else {
			ips, err = lookup(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("resolve %q: %w", host, err)
			}
		}
		v4, err := SelectIPv4(host, ips)
		if err != nil {
			return nil, err
		}
		var lastErr error
		for _, ip := range v4 {
			conn, derr := d.DialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), port))
			if derr == nil {
				return conn, nil
			}
			lastErr = derr
		}
		return nil, lastErr
	}
}
