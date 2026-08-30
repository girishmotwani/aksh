// Package dataplane defines the S1 data-plane interfaces:
// connection interception, TLS leaf certificate supply, and upstream dialling.
package dataplane

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
)

// DestinationResolver recovers the pre-NAT destination of an
// intercepted connection. The destination is kernel-attested: it is
// read from a BPF map written by the capture programs, not from a
// socket option (see docs/design/S1a-dataplane-capture.md section 6.3).
type DestinationResolver interface {
	Resolve(conn net.Conn) (netip.AddrPort, error)
}

// LeafSource supplies a TLS certificate for a requested SNI,
// minted on the fly and backed by a cache.
type LeafSource interface {
	CertificateFor(ctx context.Context, serverName string) (*tls.Certificate, error)
}

// UpstreamDialer establishes a verified TLS connection to the true
// destination. The pool key includes credID per INV-8 rule 7 — a pooled
// connection must never be reused across credential identities.
type UpstreamDialer interface {
	DialUpstream(ctx context.Context, addr netip.AddrPort, serverName string, credID string) (net.Conn, error)
}
