// Package upstream implements the Phase 5A direct upstream dialer:
// DirectDialer establishes exactly one TLS connection per DialUpstream call
// to the kernel-attested destination and verifies the peer against the
// validated identity. It performs no connection pooling -- that is Phase 5C
// (ADR-S1a-10). credID is accepted, validated, and recorded because 5C makes
// it part of the pool key; it is otherwise unused in 5A.
//
// DirectDialer enforces the loop-guard defense-in-depth: before creating any
// socket, it refuses to dial the proxy's own listener endpoint (the
// deterministic half of the loop-guard), and it registers/deregisters every
// dialed connection's local address in a listener.SelfDialRegistry so the
// accept loop can classify a redirected self-dial that lands in the race
// window between connect() and accept() (the second, defense-in-depth half).
// The primary, race-free loop-guard control is the orig_dst.uid == proxy_uid
// check performed upstream of this package, in the capture/resolver layer;
// see docs/design/S1a-dataplane-capture.md §8.3 for the full discussion of
// why this package cannot and does not perform a peer-uid lookup itself.
//
// This package is platform-neutral: it has no build tags and no dependency
// on the kernel-facing capture package.
//
// Design: docs/design/S1a-dataplane-capture.md §8.3.
package upstream
