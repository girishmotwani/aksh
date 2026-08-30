// Package tlsterm implements the Phase 5A TLS termination layer: SNI
// canonicalisation, a generation-aware per-identity leaf-certificate cache
// with single-flight mint coalescing, and a *tls.Config supplier keyed by the
// ClientHello's server name.
//
// tlsterm sits between the capture/listener layer and the request path: it
// terminates the intercepted TLS connection using a short-lived leaf
// certificate minted (and cached) per canonicalised SNI, backed by the CA
// exposed through pki.CAProvider. Certificates are re-minted whenever the
// CA's generation counter advances, so a CA rotation is observed by every new
// cache lookup without requiring an explicit cache flush.
//
// This package is platform-neutral: it has no build tags and no dependency on
// the kernel-facing capture package.
//
// Design: docs/design/S1a-dataplane-capture.md §8.2, §11.1.
package tlsterm
