// Package pki defines the S8 CA provider interface and the per-pod CA
// provider used to sign leaf certificates.
package pki

import (
	"crypto"
	"crypto/x509"
)

// CAProvider supplies the CA used to sign leaf certificates and reports a
// generation that invalidates the leaf cache. Rotation is a pod restart
// (ADR-S5-01), so there is no in-place rotate.
//
// Caller invariant: callers MUST NOT invoke Signer() before the Orchestrator
// passes the CA startup gate. The gate guarantees a non-nil cert+signer for
// the pod lifetime, so Signer() has no error return; an uninitialized CA is a
// fatal invariant violation, not a recoverable per-leaf error. PublicPEM
// returns a copy-safe PEM encoding of the public CA certificate.
type CAProvider interface {
	Signer() (*x509.Certificate, crypto.Signer)
	Generation() uint64
	PublicPEM() []byte
}
