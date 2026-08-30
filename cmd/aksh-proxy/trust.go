package main

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// upstreamCADir is the mount path for the operator-provided upstream CA
// material. It is tolerated to be absent (see appendCertsFromDir).
const upstreamCADir = "/etc/aksh/upstream-ca"

// buildUpstreamTrustPool constructs the upstream TLS trust pool in Go, replacing
// the shell SSL_CERT_FILE concatenation approach. It starts from a clone of
// systemPool (or an empty pool when systemPool is nil), then appends every PEM
// certificate found in caPubDir (the pod CA public material) and extraCADir
// (the mounted upstream CA, normally the upstreamCADir constant). A missing or
// empty directory is tolerated; an unreadable or malformed certificate file
// fails closed with an error.
func buildUpstreamTrustPool(systemPool *x509.CertPool, caPubDir, extraCADir string) (*x509.CertPool, error) {
	var pool *x509.CertPool
	if systemPool != nil {
		pool = systemPool.Clone()
	} else {
		pool = x509.NewCertPool()
	}

	for _, dir := range []string{caPubDir, extraCADir} {
		if err := appendCertsFromDir(pool, dir); err != nil {
			return nil, err
		}
	}
	return pool, nil
}

// appendCertsFromDir appends every PEM certificate file in dir to pool. An empty
// dir path or a non-existent directory is skipped. Any unreadable file or file
// that carries no valid PEM certificate is an error, so the trust pool fails
// closed rather than silently trusting less than intended.
func appendCertsFromDir(pool *x509.CertPool, dir string) error {
	if strings.TrimSpace(dir) == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("aksh-proxy: trust: read dir %q: %w", dir, err)
	}
	// Canonicalise the base directory once so containment is compared
	// canonical-vs-canonical: a symlinked mount root would otherwise make an
	// in-dir cert look out of dir. Fall back to the lexical clean if the dir
	// cannot be resolved (e.g. a transient race); the per-entry check below
	// still applies.
	cleanDir := filepath.Clean(dir)
	if resolvedDir, err := filepath.EvalSymlinks(cleanDir); err == nil {
		cleanDir = resolvedDir
	}
	for _, entry := range entries {
		name := entry.Name()
		// Kubernetes atomic-writer volumes (ConfigMap and Secret mounts) create
		// double-dot bookkeeping entries: a "..data" symlink pointing at the
		// current "..2026_..." timestamped directory, plus that directory itself.
		// Skip only the ".." prefix (the kubelet convention) so we never ReadFile
		// a directory-symlink and fail closed spuriously, while ordinary cert
		// files (including single-dot names) are still considered.
		if strings.HasPrefix(name, "..") {
			continue
		}
		certPath := filepath.Join(dir, name)
		// os.Stat follows symlinks (atomic-writer keys are symlinks to the
		// timestamped dir). Only regular files are candidate certificates: this
		// skips directories AND non-regular files (sockets, devices, FIFOs) that
		// must never be read as a cert.
		info, err := os.Stat(certPath)
		if err != nil {
			return fmt.Errorf("aksh-proxy: trust: stat cert %q: %w", certPath, err)
		}
		if !info.Mode().IsRegular() {
			continue
		}
		// Containment: a non-".."-prefixed symlink could point outside dir (e.g.
		// evil.crt -> /etc/ssl/other-ca.pem) and silently broaden the trust pool.
		// Resolve the target, require it to stay within cleanDir, and read the
		// bytes from the RESOLVED path so the containment decision and the read
		// observe the same target (no TOCTOU between EvalSymlinks and ReadFile).
		// The Kubernetes atomic-writer keys (tls.crt -> ..data/tls.crt ->
		// ..2026_.../) resolve back under dir, so this does not reject them.
		realPath, err := filepath.EvalSymlinks(certPath)
		if err != nil {
			return fmt.Errorf("aksh-proxy: trust: resolve cert %q: %w", certPath, err)
		}
		rel, err := filepath.Rel(cleanDir, realPath)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("aksh-proxy: trust: cert %q resolves outside trusted dir %q", certPath, dir)
		}
		data, err := os.ReadFile(realPath)
		if err != nil {
			return fmt.Errorf("aksh-proxy: trust: read cert %q: %w", certPath, err)
		}
		if !pool.AppendCertsFromPEM(data) {
			return fmt.Errorf("aksh-proxy: trust: %q is not a valid PEM certificate", certPath)
		}
	}
	return nil
}
