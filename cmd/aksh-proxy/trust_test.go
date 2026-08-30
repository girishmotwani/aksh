package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// selfSignedCertPEM returns a parsed self-signed CA certificate and its PEM
// encoding for the trust-pool tests.
func selfSignedCertPEM(t *testing.T, cn string) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// writeCert writes PEM bytes into dir/name.
func writeCert(t *testing.T, dir, name string, pemBytes []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), pemBytes, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
}

func TestBuildUpstreamTrustPool_SystemRootsPreservedAndPodCAAppended(t *testing.T) {
	sysCert, _ := selfSignedCertPEM(t, "system-root")
	sysPool := x509.NewCertPool()
	sysPool.AddCert(sysCert)

	_, podPEM := selfSignedCertPEM(t, "pod-ca")
	caPubDir := t.TempDir()
	writeCert(t, caPubDir, "ca.crt", podPEM)

	pool, err := buildUpstreamTrustPool(sysPool, caPubDir, "")
	if err != nil {
		t.Fatalf("buildUpstreamTrustPool() error = %v, want nil", err)
	}
	if got := len(pool.Subjects()); got != 2 {
		t.Fatalf("pool has %d subjects, want 2 (system root preserved + pod CA appended)", got)
	}
}

func TestBuildUpstreamTrustPool_UpstreamCAAppended(t *testing.T) {
	_, upstreamPEM := selfSignedCertPEM(t, "upstream-ca")
	upstreamDir := t.TempDir()
	writeCert(t, upstreamDir, "upstream.crt", upstreamPEM)

	pool, err := buildUpstreamTrustPool(nil, "", upstreamDir)
	if err != nil {
		t.Fatalf("buildUpstreamTrustPool() error = %v, want nil", err)
	}
	if got := len(pool.Subjects()); got != 1 {
		t.Fatalf("pool has %d subjects, want 1 (upstream CA appended)", got)
	}
}

func TestBuildUpstreamTrustPool_MissingDirTolerated(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-dir")
	pool, err := buildUpstreamTrustPool(nil, missing, missing)
	if err != nil {
		t.Fatalf("buildUpstreamTrustPool() error = %v, want nil (missing dir tolerated)", err)
	}
	if got := len(pool.Subjects()); got != 0 {
		t.Fatalf("pool has %d subjects, want 0", got)
	}
}

func TestBuildUpstreamTrustPool_MalformedPEM_ReturnsError(t *testing.T) {
	caPubDir := t.TempDir()
	writeCert(t, caPubDir, "bad.crt", []byte("this is not a valid PEM certificate"))

	if _, err := buildUpstreamTrustPool(nil, caPubDir, ""); err == nil {
		t.Fatal("buildUpstreamTrustPool() error = nil, want error for malformed PEM (fail closed)")
	}
}

func TestBuildUpstreamTrustPool_BothDirsEmpty_ReturnsSystemPoolClone(t *testing.T) {
	sysCert, _ := selfSignedCertPEM(t, "system-root")
	sysPool := x509.NewCertPool()
	sysPool.AddCert(sysCert)

	pool, err := buildUpstreamTrustPool(sysPool, "", "")
	if err != nil {
		t.Fatalf("buildUpstreamTrustPool() error = %v, want nil", err)
	}
	if got := len(pool.Subjects()); got != 1 {
		t.Fatalf("pool has %d subjects, want 1 (system pool clone)", got)
	}
}

// TestBuildUpstreamTrustPool_KubernetesAtomicWriterLayout reproduces the
// directory shape a Kubernetes ConfigMap/Secret mount creates: a timestamped
// "..2026_..." data directory, a "..data" symlink to it, and a per-key symlink
// pointing through "..data". The "..data" symlink resolves to a directory, so a
// naive DirEntry.IsDir() check would try to ReadFile it and fail closed. The
// build must skip the dotfile bookkeeping and append the single real cert once.
func TestBuildUpstreamTrustPool_KubernetesAtomicWriterLayout(t *testing.T) {
	_, upstreamPEM := selfSignedCertPEM(t, "upstream-ca")

	mount := t.TempDir()
	dataDir := filepath.Join(mount, "..2026_01_02_03_04_05.123456789")
	if err := os.Mkdir(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir data dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "upstream.crt"), upstreamPEM, 0o600); err != nil {
		t.Fatalf("write cert into data dir: %v", err)
	}
	if err := os.Symlink(dataDir, filepath.Join(mount, "..data")); err != nil {
		t.Skipf("symlink unsupported in this environment: %v", err)
	}
	if err := os.Symlink(filepath.Join("..data", "upstream.crt"), filepath.Join(mount, "upstream.crt")); err != nil {
		t.Skipf("symlink unsupported in this environment: %v", err)
	}

	pool, err := buildUpstreamTrustPool(nil, "", mount)
	if err != nil {
		t.Fatalf("buildUpstreamTrustPool() error = %v, want nil on atomic-writer layout", err)
	}
	if got := len(pool.Subjects()); got != 1 {
		t.Fatalf("pool has %d subjects, want 1 (single real cert appended once)", got)
	}
}

// TestBuildUpstreamTrustPool_SymlinkEscapingDir_FailsClosed verifies the
// containment guard: a non-".."-prefixed symlink whose target resolves OUTSIDE
// the trusted directory (even to a valid PEM) must be rejected so the trust pool
// cannot be silently broadened by a planted symlink.
func TestBuildUpstreamTrustPool_SymlinkEscapingDir_FailsClosed(t *testing.T) {
	_, outsidePEM := selfSignedCertPEM(t, "outside-ca")

	outsideDir := t.TempDir()
	outsideCert := filepath.Join(outsideDir, "outside.crt")
	if err := os.WriteFile(outsideCert, outsidePEM, 0o600); err != nil {
		t.Fatalf("write outside cert: %v", err)
	}

	trustDir := t.TempDir()
	if err := os.Symlink(outsideCert, filepath.Join(trustDir, "evil.crt")); err != nil {
		t.Skipf("symlink unsupported in this environment: %v", err)
	}

	if _, err := buildUpstreamTrustPool(nil, "", trustDir); err == nil {
		t.Fatal("buildUpstreamTrustPool() error = nil, want a containment error for a symlink escaping the trusted dir")
	}
}
