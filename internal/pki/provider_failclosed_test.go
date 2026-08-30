package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// These are supplementary (non-binding) regression tests. They are NOT part of
// the binding UnitTests spec (tests 25-44); they exist to lock in the fatal
// fail-closed branches of NewPodCAProvider so a future refactor cannot silently
// weaken them: (a) exactly-one-of-key/cert present is a fatal inconsistent
// state, (b) an unreadable/irregular CA path is fatal rather than treated as
// absent (no silent regeneration), (c) a loaded cert that is not a valid
// signing CA or is outside its validity window is fatal, and (d) a missing
// public copy on reload is fatal.

// makeSelfSignedCustom builds a self-signed cert for key using mutate to
// customise the template (IsCA, validity window, key usage). The returned cert
// is signed by and matches key, so mismatch checks pass and the target
// invariant is what gets exercised.
func makeSelfSignedCustom(t *testing.T, mutate func(*x509.Certificate)) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	mutate(tmpl)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return key, cert
}

func writeKeyCert(t *testing.T, dir string, key *ecdsa.PrivateKey, cert *x509.Certificate) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, privKeyFile), testKeyPEM(t, key), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, caCertFile), testCertPEM(cert), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestNewPodCAProvider_OnlyKeyPresent_FailsClosedInconsistentState(t *testing.T) {
	priv := t.TempDir()
	pub := t.TempDir()
	key, _ := makeSelfSignedCA(t)
	if err := os.WriteFile(filepath.Join(priv, privKeyFile), testKeyPEM(t, key), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPodCAProvider(context.Background(), PodCAOptions{PrivDir: priv, PubDir: pub}); err == nil {
		t.Fatal("expected fatal inconsistent-state error when only the key is present, got nil")
	}
	// Must not regenerate a cert over the inconsistent state.
	if _, err := os.Stat(filepath.Join(priv, caCertFile)); !os.IsNotExist(err) {
		t.Fatalf("cert must not be created over inconsistent state, stat err=%v", err)
	}
}

func TestNewPodCAProvider_OnlyCertPresent_FailsClosedInconsistentState(t *testing.T) {
	priv := t.TempDir()
	pub := t.TempDir()
	_, cert := makeSelfSignedCA(t)
	if err := os.WriteFile(filepath.Join(priv, caCertFile), testCertPEM(cert), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPodCAProvider(context.Background(), PodCAOptions{PrivDir: priv, PubDir: pub}); err == nil {
		t.Fatal("expected fatal inconsistent-state error when only the cert is present, got nil")
	}
	if _, err := os.Stat(filepath.Join(priv, privKeyFile)); !os.IsNotExist(err) {
		t.Fatalf("key must not be created over inconsistent state, stat err=%v", err)
	}
}

func TestNewPodCAProvider_CertPathIsDirectory_FailsClosed(t *testing.T) {
	priv := t.TempDir()
	pub := t.TempDir()
	key, _ := makeSelfSignedCA(t)
	if err := os.WriteFile(filepath.Join(priv, privKeyFile), testKeyPEM(t, key), 0o600); err != nil {
		t.Fatal(err)
	}
	// A directory at the cert path is an irregular state: a stat "exists" that
	// is not a readable regular file must fail closed, not be treated as absent.
	if err := os.Mkdir(filepath.Join(priv, caCertFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPodCAProvider(context.Background(), PodCAOptions{PrivDir: priv, PubDir: pub}); err == nil {
		t.Fatal("expected fatal error when cert path is a directory, got nil")
	}
}

func TestNewPodCAProvider_LoadedCertNotCA_FailsClosed(t *testing.T) {
	priv := t.TempDir()
	pub := t.TempDir()
	key, cert := makeSelfSignedCustom(t, func(c *x509.Certificate) {
		c.IsCA = false
		c.KeyUsage = x509.KeyUsageDigitalSignature
	})
	writeKeyCert(t, priv, key, cert)
	if _, err := NewPodCAProvider(context.Background(), PodCAOptions{PrivDir: priv, PubDir: pub}); err == nil {
		t.Fatal("expected fatal error for a loaded non-CA cert, got nil")
	}
}

func TestNewPodCAProvider_LoadedCertExpired_FailsClosed(t *testing.T) {
	priv := t.TempDir()
	pub := t.TempDir()
	key, cert := makeSelfSignedCustom(t, func(c *x509.Certificate) {
		c.NotBefore = time.Now().Add(-48 * time.Hour)
		c.NotAfter = time.Now().Add(-24 * time.Hour)
	})
	writeKeyCert(t, priv, key, cert)
	if _, err := NewPodCAProvider(context.Background(), PodCAOptions{PrivDir: priv, PubDir: pub}); err == nil {
		t.Fatal("expected fatal error for a loaded expired CA cert, got nil")
	}
}

func TestNewPodCAProvider_MissingPublicCopyOnReload_FailsClosed(t *testing.T) {
	priv := t.TempDir()
	pub := t.TempDir()
	key, cert := makeSelfSignedCA(t)
	writeKeyCert(t, priv, key, cert)
	// PubDir intentionally has no ca-cert.pem: reload must fail closed rather
	// than proceed with an unverifiable public copy.
	if _, err := NewPodCAProvider(context.Background(), PodCAOptions{PrivDir: priv, PubDir: pub}); err == nil {
		t.Fatal("expected fatal error when the public CA copy is missing on reload, got nil")
	}
}
