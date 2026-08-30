package pki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func makeSelfSignedCA(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
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

func testKeyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func testCertPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// 25
func TestNewPodCAProvider_EmptyPrivDir_ReturnsError(t *testing.T) {
	pub := t.TempDir()
	if _, err := NewPodCAProvider(context.Background(), PodCAOptions{PrivDir: "", PubDir: pub}); err == nil {
		t.Fatal("expected error for empty PrivDir, got nil")
	}
	if entries, _ := os.ReadDir(pub); len(entries) != 0 {
		t.Fatalf("PubDir should be untouched, found %d entries", len(entries))
	}
}

// 26
func TestNewPodCAProvider_EmptyPubDir_ReturnsError(t *testing.T) {
	priv := t.TempDir()
	if _, err := NewPodCAProvider(context.Background(), PodCAOptions{PrivDir: priv, PubDir: ""}); err == nil {
		t.Fatal("expected error for empty PubDir, got nil")
	}
	entries, err := os.ReadDir(priv)
	if err != nil {
		t.Fatalf("read PrivDir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("PrivDir must be left untouched, found %d entries", len(entries))
	}
}

// 27
func TestNewPodCAProvider_KeyCertMismatch_ReturnsFatalStartupError(t *testing.T) {
	priv := t.TempDir()
	pub := t.TempDir()
	keyA, _ := makeSelfSignedCA(t)
	_, certA := makeSelfSignedCA(t) // cert whose public key is NOT keyA's
	if err := os.WriteFile(filepath.Join(priv, privKeyFile), testKeyPEM(t, keyA), 0o600); err != nil {
		t.Fatal(err)
	}
	certBytes := testCertPEM(certA)
	if err := os.WriteFile(filepath.Join(priv, caCertFile), certBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPodCAProvider(context.Background(), PodCAOptions{PrivDir: priv, PubDir: pub}); err == nil {
		t.Fatal("expected fatal startup error for key/cert mismatch, got nil")
	}
	// Must not regenerate over the mismatch: cert file unchanged.
	after, err := os.ReadFile(filepath.Join(priv, caCertFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, certBytes) {
		t.Fatal("cert file was regenerated over the mismatch")
	}
}

// 28
func TestNewPodCAProvider_PublicPrivateMismatch_ReturnsFatalStartupError(t *testing.T) {
	priv := t.TempDir()
	pub := t.TempDir()
	keyA, certA := makeSelfSignedCA(t)
	_, certB := makeSelfSignedCA(t)
	if err := os.WriteFile(filepath.Join(priv, privKeyFile), testKeyPEM(t, keyA), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(priv, caCertFile), testCertPEM(certA), 0o644); err != nil {
		t.Fatal(err)
	}
	// Public copy differs from the private CA certificate.
	if err := os.WriteFile(filepath.Join(pub, caCertFile), testCertPEM(certB), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPodCAProvider(context.Background(), PodCAOptions{PrivDir: priv, PubDir: pub}); err == nil {
		t.Fatal("expected fatal startup error for public/private mismatch, got nil")
	}
}

// 29
func TestNewPodCAProvider_AbsentFiles_GeneratesECDSAP256CA(t *testing.T) {
	prov, err := NewPodCAProvider(context.Background(), PodCAOptions{PrivDir: t.TempDir(), PubDir: t.TempDir()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cert, signer := prov.Signer()
	if cert == nil || signer == nil {
		t.Fatal("Signer() returned nil cert or signer")
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("CA public key type = %T, want *ecdsa.PublicKey", cert.PublicKey)
	}
	if pub.Curve != elliptic.P256() {
		t.Fatalf("CA curve = %v, want P-256", pub.Curve.Params().Name)
	}
	if !cert.IsCA {
		t.Fatal("generated CA cert IsCA = false")
	}
	// Usable for leaf signing.
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "leaf"}, DNSNames: []string{"leaf"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	if _, err := x509.CreateCertificate(rand.Reader, tmpl, cert, &leafKey.PublicKey, signer); err != nil {
		t.Fatalf("generated CA cannot sign a leaf: %v", err)
	}
}

// 30
func TestNewPodCAProvider_GeneratedCA_PersistsPrivateKeyAndCert(t *testing.T) {
	priv := t.TempDir()
	if _, err := NewPodCAProvider(context.Background(), PodCAOptions{PrivDir: priv, PubDir: t.TempDir()}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, name := range []string{privKeyFile, caCertFile} {
		data, err := os.ReadFile(filepath.Join(priv, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		block, _ := pem.Decode(data)
		if block == nil {
			t.Fatalf("%s does not contain a PEM block", name)
		}
		if len(block.Bytes) == 0 {
			t.Fatalf("%s PEM block is empty", name)
		}
	}
}

// 31
func TestNewPodCAProvider_GeneratedCA_WritesPublicPEM(t *testing.T) {
	pub := t.TempDir()
	prov, err := NewPodCAProvider(context.Background(), PodCAOptions{PrivDir: t.TempDir(), PubDir: pub})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	onDisk, err := os.ReadFile(filepath.Join(pub, caCertFile))
	if err != nil {
		t.Fatalf("read public PEM: %v", err)
	}
	if !bytes.Equal(onDisk, prov.PublicPEM()) {
		t.Fatal("public PEM on disk does not equal PublicPEM()")
	}
	if strings.Contains(string(onDisk), "PRIVATE KEY") {
		t.Fatal("public PEM contains private key bytes")
	}
}

// 32
func TestNewPodCAProvider_ReloadExistingCA_ReturnsSamePublicPEM(t *testing.T) {
	priv := t.TempDir()
	pub := t.TempDir()
	p1, err := NewPodCAProvider(context.Background(), PodCAOptions{PrivDir: priv, PubDir: pub})
	if err != nil {
		t.Fatalf("first provider: %v", err)
	}
	p2, err := NewPodCAProvider(context.Background(), PodCAOptions{PrivDir: priv, PubDir: pub})
	if err != nil {
		t.Fatalf("reload provider: %v", err)
	}
	if !bytes.Equal(p1.PublicPEM(), p2.PublicPEM()) {
		t.Fatal("reloaded provider returned different public PEM bytes")
	}
}

// 33
func TestSigner_AfterProviderReady_ReturnsCertAndCryptoSigner(t *testing.T) {
	prov, err := NewPodCAProvider(context.Background(), PodCAOptions{PrivDir: t.TempDir(), PubDir: t.TempDir()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cert, signer := prov.Signer()
	if cert == nil {
		t.Fatal("cert is nil")
	}
	if signer == nil {
		t.Fatal("signer is nil")
	}
	eq, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		t.Fatalf("signer public key type %T has no Equal method", signer.Public())
	}
	if !eq.Equal(cert.PublicKey) {
		t.Fatal("signer public key does not match certificate public key")
	}
}

// 34
func TestGeneration_ReloadExistingCA_RemainsStableUint64(t *testing.T) {
	priv := t.TempDir()
	pub := t.TempDir()
	p1, err := NewPodCAProvider(context.Background(), PodCAOptions{PrivDir: priv, PubDir: pub})
	if err != nil {
		t.Fatalf("first provider: %v", err)
	}
	var gen uint64 = p1.Generation()
	if gen == 0 {
		t.Fatal("Generation() = 0, want non-zero")
	}
	p2, err := NewPodCAProvider(context.Background(), PodCAOptions{PrivDir: priv, PubDir: pub})
	if err != nil {
		t.Fatalf("reload provider: %v", err)
	}
	if p2.Generation() != gen {
		t.Fatalf("Generation() after reload = %d, want %d (stable)", p2.Generation(), gen)
	}
}

// 35
func TestPublicPEM_ReturnedSliceMutation_DoesNotMutateProviderState(t *testing.T) {
	prov, err := NewPodCAProvider(context.Background(), PodCAOptions{PrivDir: t.TempDir(), PubDir: t.TempDir()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	original := append([]byte(nil), prov.PublicPEM()...)
	mutable := prov.PublicPEM()
	if len(mutable) == 0 {
		t.Fatal("PublicPEM() returned empty slice")
	}
	for i := range mutable {
		mutable[i] ^= 0xFF
	}
	if !bytes.Equal(prov.PublicPEM(), original) {
		t.Fatal("mutating returned slice mutated provider state")
	}
}

// 36
func TestNewPodCAProvider_CAReadyLog_IncludesGenerationAndPublicPath(t *testing.T) {
	priv := t.TempDir()
	pub := t.TempDir()
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	prov, err := newPodCAProviderWithLogger(context.Background(), PodCAOptions{PrivDir: priv, PubDir: pub}, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, caReadyMsg) {
		t.Fatalf("log %q missing CA-ready message", out)
	}
	if !strings.Contains(out, strconv.FormatUint(prov.Generation(), 10)) {
		t.Fatalf("log %q missing generation %d", out, prov.Generation())
	}
	pubPath := filepath.Join(pub, caCertFile)
	if !strings.Contains(out, pubPath) {
		t.Fatalf("log %q missing public path %q", out, pubPath)
	}
	if strings.Contains(out, "PRIVATE KEY") {
		t.Fatalf("log %q leaks private key material", out)
	}
	if strings.Contains(out, filepath.Join(priv, privKeyFile)) {
		t.Fatalf("log %q leaks private key path", out)
	}
}
