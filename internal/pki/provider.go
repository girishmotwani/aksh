package pki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	privKeyFile = "ca-key.pem"
	// caCertFile is the CA certificate filename used in both PrivDir (the
	// authoritative private-side cert) and PubDir (the public read-only
	// copy). The two live in distinct directories; the private signing key
	// (privKeyFile) is never written to PubDir.
	caCertFile = "ca-cert.pem"

	caReadyMsg = "aksh-proxy: CA ready"

	privKeyPerm  = 0o600
	certPerm     = 0o644
	caDirPerm    = 0o700
	pubDirPerm   = 0o755
	caValidYears = 10
)

// PodCAOptions configures the per-pod CA provider directories.
type PodCAOptions struct {
	// PrivDir holds the private CA key and certificate, mounted only into
	// aksh-proxy.
	PrivDir string
	// PubDir holds the public CA certificate copy shared read-only.
	PubDir string
}

// PodCAProvider is the concrete per-pod CA implementation. It generates or
// reloads an ECDSA P-256 CA and exposes it through the CAProvider interface.
type PodCAProvider struct {
	cert       *x509.Certificate
	signer     crypto.Signer
	generation uint64
	publicPEM  []byte
}

var _ CAProvider = (*PodCAProvider)(nil)

// NewPodCAProvider loads an existing per-pod CA from opts.PrivDir or, when
// absent, generates a fresh ECDSA P-256 CA, atomically persists the private
// key and certificate, and writes the public CA copy to opts.PubDir. An
// existing key/cert or public-copy mismatch is a fatal startup error and is
// never silently regenerated.
func NewPodCAProvider(ctx context.Context, opts PodCAOptions) (*PodCAProvider, error) {
	return newPodCAProviderWithLogger(ctx, opts, slog.Default())
}

// newPodCAProviderWithLogger is NewPodCAProvider with an injectable logger so
// the CA-ready summary can be captured in tests without leaking secrets.
func newPodCAProviderWithLogger(_ context.Context, opts PodCAOptions, log *slog.Logger) (*PodCAProvider, error) {
	if log == nil {
		log = slog.Default()
	}
	if opts.PrivDir == "" {
		return nil, errors.New("pki: PodCAOptions.PrivDir must not be empty")
	}
	if opts.PubDir == "" {
		return nil, errors.New("pki: PodCAOptions.PubDir must not be empty")
	}

	privKeyPath := filepath.Join(opts.PrivDir, privKeyFile)
	privCertPath := filepath.Join(opts.PrivDir, caCertFile)
	pubCertPath := filepath.Join(opts.PubDir, caCertFile)

	keyExists, err := fileState(privKeyPath)
	if err != nil {
		return nil, err
	}
	certExists, err := fileState(privCertPath)
	if err != nil {
		return nil, err
	}

	var cert *x509.Certificate
	var signer crypto.Signer

	switch {
	case keyExists && certExists:
		cert, signer, err = loadCA(privKeyPath, privCertPath)
		if err != nil {
			return nil, err
		}
		if err := verifyPublicCopy(pubCertPath, publicPEM(cert)); err != nil {
			return nil, err
		}
	case !keyExists && !certExists:
		cert, signer, err = generateAndPersistCA(opts.PrivDir, opts.PubDir, privKeyPath, privCertPath, pubCertPath)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("pki: inconsistent CA state in %s: exactly one of key/cert present", opts.PrivDir)
	}

	prov := &PodCAProvider{
		cert:       cert,
		signer:     signer,
		generation: generationFor(cert),
		publicPEM:  publicPEM(cert),
	}

	log.Info(caReadyMsg, "generation", prov.generation, "public_path", pubCertPath)
	return prov, nil
}

// Signer returns the CA certificate and signer. The pair is non-nil for the
// pod lifetime once the provider is constructed.
func (p *PodCAProvider) Signer() (*x509.Certificate, crypto.Signer) {
	return p.cert, p.signer
}

// Generation returns a stable non-zero identifier for the CA, unchanged
// across reloads of the same persisted files.
func (p *PodCAProvider) Generation() uint64 {
	return p.generation
}

// PublicPEM returns a copy of the public CA certificate PEM. Mutating the
// returned slice does not affect provider state.
func (p *PodCAProvider) PublicPEM() []byte {
	return append([]byte(nil), p.publicPEM...)
}

func loadCA(privKeyPath, privCertPath string) (*x509.Certificate, crypto.Signer, error) {
	keyBytes, err := os.ReadFile(privKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: read CA key: %w", err)
	}
	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("pki: CA key %s is not valid PEM", privKeyPath)
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: parse CA key: %w", err)
	}
	signer, ok := parsedKey.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("pki: CA key type %T is not a crypto.Signer", parsedKey)
	}

	certBytes, err := os.ReadFile(privCertPath)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: read CA cert: %w", err)
	}
	certBlock, _ := pem.Decode(certBytes)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("pki: CA cert %s is not valid PEM", privCertPath)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: parse CA cert: %w", err)
	}

	if !publicKeysMatch(signer.Public(), cert.PublicKey) {
		return nil, nil, fmt.Errorf("pki: CA key/cert mismatch in %s: fatal, not regenerating", filepath.Dir(privKeyPath))
	}
	if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, nil, fmt.Errorf("pki: loaded CA cert %s is not a signing CA (IsCA=%v, certSign=%v): fatal, not regenerating", privCertPath, cert.IsCA, cert.KeyUsage&x509.KeyUsageCertSign != 0)
	}
	if now := time.Now(); now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, nil, fmt.Errorf("pki: loaded CA cert %s outside validity window [%s, %s]: fatal, not regenerating", privCertPath, cert.NotBefore.UTC(), cert.NotAfter.UTC())
	}
	return cert, signer, nil
}

func verifyPublicCopy(pubCertPath string, want []byte) error {
	got, err := os.ReadFile(pubCertPath)
	if err != nil {
		return fmt.Errorf("pki: read public CA copy %s: %w", pubCertPath, err)
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("pki: public CA copy %s does not match private CA cert: fatal, not repairing", pubCertPath)
	}
	return nil
}

func generateAndPersistCA(privDir, pubDir, privKeyPath, privCertPath, pubCertPath string) (*x509.Certificate, crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: generate CA key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("pki: generate serial: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "aksh-pod-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(caValidYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: create CA cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: parse generated CA cert: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: marshal CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	if err := os.MkdirAll(privDir, caDirPerm); err != nil {
		return nil, nil, fmt.Errorf("pki: create PrivDir: %w", err)
	}
	if err := atomicWriteFile(privKeyPath, keyPEM, privKeyPerm); err != nil {
		return nil, nil, fmt.Errorf("pki: persist CA key: %w", err)
	}
	if err := atomicWriteFile(privCertPath, certPEM, certPerm); err != nil {
		return nil, nil, fmt.Errorf("pki: persist CA cert: %w", err)
	}
	if err := os.MkdirAll(pubDir, pubDirPerm); err != nil {
		return nil, nil, fmt.Errorf("pki: create PubDir: %w", err)
	}
	if err := atomicWriteFile(pubCertPath, certPEM, certPerm); err != nil {
		return nil, nil, fmt.Errorf("pki: write public CA copy: %w", err)
	}
	return cert, key, nil
}

func publicPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func generationFor(cert *x509.Certificate) uint64 {
	sum := sha256.Sum256(cert.Raw)
	gen := binary.BigEndian.Uint64(sum[:8])
	if gen == 0 {
		gen = 1
	}
	return gen
}

func publicKeysMatch(a, b crypto.PublicKey) bool {
	eq, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return false
	}
	return eq.Equal(b)
}

// fileState reports whether path is an existing regular file. A missing file
// returns (false, nil). Any other stat error (e.g. permission denied) or a
// directory at path returns a non-nil error so the reconcile fails closed
// rather than mistaking an unreadable CA for an absent one and regenerating.
func fileState(path string) (bool, error) {
	info, err := os.Stat(path)
	if err == nil {
		if info.IsDir() {
			return false, fmt.Errorf("pki: %s is a directory, expected a regular file: fatal", path)
		}
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("pki: stat CA file %s: %w: fatal, not regenerating", path, err)
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".ca-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
