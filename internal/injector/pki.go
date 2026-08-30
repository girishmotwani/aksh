package injector

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
	caCertFile      = "ca.crt"
	servingCertFile = "tls.crt"
	servingKeyFile  = "tls.key"
)

const (
	defaultCAValidity      = 10 * 365 * 24 * time.Hour
	defaultServingValidity = 365 * 24 * time.Hour
)

// WebhookPKI holds the webhook CA and serving material used for HTTPS and
// caBundle reconciliation. Instances are immutable after construction.
type WebhookPKI struct {
	caCert        *x509.Certificate
	caPEM         []byte
	servingCert   *x509.Certificate
	servingTLS    tls.Certificate
	servingPEM    []byte
	servingKeyPEM []byte
}

// CABundle returns a defensive copy of the current CA certificate in PEM form.
// A copy is returned so callers cannot mutate the immutable PKI state that
// backs TLS serving and caBundle reconciliation.
func (p *WebhookPKI) CABundle() []byte {
	return cloneBytes(p.caPEM)
}

// ServingCertificate returns the TLS serving certificate.
func (p *WebhookPKI) ServingCertificate() tls.Certificate {
	return p.servingTLS
}

// NotAfter returns the serving certificate expiry.
func (p *WebhookPKI) NotAfter() time.Time {
	return p.servingCert.NotAfter
}

// BootstrapPKI loads serving material from CertDir when present, otherwise it
// generates a self-signed CA and serving certificate for the service identity.
func BootstrapPKI(opts WebhookServerOptions) (*WebhookPKI, error) {
	return bootstrapPKI(opts)
}

// BootstrapPKIWithLogger behaves like BootstrapPKI but, when it generates a
// fresh self-signed CA (rather than loading operator-supplied material), emits
// the "generated webhook CA" observability log carrying the CA notAfter.
func BootstrapPKIWithLogger(opts WebhookServerOptions, logger *slog.Logger) (*WebhookPKI, error) {
	return bootstrapPKILogged(opts, logger)
}

func bootstrapPKI(opts WebhookServerOptions) (*WebhookPKI, error) {
	return bootstrapPKILogged(opts, nil)
}

func bootstrapPKILogged(opts WebhookServerOptions, logger *slog.Logger) (*WebhookPKI, error) {
	if opts.CertDir != "" {
		populated, err := certDirPopulated(opts.CertDir)
		if err != nil {
			return nil, err
		}
		if populated {
			return loadPKI(opts.CertDir)
		}
	}
	return generateSelfSignedPKIWithLogger(opts.ServiceName, opts.ServiceNamespace, logger)
}

// certDirPopulated reports whether CertDir holds a complete set of serving
// material. It fails closed on a PARTIAL set and on any filesystem error other
// than a plain missing file: an operator that configured CertDir intending to
// supply certificates must not silently fall through to a freshly generated
// self-signed CA (which would rotate trust unexpectedly) because of a missing
// directory, permission error, or broken mount. Only a directory that exists
// with none of the three files present is a legitimate request to self-generate.
func certDirPopulated(dir string) (bool, error) {
	if _, err := os.Stat(dir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, fmt.Errorf("cert dir %q does not exist", dir)
		}
		return false, fmt.Errorf("stat cert dir %q: %w", dir, err)
	}
	var found, missing []string
	for _, name := range []string{caCertFile, servingCertFile, servingKeyFile} {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				missing = append(missing, name)
				continue
			}
			return false, fmt.Errorf("stat %q: %w", path, err)
		}
		found = append(found, name)
	}
	if len(missing) == 0 {
		return true, nil
	}
	if len(found) == 0 {
		return false, nil
	}
	return false, fmt.Errorf("cert dir %q has partial serving material (found %v, missing %v)", dir, found, missing)
}

func loadPKI(dir string) (*WebhookPKI, error) {
	caPEM, err := os.ReadFile(filepath.Join(dir, caCertFile))
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}
	servingPEM, err := os.ReadFile(filepath.Join(dir, servingCertFile))
	if err != nil {
		return nil, fmt.Errorf("read serving certificate: %w", err)
	}
	servingKeyPEM, err := os.ReadFile(filepath.Join(dir, servingKeyFile))
	if err != nil {
		return nil, fmt.Errorf("read serving key: %w", err)
	}

	caCert, err := parseCertificatePEM(caPEM)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	servingCert, err := parseCertificatePEM(servingPEM)
	if err != nil {
		return nil, fmt.Errorf("parse serving certificate: %w", err)
	}
	servingTLS, err := tls.X509KeyPair(servingPEM, servingKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("load serving keypair: %w", err)
	}
	servingTLS.Leaf = servingCert

	// Fail closed on misconfigured or stale mounts: the serving certificate must
	// chain to the loaded CA and must currently be valid. Verify checks both the
	// signature chain and time validity (NotBefore/NotAfter), so an expired or
	// mismatched pair is rejected at bootstrap rather than at request time.
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := servingCert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return nil, fmt.Errorf("loaded serving certificate not valid against loaded CA: %w", err)
	}

	return &WebhookPKI{
		caCert:        caCert,
		caPEM:         caPEM,
		servingCert:   servingCert,
		servingTLS:    servingTLS,
		servingPEM:    servingPEM,
		servingKeyPEM: servingKeyPEM,
	}, nil
}

func generateSelfSignedPKI(serviceName, serviceNamespace string) (*WebhookPKI, error) {
	now := time.Now()
	return generatePKIMaterial(serviceName, serviceNamespace,
		now.Add(-time.Hour), now.Add(defaultCAValidity),
		now.Add(-time.Hour), now.Add(defaultServingValidity))
}

// generateSelfSignedPKIWithLogger generates a self-signed CA and serving
// certificate and, when logger is non-nil, emits the "generated webhook CA"
// observability log carrying the CA notAfter. No private key material is logged.
func generateSelfSignedPKIWithLogger(serviceName, serviceNamespace string, logger *slog.Logger) (*WebhookPKI, error) {
	pki, err := generateSelfSignedPKI(serviceName, serviceNamespace)
	if err != nil {
		return nil, err
	}
	if logger != nil {
		logger.Info("aksh-injector: generated webhook CA",
			"notAfter", pki.caCert.NotAfter.UTC().Format(time.RFC3339),
		)
	}
	return pki, nil
}

func generatePKIMaterial(serviceName, serviceNamespace string, caNotBefore, caNotAfter, servingNotBefore, servingNotAfter time.Time) (*WebhookPKI, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	caSerial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "aksh-injector-ca"},
		NotBefore:             caNotBefore,
		NotAfter:              caNotAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	servingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate serving key: %w", err)
	}
	servingSerial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	servingTemplate := &x509.Certificate{
		SerialNumber: servingSerial,
		Subject:      pkix.Name{CommonName: serviceName},
		NotBefore:    servingNotBefore,
		NotAfter:     servingNotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     serviceDNSNames(serviceName, serviceNamespace),
	}
	servingDER, err := x509.CreateCertificate(rand.Reader, servingTemplate, caCert, &servingKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("create serving certificate: %w", err)
	}
	servingCert, err := x509.ParseCertificate(servingDER)
	if err != nil {
		return nil, fmt.Errorf("parse serving certificate: %w", err)
	}
	servingPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: servingDER})

	servingKeyDER, err := x509.MarshalPKCS8PrivateKey(servingKey)
	if err != nil {
		return nil, fmt.Errorf("marshal serving key: %w", err)
	}
	servingKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: servingKeyDER})

	servingTLS, err := tls.X509KeyPair(servingPEM, servingKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("assemble serving keypair: %w", err)
	}
	servingTLS.Leaf = servingCert

	return &WebhookPKI{
		caCert:        caCert,
		caPEM:         caPEM,
		servingCert:   servingCert,
		servingTLS:    servingTLS,
		servingPEM:    servingPEM,
		servingKeyPEM: servingKeyPEM,
	}, nil
}

// serviceDNSNames returns the exact SAN list required for the serving cert.
func serviceDNSNames(serviceName, serviceNamespace string) []string {
	return []string{
		serviceName,
		serviceName + "." + serviceNamespace,
		serviceName + "." + serviceNamespace + ".svc",
		serviceName + "." + serviceNamespace + ".svc.cluster.local",
	}
}

func parseCertificatePEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no CERTIFICATE PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}
	return serial, nil
}
