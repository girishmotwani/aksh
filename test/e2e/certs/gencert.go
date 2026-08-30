// Command gencert produces the throwaway TLS material for the kind e2e harness:
// a CA (aksh-e2e-upstream-ca) and a leaf signed by it. The proxy trusts the CA
// via SSL_CERT_FILE (see manifests/50-aksh-pod.yaml wrapper) so its upstream
// TLS handshake to the echo server verifies without InsecureSkipVerify. Writes
// ca.crt, server.crt, server.key into OUT_DIR (default: the current directory).
//
// LEAF_NAMES overrides the leaf's subject and SANs (comma-separated, first name
// becomes the CommonName); it defaults to allowed.test. The kagent harness uses
// it to issue a leaf for api.openai.com, so that the agent under test dials the
// real provider hostname and aksh sees the SNI it would see in production.
//
// Run (via the run.ps1 driver, or manually):
//
//	docker run --rm -v "${PWD}/test/e2e/certs:/out" -w /out -e OUT_DIR=/out \
//	  golang:1.26-bookworm sh -c "go run gencert.go"
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"time"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func writePEM(path, typ string, der []byte) {
	f, err := os.Create(path)
	must(err)
	defer f.Close()
	must(pem.Encode(f, &pem.Block{Type: typ, Bytes: der}))
}

func main() {
	out := os.Getenv("OUT_DIR")
	if out == "" {
		out = "."
	}

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "aksh-e2e-upstream-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * 365 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	must(err)
	writePEM(out+"/ca.crt", "CERTIFICATE", caDER)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	caCert, err := x509.ParseCertificate(caDER)
	must(err)
	names := []string{"allowed.test"}
	if raw := os.Getenv("LEAF_NAMES"); raw != "" {
		names = names[:0]
		for _, n := range strings.Split(raw, ",") {
			if n = strings.TrimSpace(n); n != "" {
				names = append(names, n)
			}
		}
		if len(names) == 0 {
			panic("LEAF_NAMES set but contained no usable names")
		}
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * 365 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	must(err)
	writePEM(out+"/server.crt", "CERTIFICATE", leafDER)
	writePEM(out+"/server.key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(leafKey))
}
