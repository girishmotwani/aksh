// Command genca produces a throwaway CA for the aksh pod-CA slot in the kagent
// e2e harness: ca-key.pem (PKCS#8) and ca-cert.pem, the exact filenames
// internal/pki/provider.go expects in AKSH_CA_PRIV_DIR / AKSH_CA_PUB_DIR.
//
// The proxy normally generates this CA itself on first start. Here it is
// pre-generated and mounted read-only into both containers, because the agent
// must trust the CA that aksh mints its api.openai.com leaf with, and the
// agent's trust anchor is a plain file path in its config (tls_ca_cert_path).
// Letting the proxy generate at run time would make that file appear only after
// the agent container had already started, i.e. a startup race. Pre-seeding
// removes the race; provider.go loads existing material when both files are
// present and only generates when both are absent, so this exercises a
// supported production path rather than a test-only one.
//
// Run (via the run.ps1 driver, or manually):
//
//	docker run --rm -v "${PWD}/test/e2e/kagent/certs:/out" -w /out -e OUT_DIR=/out \
//	  golang:1.26-bookworm sh -c "go run genca.go"
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
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

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "aksh-kagent-e2e-pod-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * 365 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	must(err)
	writePEM(out+"/ca-cert.pem", "CERTIFICATE", der)

	// PKCS#8: loadCA parses the key with x509.ParsePKCS8PrivateKey only.
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	must(err)
	writePEM(out+"/ca-key.pem", "PRIVATE KEY", pkcs8)
}
