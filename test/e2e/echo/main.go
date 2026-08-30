package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
)

// Minimal HTTPS "echo" upstream used as the allowed destination in the kind
// e2e harness. It presents a leaf for allowed.test (see ../certs/gencert.go)
// and serves http/1.1 ONLY: the aksh request path is HTTP/1.1-only (it rejects
// the HTTP/2 preface), so an http/1.1-only upstream mirrors an ordinary server
// and avoids the known h2-ALPN relay gap in the request path.
func main() {
	addr := os.Getenv("ECHO_LISTEN")
	if addr == "" {
		addr = ":8443"
	}
	msg := os.Getenv("ECHO_MSG")
	if msg == "" {
		msg = "ALLOWED-UPSTREAM-OK"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s host=%s path=%s method=%s\n", msg, r.Host, r.URL.Path, r.Method)
		log.Printf("echo served host=%s path=%s method=%s from=%s", r.Host, r.URL.Path, r.Method, r.RemoteAddr)
	})
	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		TLSConfig:    &tls.Config{NextProtos: []string{"http/1.1"}},
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	log.Printf("echo listening (TLS, http/1.1 only) on %s", addr)
	log.Fatal(srv.ListenAndServeTLS("/certs/server.crt", "/certs/server.key"))
}
