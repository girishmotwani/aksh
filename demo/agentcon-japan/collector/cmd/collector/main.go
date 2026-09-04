// Command collector is the AgentCon Japan demo telemetry endpoint. It plays the
// role of an external "ops-insights" telemetry service that a Kagent agent is
// coaxed into exfiltrating cluster diagnostics to. Aksh transparently captures
// that egress; this collector is what the traffic would have reached, and its
// observer UI makes the captured payloads visible on stage.
//
// Two listeners, on purpose:
//   - HTTPS ingest (TLS, HTTP/1.1 only): write-only diagnostic intake.
//   - plain HTTP observer: dashboard + harness endpoints (read/count/reset).
//
// Splitting them means the reset/enumerate surface is never reachable over the
// ingest port an agent can dial.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/girishmotwani/aksh/demo/agentcon-japan/collector/internal/collector"
)

func main() {
	var (
		ingestAddr   = flag.String("ingest-addr", ":8443", "HTTPS ingest listen address")
		uiAddr       = flag.String("ui-addr", ":8080", "plain HTTP observer UI / harness listen address")
		tlsCert      = flag.String("tls-cert", "/etc/collector/tls/tls.crt", "path to the ingest TLS certificate (PEM)")
		tlsKey       = flag.String("tls-key", "/etc/collector/tls/tls.key", "path to the ingest TLS private key (PEM)")
		storeCap     = flag.Int("store-cap", 1000, "maximum number of events retained in memory")
		maxBodyBytes = flag.Int64("max-body-bytes", collector.MaxBodyBytes, "maximum accepted ingest body size in bytes")
	)
	flag.Parse()

	logger := log.New(os.Stdout, "collector ", log.LstdFlags|log.LUTC)

	store := collector.NewStore(*storeCap)
	ingest := collector.NewIngest(store, *maxBodyBytes, logger)
	observer := collector.NewObserver(store)

	ingestSrv := &http.Server{
		Addr:    *ingestAddr,
		Handler: ingest.Handler(),
		// HTTP/1.1 only: aksh's request path rejects the HTTP/2 preface, so an
		// h2-capable listener would fail the captured relay instead of being
		// exercised. Pinning http/1.1 keeps the demo on the supported path.
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"http/1.1"},
		},
		TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          logger,
	}

	uiSrv := &http.Server{
		Addr:              *uiAddr,
		Handler:           observer.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// No WriteTimeout: the SSE dashboard stream is intentionally long-lived
		// and clears its own deadline per response.
		IdleTimeout: 120 * time.Second,
		ErrorLog:    logger,
	}

	errCh := make(chan error, 2)

	go func() {
		logger.Printf("ingest listening (HTTPS, http/1.1 only) on %s path=%s", ingestSrv.Addr, collector.IngestPath)
		err := ingestSrv.ListenAndServeTLS(*tlsCert, *tlsKey)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	go func() {
		logger.Printf("observer UI listening (HTTP) on %s", uiSrv.Addr)
		err := uiSrv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		logger.Printf("server error: %v", err)
	case sig := <-stop:
		logger.Printf("received %s, shutting down", sig)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = ingestSrv.Shutdown(ctx)
	_ = uiSrv.Shutdown(ctx)
	logger.Printf("stopped")
}
