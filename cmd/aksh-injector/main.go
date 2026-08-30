// Command aksh-injector serves the aksh admission webhook.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/injector"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// newInClusterClient builds an in-cluster Kubernetes client. It is a package
// variable so tests can substitute a fake client without a real cluster.
var newInClusterClient = func() (kubernetes.Interface, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(config)
}

func main() {
	addr := flag.String("addr", envOrDefault("AKSH_INJECTOR_LISTEN_ADDR", ":9443"), "webhook listen address")
	certDir := flag.String("cert-dir", os.Getenv("AKSH_INJECTOR_CERT_DIR"), "serving certificate directory")
	serviceName := flag.String("service-name", envOrDefault("AKSH_INJECTOR_SERVICE_NAME", "aksh-injector"), "service name for serving cert SANs")
	serviceNamespace := flag.String("service-namespace", envOrDefault("AKSH_INJECTOR_NAMESPACE", podNamespace()), "service namespace for serving cert SANs")
	mutatingConfig := flag.String("mutating-webhook-configuration", envOrDefault("AKSH_INJECTOR_MUTATING_CONFIG", "aksh-injector-mutating"), "MutatingWebhookConfiguration to patch")
	validatingConfig := flag.String("validating-webhook-configuration", envOrDefault("AKSH_INJECTOR_VALIDATING_CONFIG", "aksh-injector-validating"), "ValidatingWebhookConfiguration to patch")
	patchInterval := flag.Duration("cabundle-patch-interval", 5*time.Minute, "caBundle reconciliation interval")
	proxyImage := flag.String("proxy-image", envOrDefault("AKSH_PROXY_IMAGE", "aksh-proxy:latest"), "aksh proxy image")
	metricsAddr := flag.String("metrics-addr", envOrDefault("AKSH_INJECTOR_METRICS_ADDR", ":9464"), "Prometheus metrics listen address")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// One registry, one recorder: the counters written by the admission handlers
	// are exactly the counters scraped at /metrics.
	registry := prometheus.NewRegistry()
	recorder, err := audit.NewPromMetricsRecorder(registry)
	if err != nil {
		log.Fatal(err)
	}

	inj, err := injector.NewSidecarInjector(injector.InjectorOptions{
		ProxyImage:       *proxyImage,
		ReservedUID:      1774,
		ReservedGID:      1774,
		OptInLabelKey:    "aksh.dev/inject",
		OptInLabelValue:  "enabled",
		InjectionVersion: "v1",
	})
	if err != nil {
		log.Fatal(err)
	}

	opts := injector.WebhookServerOptions{
		Addr:                           *addr,
		CertDir:                        *certDir,
		ServiceName:                    *serviceName,
		ServiceNamespace:               *serviceNamespace,
		MutatingWebhookConfiguration:   *mutatingConfig,
		ValidatingWebhookConfiguration: *validatingConfig,
		CABundlePatchInterval:          *patchInterval,
	}

	// Bootstrap ordering: initialize PKI, then start caBundle reconciliation,
	// and only report ready after the first successful patch.
	pki, err := injector.BootstrapPKIWithLogger(opts, logger)
	if err != nil {
		log.Fatal(err)
	}
	client, err := newInClusterClient()
	if err != nil {
		log.Fatal(err)
	}

	server, err := injector.NewWebhookServer(opts, inj,
		injector.WithPKI(pki),
		injector.WithClient(client),
		injector.WithLogger(logger),
		injector.WithMetrics(recorder),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Expose Prometheus metrics on a separate plain-HTTP listener.
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	metricsServer := &http.Server{
		Addr:              *metricsAddr,
		Handler:           metricsMux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		if err := metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("aksh-injector: metrics server failed", "error", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := metricsServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("aksh-injector: metrics server shutdown failed", "error", err)
		}
	}()

	// Bootstrap ordering is fail-closed: the initial caBundle patch MUST succeed
	// before serving. If it fails, exit so the pod restarts rather than serving
	// TLS with a stale/absent caBundle in the webhook configurations.
	if err := server.ReconcileCABundle(ctx); err != nil {
		stop()
		log.Fatalf("aksh-injector: initial caBundle patch failed: %v", err)
	}
	go server.RunCABundleReconciliation(ctx)

	if err := server.Serve(ctx); err != nil && !errors.Is(err, context.Canceled) {
		stop()
		log.Fatal(err)
	}
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func podNamespace() string {
	if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
		return ns
	}
	return "aksh-system"
}
