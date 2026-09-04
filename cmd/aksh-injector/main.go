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
	"strconv"
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

	// Runtime profile: optional, environment-specific settings stamped into the
	// injected aksh sidecar. Unset flags reproduce the legacy placeholder
	// profile. Each flag defaults from an AKSH_INJECTOR_* env var so the Helm
	// chart can wire them through the container environment.
	entraTenantID := flag.String("entra-tenant-id", os.Getenv("AKSH_INJECTOR_ENTRA_TENANT_ID"), "Entra tenant ID stamped into injected pods")
	entraClientID := flag.String("entra-client-id", os.Getenv("AKSH_INJECTOR_ENTRA_CLIENT_ID"), "Entra client ID stamped into injected pods")
	entraAuthority := flag.String("entra-authority", os.Getenv("AKSH_INJECTOR_ENTRA_AUTHORITY"), "Entra authority URL stamped into injected pods")
	hostCgroupMount := flag.String("host-cgroup-mount", os.Getenv("AKSH_INJECTOR_HOST_CGROUP_MOUNT"), "AKSH_CAPTURE_HOST_CGROUP_MOUNT value stamped into injected pods")
	localCgroupMount := flag.String("local-cgroup-mount", os.Getenv("AKSH_INJECTOR_LOCAL_CGROUP_MOUNT"), "AKSH_CAPTURE_LOCAL_CGROUP_MOUNT value stamped into injected pods")
	captureDNSServer := flag.String("capture-dns-server", os.Getenv("AKSH_INJECTOR_CAPTURE_DNS_SERVER"), "AKSH_CAPTURE_DNS_SERVER host:port stamped into injected pods")
	captureBypassCIDRs := flag.String("capture-bypass-cidrs", os.Getenv("AKSH_INJECTOR_CAPTURE_BYPASS_CIDRS"), "AKSH_CAPTURE_BYPASS_CIDRS list stamped into injected pods")
	caSecretName := flag.String("ca-secret-name", os.Getenv("AKSH_INJECTOR_CA_SECRET_NAME"), "Secret backing the pod ca-priv/ca-pub volumes (empty = emptyDir)")
	caCertKey := flag.String("ca-cert-key", envOrDefault("AKSH_INJECTOR_CA_CERT_KEY", "tls.crt"), "CA Secret key for the certificate (ca-priv)")
	caPrivateKeyKey := flag.String("ca-private-key-key", envOrDefault("AKSH_INJECTOR_CA_PRIVATE_KEY_KEY", "tls.key"), "CA Secret key for the private key (ca-priv)")
	caPublicCertKey := flag.String("ca-public-cert-key", envOrDefault("AKSH_INJECTOR_CA_PUBLIC_CERT_KEY", "tls.crt"), "CA Secret key for the public certificate (ca-pub)")
	staticTokenSecretName := flag.String("static-token-secret-name", os.Getenv("AKSH_INJECTOR_STATIC_TOKEN_SECRET_NAME"), "Secret holding a static bearer credential mounted only into the aksh sidecar (empty = disabled)")
	staticTokenSecretKey := flag.String("static-token-secret-key", envOrDefault("AKSH_INJECTOR_STATIC_TOKEN_SECRET_KEY", "token"), "static-token Secret key mapped to the on-disk token file")
	podAttribution := flag.Bool("pod-attribution", envBoolOrDefault("AKSH_INJECTOR_POD_ATTRIBUTION", true), "stamp downward-API pod attribution env vars into injected pods")
	flag.Parse()

	profile := injector.RuntimeProfile{
		EntraTenantID:         *entraTenantID,
		EntraClientID:         *entraClientID,
		EntraAuthority:        *entraAuthority,
		HostCgroupMount:       *hostCgroupMount,
		LocalCgroupMount:      *localCgroupMount,
		DNSServer:             *captureDNSServer,
		BypassCIDRs:           *captureBypassCIDRs,
		CASecretName:          *caSecretName,
		CACertKey:             *caCertKey,
		CAPrivateKeyKey:       *caPrivateKeyKey,
		CAPublicCertKey:       *caPublicCertKey,
		StaticTokenSecretName: *staticTokenSecretName,
		StaticTokenSecretKey:  *staticTokenSecretKey,
		PodAttribution:        *podAttribution,
	}

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
		RuntimeProfile:   profile,
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

// envBoolOrDefault parses a boolean env var, returning fallback when unset or
// unparseable. Accepts the strconv.ParseBool forms (1/t/T/TRUE/true/... and
// their false counterparts).
func envBoolOrDefault(name string, fallback bool) bool {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func podNamespace() string {
	if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
		return ns
	}
	return "aksh-system"
}
