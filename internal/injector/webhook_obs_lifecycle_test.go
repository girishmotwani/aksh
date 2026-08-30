package injector

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/client-go/kubernetes/fake"
)

// 172
func TestWebhookServer_Start_LogsServingWebhookWithAddr(t *testing.T) {
	logger, sb := newCaptureLogger()
	server, err := NewWebhookServer(WebhookServerOptions{}, testInjector{}, WithLogger(logger))
	if err != nil {
		t.Fatalf("NewWebhookServer() error = %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { _ = server.serve(ctx, ln); close(done) }()

	waitForLog(t, sb, "aksh-injector: serving webhook")
	record, _ := findLogRecord(t, sb, "aksh-injector: serving webhook")
	if _, present := record["addr"]; !present {
		t.Fatalf("serving log missing addr field: %v", record)
	}
	cancel()
	<-done
}

// 173
func TestWebhookServer_GenerateSelfSignedCA_LogsGeneratedWebhookCAWithNotAfter(t *testing.T) {
	logger, sb := newCaptureLogger()
	pki, err := generateSelfSignedPKIWithLogger(testServiceName, testServiceNamespace, logger)
	if err != nil {
		t.Fatalf("generateSelfSignedPKIWithLogger() error = %v", err)
	}
	if pki == nil {
		t.Fatal("expected PKI material")
	}
	record, ok := findLogRecord(t, sb, "aksh-injector: generated webhook CA")
	if !ok {
		t.Fatalf("generated-CA log not found; records=%s", sb.String())
	}
	if _, present := record["notAfter"]; !present {
		t.Fatalf("generated-CA log missing notAfter field: %v", record)
	}
}

// 174
func TestWebhookServer_PatchCABundle_LogsConfigurationAndResourceVersion(t *testing.T) {
	logger, sb := newCaptureLogger()
	rec, _ := newTestMetrics(t)

	mutating := mutatingConfig(testMutatingName, []byte("stale-mutating"), 1)
	mutating.ResourceVersion = "100"
	validating := validatingConfig(testValidatingName, []byte("stale-validating"), 1)
	validating.ResourceVersion = "200"
	client := fake.NewSimpleClientset(mutating, validating)

	rc := &caBundleReconciler{
		client:         client,
		mutatingName:   testMutatingName,
		validatingName: testValidatingName,
		logger:         logger,
		metrics:        rec,
	}
	if err := rc.reconcile(context.Background(), []byte("current-ca")); err != nil {
		t.Fatalf("reconcile() error = %v", err)
	}

	records := logRecords(t, sb)
	var mutatingLogged, validatingLogged bool
	for _, r := range records {
		if r["msg"] != "aksh-injector: patched webhook caBundle" {
			continue
		}
		if _, ok := r["resourceVersion"]; !ok {
			t.Fatalf("patch log missing resourceVersion: %v", r)
		}
		switch r["configuration"] {
		case "mutating":
			mutatingLogged = true
		case "validating":
			validatingLogged = true
		}
	}
	if !mutatingLogged || !validatingLogged {
		t.Fatalf("expected patched log for both configurations; records=%s", sb.String())
	}
}

// 175
func TestWebhookServer_PatchCABundle_IncrementsPatchMetricWithConfigurationAndResult(t *testing.T) {
	rec, reg := newTestMetrics(t)

	// Mutating exists (stale) -> success. Validating is absent -> Get fails ->
	// error result for the validating configuration.
	mutating := mutatingConfig(testMutatingName, []byte("stale-mutating"), 1)
	client := fake.NewSimpleClientset(mutating)

	rc := &caBundleReconciler{
		client:         client,
		mutatingName:   testMutatingName,
		validatingName: testValidatingName,
		metrics:        rec,
	}
	if err := rc.reconcile(context.Background(), []byte("current-ca")); err == nil {
		t.Fatal("reconcile() error = nil, want failure on absent validating configuration")
	}

	fam := metricFamily(t, reg, "aksh_webhook_cabundle_patch_total")
	if got := counterValueWith(fam, map[string]string{"configuration": "mutating", "result": "success"}); got != 1 {
		t.Fatalf("cabundle_patch_total{mutating,success} = %v, want 1", got)
	}
	if got := counterValueWith(fam, map[string]string{"configuration": "validating", "result": "error"}); got != 1 {
		t.Fatalf("cabundle_patch_total{validating,error} = %v, want 1", got)
	}
}

// 178
func TestWebhookServer_TLSHandshakeError_LogsBoundedTLSError(t *testing.T) {
	_, sb, ln, cancel, done := startTLSServer(t)
	defer func() { cancel(); <-done }()

	triggerTLSHandshakeFailure(t, ln.Addr().String())

	waitForLog(t, sb, "aksh-injector: webhook TLS error")
	record, _ := findLogRecord(t, sb, "aksh-injector: webhook TLS error")
	errVal, _ := record["error"].(string)
	if errVal == "" {
		t.Fatalf("TLS error log missing bounded error field: %v", record)
	}
	if len(errVal) > maxTLSErrorLen {
		t.Fatalf("TLS error field not bounded: len=%d", len(errVal))
	}
	if contains(sb.String(), "PRIVATE KEY") || contains(sb.String(), "BEGIN CERTIFICATE") {
		t.Fatalf("TLS error log leaked key material: %s", sb.String())
	}
}

// 179
func TestWebhookServer_TLSError_IncrementsWebhookTLSErrorsMetric(t *testing.T) {
	reg, sb, ln, cancel, done := startTLSServerWithMetrics(t)
	defer func() { cancel(); <-done }()

	triggerTLSHandshakeFailure(t, ln.Addr().String())
	waitForLog(t, sb, "aksh-injector: webhook TLS error")

	deadline := time.After(2 * time.Second)
	for {
		fam := metricFamily(t, reg, "aksh_webhook_tls_errors_total")
		if counterValueWith(fam, map[string]string{}) >= 1 {
			return
		}
		select {
		case <-deadline:
			t.Fatal("aksh_webhook_tls_errors_total did not increment")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func startTLSServer(t *testing.T) (*WebhookServer, *syncBuffer, net.Listener, context.CancelFunc, chan struct{}) {
	t.Helper()
	rec, _ := newTestMetrics(t)
	logger, sb := newCaptureLogger()
	pki, err := generateSelfSignedPKI(testServiceName, testServiceNamespace)
	if err != nil {
		t.Fatalf("generateSelfSignedPKI() error = %v", err)
	}
	server, err := NewWebhookServer(WebhookServerOptions{}, testInjector{}, WithPKI(pki), WithLogger(logger), WithMetrics(rec))
	if err != nil {
		t.Fatalf("NewWebhookServer() error = %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = server.serve(ctx, ln); close(done) }()
	return server, sb, ln, cancel, done
}

func startTLSServerWithMetrics(t *testing.T) (*prometheus.Registry, *syncBuffer, net.Listener, context.CancelFunc, chan struct{}) {
	t.Helper()
	rec, reg := newTestMetrics(t)
	logger, sb := newCaptureLogger()
	pki, err := generateSelfSignedPKI(testServiceName, testServiceNamespace)
	if err != nil {
		t.Fatalf("generateSelfSignedPKI() error = %v", err)
	}
	server, err := NewWebhookServer(WebhookServerOptions{}, testInjector{}, WithPKI(pki), WithLogger(logger), WithMetrics(rec))
	if err != nil {
		t.Fatalf("NewWebhookServer() error = %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = server.serve(ctx, ln); close(done) }()
	return reg, sb, ln, cancel, done
}

// triggerTLSHandshakeFailure dials the TLS listener with plain non-TLS bytes so
// the server-side handshake fails and routes through the bounded TLS-error seam.
func triggerTLSHandshakeFailure(t *testing.T, addr string) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("this is not a TLS ClientHello\n"))
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 16)
	_, _ = conn.Read(buf)
}

func waitForLog(t *testing.T, sb *syncBuffer, msg string) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		if _, ok := findLogRecord(t, sb, msg); ok {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("log %q not observed; records=%s", msg, sb.String())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func contains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}
