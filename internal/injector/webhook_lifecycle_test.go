package injector

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

const (
	testServiceName      = "aksh-injector"
	testServiceNamespace = "aksh-system"
	testMutatingName     = "aksh-injector-mutating"
	testValidatingName   = "aksh-injector-validating"
)

// 154
func TestWebhookServer_GenerateSelfSignedCA_CreatesServingCertSignedByCurrentCA(t *testing.T) {
	pki, err := generateSelfSignedPKI(testServiceName, testServiceNamespace)
	if err != nil {
		t.Fatalf("generateSelfSignedPKI() error = %v", err)
	}

	if pki.caCert == nil || pki.servingCert == nil {
		t.Fatal("expected both CA and serving certificates to be created")
	}
	if !pki.caCert.IsCA {
		t.Fatal("generated CA certificate is not marked IsCA")
	}
	if err := pki.servingCert.CheckSignatureFrom(pki.caCert); err != nil {
		t.Fatalf("serving cert not signed by current CA: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(pki.caCert)
	if _, err := pki.servingCert.Verify(x509.VerifyOptions{
		Roots:     roots,
		DNSName:   testServiceName,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("serving cert failed verification against current CA: %v", err)
	}
}

// 155
func TestWebhookServer_LoadCertDirServingMaterial_UsesLoadedCAAndServingCert(t *testing.T) {
	dir := t.TempDir()
	seed, err := generateSelfSignedPKI(testServiceName, testServiceNamespace)
	if err != nil {
		t.Fatalf("seed generateSelfSignedPKI() error = %v", err)
	}
	writeFile(t, filepath.Join(dir, caCertFile), seed.caPEM)
	writeFile(t, filepath.Join(dir, servingCertFile), seed.servingPEM)
	writeFile(t, filepath.Join(dir, servingKeyFile), seed.servingKeyPEM)

	pki, err := bootstrapPKI(WebhookServerOptions{
		CertDir:          dir,
		ServiceName:      testServiceName,
		ServiceNamespace: testServiceNamespace,
	})
	if err != nil {
		t.Fatalf("bootstrapPKI() error = %v", err)
	}

	if !bytes.Equal(pki.caPEM, seed.caPEM) {
		t.Fatal("bootstrap did not use loaded CA material")
	}
	if !bytes.Equal(pki.servingPEM, seed.servingPEM) {
		t.Fatal("bootstrap did not use loaded serving certificate")
	}
}

// 156
func TestWebhookServer_GenerateSelfSignedCA_IncludesServiceDNSSANsInServingCert(t *testing.T) {
	pki, err := generateSelfSignedPKI(testServiceName, testServiceNamespace)
	if err != nil {
		t.Fatalf("generateSelfSignedPKI() error = %v", err)
	}

	want := []string{
		"aksh-injector",
		"aksh-injector.aksh-system",
		"aksh-injector.aksh-system.svc",
		"aksh-injector.aksh-system.svc.cluster.local",
	}
	if !reflect.DeepEqual(pki.servingCert.DNSNames, want) {
		t.Fatalf("serving cert DNSNames = %v, want %v", pki.servingCert.DNSNames, want)
	}
}

// 157
func TestWebhookServer_ReconcileCABundle_PatchesMutatingAndValidatingWebhookConfigurations(t *testing.T) {
	caPEM := []byte("-----BEGIN CERTIFICATE-----\ncurrent-ca\n-----END CERTIFICATE-----")
	mutating := mutatingConfig(testMutatingName, []byte("stale-mutating"), 2)
	validating := validatingConfig(testValidatingName, []byte("stale-validating"), 2)
	client := fake.NewSimpleClientset(mutating, validating)

	rc := &caBundleReconciler{
		client:         client,
		mutatingName:   testMutatingName,
		validatingName: testValidatingName,
	}
	if err := rc.reconcile(context.Background(), caPEM); err != nil {
		t.Fatalf("reconcile() error = %v", err)
	}

	gotMutating, err := client.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(context.Background(), testMutatingName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get mutating: %v", err)
	}
	for i, w := range gotMutating.Webhooks {
		if !bytes.Equal(w.ClientConfig.CABundle, caPEM) {
			t.Fatalf("mutating webhook[%d] caBundle = %q, want current CA PEM", i, w.ClientConfig.CABundle)
		}
	}
	gotValidating, err := client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(context.Background(), testValidatingName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get validating: %v", err)
	}
	for i, w := range gotValidating.Webhooks {
		if !bytes.Equal(w.ClientConfig.CABundle, caPEM) {
			t.Fatalf("validating webhook[%d] caBundle = %q, want current CA PEM", i, w.ClientConfig.CABundle)
		}
	}
}

// 158
func TestWebhookServer_ReadyzServingMaterialExpired_ReturnsServiceUnavailable(t *testing.T) {
	now := time.Now()
	pki, err := generatePKIMaterial(testServiceName, testServiceNamespace,
		now.Add(-2*time.Hour), now.Add(defaultCAValidity),
		now.Add(-2*time.Hour), now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("generatePKIMaterial() error = %v", err)
	}
	client := fake.NewSimpleClientset(
		mutatingConfig(testMutatingName, pki.CABundle(), 1),
		validatingConfig(testValidatingName, pki.CABundle(), 1),
	)
	server := newReadinessServer(t, pki, client)

	if code := getReadyz(t, server); code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz status = %d, want %d", code, http.StatusServiceUnavailable)
	}
}

// 159
func TestWebhookServer_ReadyzCABundleMismatch_ReturnsServiceUnavailable(t *testing.T) {
	pki, err := generateSelfSignedPKI(testServiceName, testServiceNamespace)
	if err != nil {
		t.Fatalf("generateSelfSignedPKI() error = %v", err)
	}
	client := fake.NewSimpleClientset(
		mutatingConfig(testMutatingName, pki.CABundle(), 1),
		validatingConfig(testValidatingName, []byte("different-ca"), 1),
	)
	server := newReadinessServer(t, pki, client)

	if code := getReadyz(t, server); code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz status = %d, want %d", code, http.StatusServiceUnavailable)
	}
}

// 160
func TestWebhookServer_ReadyzServingMaterialAndCABundlesConsistent_ReturnsOK(t *testing.T) {
	pki, err := generateSelfSignedPKI(testServiceName, testServiceNamespace)
	if err != nil {
		t.Fatalf("generateSelfSignedPKI() error = %v", err)
	}
	client := fake.NewSimpleClientset(
		mutatingConfig(testMutatingName, pki.CABundle(), 2),
		validatingConfig(testValidatingName, pki.CABundle(), 2),
	)
	server := newReadinessServer(t, pki, client)

	if code := getReadyz(t, server); code != http.StatusOK {
		t.Fatalf("/readyz status = %d, want %d", code, http.StatusOK)
	}
}

// 162
func TestWebhookServer_ReadyzBeforeCABundlePatch_ReturnsServiceUnavailable(t *testing.T) {
	pki, err := generateSelfSignedPKI(testServiceName, testServiceNamespace)
	if err != nil {
		t.Fatalf("generateSelfSignedPKI() error = %v", err)
	}
	client := fake.NewSimpleClientset(
		mutatingConfig(testMutatingName, nil, 1),
		validatingConfig(testValidatingName, nil, 1),
	)
	server := newReadinessServer(t, pki, client)

	if code := getReadyz(t, server); code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz status = %d, want %d", code, http.StatusServiceUnavailable)
	}
}

// 163
func TestWebhookServer_ShutdownWithInFlightAdmissionRequest_DrainsBeforeStopping(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server, err := NewWebhookServer(WebhookServerOptions{Addr: "127.0.0.1:0"}, &blockingInjector{started: started, release: release})
	if err != nil {
		t.Fatalf("NewWebhookServer() error = %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.serve(ctx, ln) }()

	body, err := json.Marshal(mutateReview(types.UID("in-flight"), metav1.GroupVersionKind{Version: "v1", Kind: "Pod"}, admissionv1.Create))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	inFlight := make(chan int, 1)
	go func() {
		resp, err := http.Post("http://"+addr+"/mutate", "application/json", bytes.NewReader(body))
		if err != nil {
			inFlight <- -1
			return
		}
		defer resp.Body.Close()
		inFlight <- resp.StatusCode
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight request never reached handler")
	}

	cancel()
	close(release)

	select {
	case code := <-inFlight:
		if code != http.StatusOK {
			t.Fatalf("in-flight request status = %d, want %d", code, http.StatusOK)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight request did not drain before shutdown")
	}

	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("serve returned error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop after shutdown")
	}

	if _, err := http.Post("http://"+addr+"/mutate", "application/json", bytes.NewReader(body)); err == nil {
		t.Fatal("server accepted a new request after shutdown")
	}
}

// 168
func TestWebhookServer_BootstrapOrderingWebhookConfigurationsUntrusted_FailsClosedUntilReady(t *testing.T) {
	pki, err := generateSelfSignedPKI(testServiceName, testServiceNamespace)
	if err != nil {
		t.Fatalf("generateSelfSignedPKI() error = %v", err)
	}
	client := fake.NewSimpleClientset(
		mutatingConfig(testMutatingName, nil, 1),
		validatingConfig(testValidatingName, []byte("non-matching"), 1),
	)
	server := newReadinessServer(t, pki, client)

	if server.ready(context.Background()) {
		t.Fatal("server reported ready while webhook configurations were untrusted")
	}

	if err := server.ReconcileCABundle(context.Background()); err != nil {
		t.Fatalf("ReconcileCABundle() error = %v", err)
	}

	if !server.ready(context.Background()) {
		t.Fatal("server not ready after caBundle reconciliation installed current CA")
	}
}

// Regression (Slice-4 MMR): a CertDir with only some serving-material files is
// operator misconfiguration and must fail closed, not silently self-generate.
func TestBootstrapPKI_PartialCertDir_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	seed, err := generateSelfSignedPKI(testServiceName, testServiceNamespace)
	if err != nil {
		t.Fatalf("seed generateSelfSignedPKI() error = %v", err)
	}
	writeFile(t, filepath.Join(dir, caCertFile), seed.caPEM)

	if _, err := bootstrapPKI(WebhookServerOptions{
		CertDir:          dir,
		ServiceName:      testServiceName,
		ServiceNamespace: testServiceNamespace,
	}); err == nil {
		t.Fatal("bootstrapPKI() with partial CertDir did not return an error")
	}
}

// Regression (Slice-4 MMR): loaded serving material that does not chain to the
// loaded CA must be rejected at bootstrap, not accepted for TLS serving.
func TestWebhookServer_LoadCertDirServingMaterial_ServingCertNotSignedByCA_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	caSource, err := generateSelfSignedPKI(testServiceName, testServiceNamespace)
	if err != nil {
		t.Fatalf("ca source generateSelfSignedPKI() error = %v", err)
	}
	servingSource, err := generateSelfSignedPKI(testServiceName, testServiceNamespace)
	if err != nil {
		t.Fatalf("serving source generateSelfSignedPKI() error = %v", err)
	}
	writeFile(t, filepath.Join(dir, caCertFile), caSource.caPEM)
	writeFile(t, filepath.Join(dir, servingCertFile), servingSource.servingPEM)
	writeFile(t, filepath.Join(dir, servingKeyFile), servingSource.servingKeyPEM)

	if _, err := bootstrapPKI(WebhookServerOptions{
		CertDir:          dir,
		ServiceName:      testServiceName,
		ServiceNamespace: testServiceNamespace,
	}); err == nil {
		t.Fatal("bootstrapPKI() accepted serving cert not signed by loaded CA")
	}
}

// Regression (Slice-4 MMR): reconcile must refuse an empty CA PEM so it cannot
// clear an existing trust root in the webhook configurations.
func TestReconcileCABundle_EmptyCAPEM_RefusesAndPreservesExistingBundle(t *testing.T) {
	existing := []byte("existing-ca")
	client := fake.NewSimpleClientset(
		mutatingConfig(testMutatingName, existing, 1),
		validatingConfig(testValidatingName, existing, 1),
	)
	rc := &caBundleReconciler{client: client, mutatingName: testMutatingName, validatingName: testValidatingName}

	if err := rc.reconcile(context.Background(), nil); err == nil {
		t.Fatal("reconcile() with empty CA PEM did not return an error")
	}

	got, err := client.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(context.Background(), testMutatingName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get mutating: %v", err)
	}
	if !bytes.Equal(got.Webhooks[0].ClientConfig.CABundle, existing) {
		t.Fatalf("existing caBundle was modified: got %q, want %q", got.Webhooks[0].ClientConfig.CABundle, existing)
	}
}

// Regression (Slice-4 MMR): CABundle() must return a defensive copy so callers
// cannot mutate the immutable PKI state.
func TestWebhookPKI_CABundle_ReturnsDefensiveCopy(t *testing.T) {
	pki, err := generateSelfSignedPKI(testServiceName, testServiceNamespace)
	if err != nil {
		t.Fatalf("generateSelfSignedPKI() error = %v", err)
	}
	first := pki.CABundle()
	if len(first) == 0 {
		t.Fatal("CABundle() returned empty PEM")
	}
	original := append([]byte(nil), first...)
	for i := range first {
		first[i] ^= 0xFF
	}
	if !bytes.Equal(pki.CABundle(), original) {
		t.Fatal("mutating the returned CABundle slice corrupted PKI state")
	}
}

// Regression (Slice-4 MMR iter1): a configured CertDir that does not exist is
// operator misconfiguration and must fail closed, not silently self-generate.
func TestBootstrapPKI_NonexistentCertDir_ReturnsError(t *testing.T) {
	missingDir := filepath.Join(t.TempDir(), "does-not-exist")
	if _, err := bootstrapPKI(WebhookServerOptions{
		CertDir:          missingDir,
		ServiceName:      testServiceName,
		ServiceNamespace: testServiceNamespace,
	}); err == nil {
		t.Fatal("bootstrapPKI() with nonexistent CertDir did not return an error")
	}
}

func newReadinessServer(t *testing.T, pki *WebhookPKI, client kubernetes.Interface) *WebhookServer {
	t.Helper()
	server, err := NewWebhookServer(WebhookServerOptions{
		MutatingWebhookConfiguration:   testMutatingName,
		ValidatingWebhookConfiguration: testValidatingName,
	}, testInjector{}, WithPKI(pki), WithClient(client))
	if err != nil {
		t.Fatalf("NewWebhookServer() error = %v", err)
	}
	return server
}

func getReadyz(t *testing.T, server *WebhookServer) int {
	t.Helper()
	recorder := httptest.NewRecorder()
	server.Handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	return recorder.Code
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mutatingConfig(name string, caBundle []byte, webhooks int) *admissionregistrationv1.MutatingWebhookConfiguration {
	cfg := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}
	for i := 0; i < webhooks; i++ {
		cfg.Webhooks = append(cfg.Webhooks, admissionregistrationv1.MutatingWebhook{
			Name:         "mutate.pods.aksh.dev",
			ClientConfig: admissionregistrationv1.WebhookClientConfig{CABundle: caBundle},
		})
	}
	return cfg
}

func validatingConfig(name string, caBundle []byte, webhooks int) *admissionregistrationv1.ValidatingWebhookConfiguration {
	cfg := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}
	for i := 0; i < webhooks; i++ {
		cfg.Webhooks = append(cfg.Webhooks, admissionregistrationv1.ValidatingWebhook{
			Name:         "validate.pods.aksh.dev",
			ClientConfig: admissionregistrationv1.WebhookClientConfig{CABundle: caBundle},
		})
	}
	return cfg
}

type blockingInjector struct {
	started chan struct{}
	release chan struct{}
}

func (b *blockingInjector) Patch(pod *corev1.Pod) (*corev1.Pod, error) {
	close(b.started)
	<-b.release
	return pod, nil
}

func (b *blockingInjector) Validate(*corev1.Pod) error { return nil }
