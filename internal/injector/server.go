package injector

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
	jsonpatch "gomodules.xyz/jsonpatch/v2"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

const maxAdmissionBodyBytes int64 = 3 << 20

const (
	shutdownTimeout              = 5 * time.Second
	defaultCABundlePatchInterval = 5 * time.Minute
)

var (
	marshalJSON = json.Marshal
	createPatch = jsonpatch.CreatePatch
)

// WebhookServer serves the injector admission and health endpoints.
type WebhookServer struct {
	Handler http.Handler

	injector   Injector
	server     *http.Server
	opts       WebhookServerOptions
	pki        *WebhookPKI
	reconciler *caBundleReconciler
	logger     *slog.Logger
	metrics    audit.MetricsRecorder
}

// WebhookServerOption customizes a WebhookServer with serving material and a
// Kubernetes client seam so tests never require a real cluster.
type WebhookServerOption func(*WebhookServer)

// WithLogger installs the structured logger used for bounded observability. A
// nil logger is ignored so the discard default is preserved.
func WithLogger(logger *slog.Logger) WebhookServerOption {
	return func(s *WebhookServer) {
		if logger != nil {
			s.logger = logger
		}
	}
}

// WithMetrics installs the metrics recorder used for admission, caBundle, and
// TLS observability. A nil recorder is ignored so the no-op default is preserved.
func WithMetrics(metrics audit.MetricsRecorder) WebhookServerOption {
	return func(s *WebhookServer) {
		if metrics != nil {
			s.metrics = metrics
		}
	}
}

// WithPKI installs the serving material used for TLS and caBundle readiness.
func WithPKI(pki *WebhookPKI) WebhookServerOption {
	return func(s *WebhookServer) {
		s.pki = pki
	}
}

// WithClient installs the Kubernetes client used to reconcile and observe the
// webhook configurations' caBundle state.
func WithClient(client kubernetes.Interface) WebhookServerOption {
	return func(s *WebhookServer) {
		if client == nil {
			log.Print("aksh-injector: WithClient called with nil client; caBundle reconciliation disabled")
			return
		}
		s.reconciler = &caBundleReconciler{
			client:         client,
			mutatingName:   s.opts.MutatingWebhookConfiguration,
			validatingName: s.opts.ValidatingWebhookConfiguration,
		}
	}
}

// NewWebhookServer constructs an HTTPS webhook server. When serving material is
// supplied via WithPKI the listener serves TLS; otherwise it serves plain HTTP.
func NewWebhookServer(opts WebhookServerOptions, inj Injector, mods ...WebhookServerOption) (*WebhookServer, error) {
	mux := http.NewServeMux()
	webhook := &WebhookServer{
		Handler:  mux,
		injector: inj,
		opts:     opts,
		logger:   discardLogger(),
		metrics:  audit.NopMetricsRecorder{},
	}
	mux.HandleFunc("/mutate", webhook.HandleMutate)
	mux.HandleFunc("/validate", webhook.HandleValidate)
	mux.HandleFunc("/healthz", webhook.HandleHealthz)
	mux.HandleFunc("/readyz", webhook.HandleReadyz)
	for _, mod := range mods {
		mod(webhook)
	}
	// Propagate the resolved observability seam into the reconciler regardless of
	// the order in which WithClient/WithLogger/WithMetrics were supplied.
	if webhook.reconciler != nil {
		webhook.reconciler.logger = webhook.logger
		webhook.reconciler.metrics = webhook.metrics
	}
	webhook.server = &http.Server{
		Addr:    opts.Addr,
		Handler: webhook.Handler,
	}
	if webhook.pki != nil {
		webhook.server.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				cert := webhook.pki.ServingCertificate()
				return &cert, nil
			},
		}
		// Route net/http TLS handshake errors through the bounded TLS-error seam
		// so a failing handshake increments aksh_webhook_tls_errors_total and
		// logs without any key material.
		webhook.server.ErrorLog = log.New(tlsErrorLogWriter{server: webhook}, "", 0)
	}
	return webhook, nil
}

// Serve starts the webhook server on the configured address and stops it when
// ctx is cancelled, draining in-flight requests before returning.
func (s *WebhookServer) Serve(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.server.Addr)
	if err != nil {
		return err
	}
	return s.serve(ctx, ln)
}

func (s *WebhookServer) serve(ctx context.Context, ln net.Listener) error {
	s.logger.Info("aksh-injector: serving webhook", "addr", ln.Addr().String())
	errCh := make(chan error, 1)
	go func() {
		if s.pki != nil {
			errCh <- s.server.ServeTLS(ln, "", "")
		} else {
			errCh <- s.server.Serve(ln)
		}
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := s.server.Shutdown(shutdownCtx); err != nil {
			return err
		}
		if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

// ReconcileCABundle patches the current CA PEM into both webhook configurations.
func (s *WebhookServer) ReconcileCABundle(ctx context.Context) error {
	if s.reconciler == nil {
		return errors.New("caBundle reconciler is not configured")
	}
	if s.pki == nil {
		return errors.New("serving material is not configured")
	}
	return s.reconciler.reconcile(ctx, s.pki.CABundle())
}

// RunCABundleReconciliation performs an initial reconciliation and then keeps
// the webhook configurations' caBundle equal to the current CA on an interval
// until ctx is cancelled.
func (s *WebhookServer) RunCABundleReconciliation(ctx context.Context) {
	if s.reconciler == nil || s.pki == nil {
		s.logger.Warn("aksh-injector: caBundle reconciliation not started", "reconciler", s.reconciler != nil, "pki", s.pki != nil)
		return
	}
	if err := s.ReconcileCABundle(ctx); err != nil {
		s.logger.Error("aksh-injector: caBundle reconciliation failed", "error", err)
	}

	interval := s.opts.CABundlePatchInterval
	if interval <= 0 {
		interval = defaultCABundlePatchInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.ReconcileCABundle(ctx); err != nil {
				s.logger.Error("aksh-injector: caBundle reconciliation failed", "error", err)
			}
		}
	}
}

// ready reports whether serving material is unexpired and both webhook
// configurations carry the current CA bundle. It fails closed on any error.
func (s *WebhookServer) ready(ctx context.Context) bool {
	if s.pki == nil {
		return false
	}
	if !s.pki.NotAfter().After(time.Now()) {
		return false
	}
	if s.reconciler == nil {
		return false
	}
	ok, err := s.reconciler.bundlesConsistent(ctx, s.pki.CABundle())
	if err != nil {
		return false
	}
	return ok
}

// HandleMutate returns a JSONPatch response for CREATE Pod requests.
func (s *WebhookServer) HandleMutate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	start := time.Now()
	defer func() { s.metrics.AdmissionDuration(audit.WebhookMutate, time.Since(start)) }()

	review, err := decodeAdmissionReview(w, r)
	if err != nil {
		s.metrics.AdmissionRequest(audit.WebhookMutate, audit.AdmissionResultError)
		http.Error(w, "invalid admission review", http.StatusBadRequest)
		return
	}
	if review.Request == nil {
		s.denyMutate(w, "", "admission request is required")
		return
	}
	if review.Request.Kind.Kind != "Pod" {
		s.denyMutate(w, review.Request.UID, "request kind must be Pod")
		return
	}
	if review.Request.Operation != admissionv1.Create {
		s.denyMutate(w, review.Request.UID, "request operation must be CREATE")
		return
	}

	var pod corev1.Pod
	if err := json.Unmarshal(review.Request.Object.Raw, &pod); err != nil {
		s.denyMutate(w, review.Request.UID, "object must be a Pod")
		return
	}
	// Capture the baseline JSON BEFORE Patch so an accidental in-place mutation
	// cannot corrupt the diff. We re-marshal the decoded pod (rather than using
	// Request.Object.Raw) so both sides of the diff share one serializer, which
	// yields a minimal JSONPatch; this original-marshal step is also the
	// fail-closed seam exercised by the OriginalMarshalError test.
	originalJSON, err := marshalJSON(&pod)
	if err != nil {
		s.errorMutate(w, review.Request.UID, "failed to marshal original pod")
		return
	}
	patchedPod, err := s.injector.Patch(&pod)
	if err != nil {
		s.denyMutate(w, review.Request.UID, err.Error())
		return
	}
	patchedJSON, err := marshalJSON(patchedPod)
	if err != nil {
		s.errorMutate(w, review.Request.UID, "failed to marshal patched pod")
		return
	}
	patchOps, err := createPatch(originalJSON, patchedJSON)
	if err != nil {
		s.errorMutate(w, review.Request.UID, "failed to create JSONPatch")
		return
	}
	patchBytes, err := json.Marshal(patchOps)
	if err != nil {
		s.errorMutate(w, review.Request.UID, "failed to marshal JSONPatch")
		return
	}
	s.metrics.AdmissionRequest(audit.WebhookMutate, audit.AdmissionResultAllowed)
	s.metrics.AdmissionPatchBytes(len(patchBytes))
	s.logger.Info("aksh-injector: pod mutation allowed",
		"namespace", review.Request.Namespace,
		"name", podIdentifier(&pod, review.Request.Name),
		"uid", string(review.Request.UID),
		"patchBytes", len(patchBytes),
	)
	patchType := admissionv1.PatchTypeJSONPatch
	writeAdmissionReview(w, admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Response: &admissionv1.AdmissionResponse{
			UID:       review.Request.UID,
			Allowed:   true,
			PatchType: &patchType,
			Patch:     patchBytes,
		},
	})
}

// denyMutate records the mutate denial metric and writes a fail-closed denied
// AdmissionReview response.
func (s *WebhookServer) denyMutate(w http.ResponseWriter, uid types.UID, message string) {
	s.metrics.AdmissionRequest(audit.WebhookMutate, audit.AdmissionResultDenied)
	writeAdmissionReview(w, deniedAdmissionReview(uid, message))
}

// errorMutate records an internal-error admission result - a server-side fault
// (marshal or JSONPatch-construction failure), not a policy denial - so the
// aksh_admission_requests_total{result} label separates webhook faults from
// legitimate denials. The response is still a fail-closed denial.
func (s *WebhookServer) errorMutate(w http.ResponseWriter, uid types.UID, message string) {
	s.metrics.AdmissionRequest(audit.WebhookMutate, audit.AdmissionResultError)
	writeAdmissionReview(w, deniedAdmissionReview(uid, message))
}

// podIdentifier returns a bounded name for logging: the request name when set,
// otherwise the pod's own metadata name (which may be empty for generateName
// pods). Only the name is logged; the pod object itself is never logged.
func podIdentifier(pod *corev1.Pod, requestName string) string {
	if requestName != "" {
		return requestName
	}
	return pod.Name
}

// HandleValidate asserts INV-10 on the final admitted pod for pod CREATE and
// pods/ephemeralcontainers UPDATE. It fails closed: malformed input, missing
// request, non-Pod kinds, and unsupported operations are denied, and Validate
// failures map to AdmissionReview denials (403 for AdmissionError, 500 for
// unexpected errors).
func (s *WebhookServer) HandleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	start := time.Now()
	defer func() { s.metrics.AdmissionDuration(audit.WebhookValidate, time.Since(start)) }()

	review, err := decodeAdmissionReview(w, r)
	if err != nil {
		s.metrics.AdmissionRequest(audit.WebhookValidate, audit.AdmissionResultError)
		http.Error(w, "invalid admission review", http.StatusBadRequest)
		return
	}
	if review.Request == nil {
		s.denyValidate(w, "", "admission request is required")
		return
	}
	if review.Request.Kind.Kind != "Pod" {
		s.denyValidate(w, review.Request.UID, "request kind must be Pod")
		return
	}
	if !isValidatableOperation(review.Request) {
		s.denyValidate(w, review.Request.UID, "request operation must be CREATE or pods/ephemeralcontainers UPDATE")
		return
	}

	var pod corev1.Pod
	if err := json.Unmarshal(review.Request.Object.Raw, &pod); err != nil {
		s.denyValidate(w, review.Request.UID, "object must be a Pod")
		return
	}
	if err := s.injector.Validate(&pod); err != nil {
		// A field-specific AdmissionError is a policy denial (403); any other
		// error is an internal webhook fault (500). Separate them in the metric
		// so webhook failures are not hidden under legitimate denials.
		var ae AdmissionError
		if errors.As(err, &ae) {
			s.metrics.AdmissionRequest(audit.WebhookValidate, audit.AdmissionResultDenied)
		} else {
			s.metrics.AdmissionRequest(audit.WebhookValidate, audit.AdmissionResultError)
		}
		s.logValidationDenial(review.Request, err)
		writeAdmissionReview(w, validationDeniedAdmissionReview(review.Request.UID, err))
		return
	}
	s.metrics.AdmissionRequest(audit.WebhookValidate, audit.AdmissionResultAllowed)
	writeAdmissionReview(w, admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Response: &admissionv1.AdmissionResponse{
			UID:     review.Request.UID,
			Allowed: true,
		},
	})
}

// denyValidate records the validate denial metric and writes a fail-closed
// denied AdmissionReview response for the pre-Validate guard checks.
func (s *WebhookServer) denyValidate(w http.ResponseWriter, uid types.UID, message string) {
	s.metrics.AdmissionRequest(audit.WebhookValidate, audit.AdmissionResultDenied)
	writeAdmissionReview(w, deniedAdmissionReview(uid, message))
}

// logValidationDenial emits a bounded denial log carrying the offending field
// and reason. Only the bounded AdmissionError field/reason (or a generic reason
// for unexpected errors) and request identity are logged — never the pod object,
// secrets, or any credential material.
func (s *WebhookServer) logValidationDenial(request *admissionv1.AdmissionRequest, err error) {
	var ae AdmissionError
	if errors.As(err, &ae) {
		// Policy denial: an expected INV-10 rejection, logged at Info.
		s.logger.Info("aksh-injector: pod admission denied",
			"namespace", request.Namespace,
			"name", request.Name,
			"uid", string(request.UID),
			"field", ae.Field,
			"reason", ae.Reason,
		)
		return
	}
	// A non-AdmissionError is an internal validation fault, not a policy
	// decision: log at Error (bounded, no underlying detail) so it is not
	// misread as a routine denial.
	s.logger.Error("aksh-injector: pod admission denied",
		"namespace", request.Namespace,
		"name", request.Name,
		"uid", string(request.UID),
		"field", "",
		"reason", "validation failed",
	)
}

// isValidatableOperation reports whether the request is a pod CREATE or a
// pods/ephemeralcontainers UPDATE, the two operations that produce a final pod
// requiring INV-10 validation.
func isValidatableOperation(request *admissionv1.AdmissionRequest) bool {
	if request.Operation == admissionv1.Create {
		return true
	}
	return request.Operation == admissionv1.Update && request.SubResource == "ephemeralcontainers"
}

// validationDeniedAdmissionReview maps a Validate error to a fail-closed
// AdmissionReview denial: 403 for a field-specific AdmissionError, 500 otherwise.
func validationDeniedAdmissionReview(uid types.UID, err error) admissionv1.AdmissionReview {
	code := int32(http.StatusInternalServerError)
	message := "validation failed"
	var ae AdmissionError
	if errors.As(err, &ae) {
		code = http.StatusForbidden
		message = ae.Error()
	}
	return admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Response: &admissionv1.AdmissionResponse{
			UID:     uid,
			Allowed: false,
			Result:  &metav1.Status{Code: code, Message: message},
		},
	}
}

// HandleHealthz reports process liveness.
func (s *WebhookServer) HandleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// HandleReadyz reports readiness: serving material must be unexpired and both
// webhook configurations must carry the current CA bundle. It fails closed.
func (s *WebhookServer) HandleReadyz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.ready(r.Context()) {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func decodeAdmissionReview(w http.ResponseWriter, r *http.Request) (admissionv1.AdmissionReview, error) {
	var review admissionv1.AdmissionReview
	body := http.MaxBytesReader(w, r.Body, maxAdmissionBodyBytes)
	defer body.Close()
	if err := json.NewDecoder(body).Decode(&review); err != nil {
		return admissionv1.AdmissionReview{}, err
	}
	return review, nil
}

func writeAdmissionReview(w http.ResponseWriter, review admissionv1.AdmissionReview) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(review); err != nil {
		http.Error(w, "failed to encode admission response", http.StatusInternalServerError)
	}
}

func deniedAdmissionReview(uid types.UID, message string) admissionv1.AdmissionReview {
	return admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Response: &admissionv1.AdmissionResponse{
			UID:     uid,
			Allowed: false,
			Result:  &metav1.Status{Message: message},
		},
	}
}
