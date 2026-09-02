package watch

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	v1alpha1 "github.com/girishmotwani/aksh/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// forbiddenErr builds the error client-go surfaces when RBAC denies the policy
// list, i.e. the exact failure a missing RoleBinding produces.
func forbiddenErr() error {
	return apierrors.NewForbidden(
		schema.GroupResource{Group: "aksh.dev", Resource: "akshpolicies"},
		"",
		errors.New("akshpolicies.aksh.dev is forbidden: User \"system:serviceaccount:app-ns:default\" cannot list resource \"akshpolicies\""),
	)
}

// captureLog points a watcher's logger at a buffer and returns it.
func captureLog(w *Watcher) *bytes.Buffer {
	buf := &bytes.Buffer{}
	w.log = slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return buf
}

// A forbidden list is the missing-RBAC case. It must be counted on its own
// metric and logged at ERROR naming the remediation, because this error
// previously reached no log, no metric and no returned error at all.
func TestNoteListFailure_Forbidden_CountsMetricAndLogsRemediation(t *testing.T) {
	w := mustWatcher(t, Options{Namespace: "app-ns", MaxStaleness: time.Minute}, newFakeClient("app-ns"), &Store{})
	m := &countingMetrics{}
	w.metrics = m
	buf := captureLog(w)

	w.noteListFailure(phaseInitial, forbiddenErr())

	if got := m.forbiddenCount(); got != 1 {
		t.Fatalf("PolicyListForbidden calls = %d, want 1", got)
	}
	if got := m.count(); got != 0 {
		t.Fatalf("PolicyStaleDeny calls = %d, want 0 (a forbidden list is not a staleness transition)", got)
	}

	out := buf.String()
	if !strings.Contains(out, "level=ERROR") {
		t.Errorf("forbidden list logged below ERROR; an operator must not have to raise the log level to see it:\n%s", out)
	}
	for _, want := range []string{"akshpolicies", "verbs=[get,list,watch]", "remediation", "app-ns", "phase=initial"} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %q, so the message is not actionable on its own:\n%s", want, out)
		}
	}
}

// A transport or availability failure is retryable and must not be reported as
// a permission problem, or the forbidden metric becomes useless as an alert.
func TestNoteListFailure_NonForbidden_DoesNotCountAsForbidden(t *testing.T) {
	w := mustWatcher(t, Options{Namespace: "app-ns", MaxStaleness: time.Minute}, newFakeClient("app-ns"), &Store{})
	m := &countingMetrics{}
	w.metrics = m
	buf := captureLog(w)

	w.noteListFailure(phaseInitial, errors.New("connection refused"))

	if got := m.forbiddenCount(); got != 0 {
		t.Fatalf("PolicyListForbidden calls = %d for a transport error, want 0", got)
	}
	out := buf.String()
	if !strings.Contains(out, "level=WARN") {
		t.Errorf("retryable list failure not logged at WARN:\n%s", out)
	}
	if strings.Contains(out, "remediation") {
		t.Errorf("RBAC remediation suggested for a transport error, which would mislead the operator:\n%s", out)
	}
}

// 401 is a rejected or absent ServiceAccount token. Like 403 it cannot be fixed
// by retrying, so it must classify the same way.
func TestNoteListFailure_Unauthorized_ClassifiesAsAccessDenied(t *testing.T) {
	w := mustWatcher(t, Options{Namespace: "app-ns", MaxStaleness: time.Minute}, newFakeClient("app-ns"), &Store{})
	m := &countingMetrics{}
	w.metrics = m
	captureLog(w)

	w.noteListFailure(phaseInitial, apierrors.NewUnauthorized("token expired"))

	if got := m.forbiddenCount(); got != 1 {
		t.Fatalf("PolicyListForbidden calls = %d for a 401, want 1", got)
	}
}

// The initial-list loop retries on a 50ms base backoff for the whole
// first-snapshot window, so unrated logging would bury the message. The first
// failure must always be emitted and the rest sampled.
func TestNoteListFailure_RateLimits_ButAlwaysLogsTheFirst(t *testing.T) {
	w := mustWatcher(t, Options{Namespace: "app-ns", MaxStaleness: time.Minute}, newFakeClient("app-ns"), &Store{})
	w.metrics = &countingMetrics{}
	buf := captureLog(w)

	for i := 0; i < logEveryNListFailures*2; i++ {
		w.noteListFailure(phaseInitial, forbiddenErr())
	}

	got := strings.Count(buf.String(), "attempts=")
	// Attempt 1 (always), then attempts 10 and 20.
	if want := 3; got != want {
		t.Fatalf("log lines = %d, want %d for %d failures at 1-in-%d sampling", got, want, logEveryNListFailures*2, logEveryNListFailures)
	}
	if !strings.Contains(buf.String(), "attempts=1") {
		t.Error("the first failure was not logged; a short-lived outage would be entirely silent")
	}
}

// After a success the failure state must reset, so a later outage is reported
// immediately rather than being swallowed by the rate limiter, and so a stale
// error is not attached to an unrelated later timeout.
func TestNoteListSuccess_ResetsFailureStateAndLastError(t *testing.T) {
	w := mustWatcher(t, Options{Namespace: "app-ns", MaxStaleness: time.Minute}, newFakeClient("app-ns"), &Store{})
	w.metrics = &countingMetrics{}
	captureLog(w)

	for i := 0; i < logEveryNListFailures+5; i++ {
		w.noteListFailure(phaseInitial, forbiddenErr())
	}
	if w.lastListFailure() == nil {
		t.Fatal("lastListFailure() = nil while failing, want the retained error")
	}

	w.noteListSuccess()

	if err := w.lastListFailure(); err != nil {
		t.Fatalf("lastListFailure() = %v after a success, want nil", err)
	}
	buf := captureLog(w)
	w.noteListFailure(phaseReconnect, forbiddenErr())
	if !strings.Contains(buf.String(), "attempts=1") {
		t.Fatalf("failure after a success was not logged immediately:\n%s", buf.String())
	}
}

// The regression this whole change exists for: a first-snapshot timeout used to
// return a bare context error, so an operator saw "context deadline exceeded"
// and had no way to learn that RBAC was the cause.
func TestWaitFirstSnapshot_Timeout_ReportsTheUnderlyingListFailure(t *testing.T) {
	client := newFakeClient("app-ns")
	client.listFn = func(int) (*v1alpha1.AkshPolicyList, error) { return nil, forbiddenErr() }

	w := mustWatcher(t, Options{Namespace: "app-ns", MaxStaleness: time.Minute}, client, &Store{})
	w.metrics = &countingMetrics{}
	captureLog(w)

	runCtx, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	go func() { _ = w.Run(runCtx) }()

	waitCtx, cancelWait := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancelWait()

	err := w.WaitFirstSnapshot(waitCtx)
	if err == nil {
		t.Fatal("WaitFirstSnapshot() = nil, want a timeout error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitFirstSnapshot() = %v; callers classify this with errors.Is, so the context error must stay wrapped", err)
	}
	if !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("WaitFirstSnapshot() = %q, want the underlying list failure named; a bare deadline error points at the wrong cause", err)
	}
}

// With no list failure recorded, the timeout must stay exactly the context
// error so unrelated cancellations are not decorated with misleading detail.
func TestWaitFirstSnapshot_CanceledWithNoListFailure_ReturnsBareContextError(t *testing.T) {
	w := mustWatcher(t, Options{Namespace: "app-ns", MaxStaleness: time.Minute}, newFakeClient("app-ns"), &Store{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := w.WaitFirstSnapshot(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("WaitFirstSnapshot() = %v, want context.Canceled", err)
	}
	if strings.Contains(err.Error(), "last list error") {
		t.Fatalf("WaitFirstSnapshot() = %q, want no list detail when none was recorded", err)
	}
}
