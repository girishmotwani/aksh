package watch

import (
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// listFailurePhase names the loop that observed a failed List so a log line
// distinguishes "policy was never obtained" from "policy was lost after having
// worked". The two have very different operator responses: the first is almost
// always a missing RoleBinding at install time, the second is a permission or
// API-server change against a pod that was previously healthy.
type listFailurePhase string

const (
	phaseInitial   listFailurePhase = "initial"
	phaseReconnect listFailurePhase = "reconnect"
)

// logEveryNListFailures rate-limits the retry logging. The first failure after
// a success is always emitted; thereafter one in every N. Without this, the
// initial-list loop retries on a 50ms base backoff and would emit hundreds of
// lines before the first-snapshot timeout fires, burying the message it is
// trying to convey.
const logEveryNListFailures = 10

// requiredPolicyRBAC is the remediation named in the forbidden log line. It is
// spelled out rather than pointing at documentation because this message is
// frequently the only artifact an operator has when the sidecar will not start,
// and it must be actionable without leaving the terminal.
const requiredPolicyRBAC = "grant the pod's ServiceAccount a Role in its own namespace with " +
	"apiGroups=[aksh.dev] resources=[akshpolicies] verbs=[get,list,watch], and a RoleBinding to it"

// isPolicyAccessDenied reports whether err is the API server refusing the
// caller rather than a transport or availability failure. 403 is the missing
// RoleBinding; 401 is a rejected or absent ServiceAccount token. Both are
// permanent from the proxy's perspective -- retrying cannot fix them -- which
// is exactly why they warrant a louder report than a generic list failure.
func isPolicyAccessDenied(err error) bool {
	return apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err)
}

// noteListFailure records and reports a failed policy List.
//
// Retaining the error is the point: initialList previously discarded it, so a
// 403 never reached a log, a metric or the returned error, and the only
// operator-visible symptom was the first-snapshot gate timing out with a bare
// "context deadline exceeded" that pointed at the wrong cause entirely.
func (w *Watcher) noteListFailure(phase listFailurePhase, err error) {
	if err == nil {
		return
	}
	w.lastListErr.Store(&err)

	denied := isPolicyAccessDenied(err)
	if denied {
		w.metrics.PolicyListForbidden()
	}

	n := w.listFailures.Add(1)
	if n != 1 && n%logEveryNListFailures != 0 {
		return
	}

	if denied {
		w.log.Error("policy list refused by the API server; this pod's ServiceAccount cannot read AkshPolicy, so the proxy will never obtain a policy snapshot and will fail to start",
			"namespace", w.opts.Namespace,
			"phase", string(phase),
			"remediation", requiredPolicyRBAC,
			"attempts", n,
			"error", err.Error())
		return
	}

	w.log.Warn("policy list failed; retrying",
		"namespace", w.opts.Namespace,
		"phase", string(phase),
		"attempts", n,
		"error", err.Error())
}

// noteListSuccess clears the failure state after a successful List so that a
// later outage is reported immediately rather than being swallowed by the rate
// limiter, and so a stale error cannot be attached to an unrelated later
// timeout.
func (w *Watcher) noteListSuccess() {
	w.listFailures.Store(0)
	w.lastListErr.Store(nil)
}

// lastListFailure returns the most recent List error, or nil if the last List
// succeeded or none has been attempted.
func (w *Watcher) lastListFailure() error {
	if p := w.lastListErr.Load(); p != nil {
		return *p
	}
	return nil
}
