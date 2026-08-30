package pipeline

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/girishmotwani/aksh/internal/policy"
	"github.com/girishmotwani/aksh/internal/token"
)

const defaultAuditTimeout = 250 * time.Millisecond

type AuditSink interface {
	Record(ctx context.Context, ev AuditEvent) error
}

type Pipeline struct {
	stages        []Stage
	auditBoundary int // index of first post-audit stage
	auditSink     AuditSink
	auditTimeout  time.Duration
	identity      AuditIdentity
}

// AuditIdentity is the per-process pod attribution and service-account identity
// stamped onto every audit record. It is resolved once at startup from the S5
// Downward API (never re-read per request) because it is constant for the life
// of the process: replicas share a ServiceAccount, so the pod triple is the only
// thing that distinguishes them (ADR-S0-06), and re-reading the environment on
// the request path would be pure overhead for a value that cannot change.
type AuditIdentity struct {
	PodNamespace   string
	PodName        string
	PodUID         string
	ServiceAccount string
}

// PipelineOption configures a Pipeline at construction time. It exists so
// additive, optional wiring (such as the audit identity) can be supplied
// without changing NewPipeline's signature, which has many test callers that
// must keep compiling unchanged.
type PipelineOption func(*Pipeline)

// WithAuditIdentity stamps the per-process pod attribution and service account
// onto every audit record this pipeline emits. Omitting it leaves the identity
// zero-valued, which the encoder renders as empty strings — the pre-option
// behaviour, so existing callers are unaffected.
func WithAuditIdentity(id AuditIdentity) PipelineOption {
	return func(p *Pipeline) { p.identity = id }
}

// AuditIdentity returns the per-process pod attribution stamped onto audit
// records. Exposed so the runtime wiring can be verified end-to-end: the value
// is a startup constant, so reading it is race-free.
func (p *Pipeline) AuditIdentity() AuditIdentity { return p.identity }

func NewPipeline(stages []Stage, sink AuditSink, opts ...PipelineOption) *Pipeline {
	// Freeze ordering at construction time so a caller cannot move security
	// boundaries by mutating its slice while requests are in flight.
	copied := make([]Stage, len(stages))
	copy(copied, stages)

	boundary := len(copied)
	for i, stage := range copied {
		if stage != nil && stage.Name() == "inject" {
			// Audit is inserted immediately before credential materialisation;
			// every earlier decision is therefore recorded before injection.
			boundary = i
			break
		}
	}

	p := &Pipeline{
		stages:        copied,
		auditBoundary: boundary,
		auditSink:     sink,
		auditTimeout:  defaultAuditTimeout,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(p)
		}
	}
	return p
}

func (p *Pipeline) Execute(ctx context.Context, rc *RequestContext) (decision Decision) {
	if rc == nil {
		return DenyFault(ReasonInternal, fmt.Errorf("request context is nil"))
	}
	if rc.Timings == nil {
		rc.Timings = make(map[string]time.Duration, len(p.stages)+1)
	}
	if rc.StartTime.IsZero() {
		rc.StartTime = time.Now()
	}

	preAuditEnd := p.auditBoundary

	// Pre-audit stages short-circuit request processing, but never the single
	// audit attempt that records both allows and denials.
	decision, _, _ = p.runStages(rc, p.stages[:preAuditEnd], true)
	decision = normalizeDecision(decision)

	auditDecision := decision
	if auditDecision.IsAllow() {
		auditDecision = Allow()
	}
	if err := p.audit(rc, auditDecision); err != nil {
		decision = DenyFault(ReasonAuditUnavailable, err)
		rc.Decision = decision
		return decision
	}

	if !decision.IsAllow() {
		rc.Decision = decision
		return decision
	}

	postDecision, _, _ := p.runStages(rc, p.stages[preAuditEnd:], false)
	if !postDecision.IsAllow() {
		// The committed allow remains authoritative; this return value only
		// reports that post-audit completion did not succeed.
		fault := DenyFault(ReasonInternal, fmt.Errorf("post-audit completion failure"))
		fault.Fault = true
		rc.Decision = fault
		return fault
	}
	rc.Decision = Allow()
	return Allow()
}

func (p *Pipeline) runStages(rc *RequestContext, stages []Stage, preAudit bool) (Decision, bool, error) {
	decision := Allow()
	for _, stage := range stages {
		if stage == nil {
			continue
		}

		start := time.Now()
		stageDecision, panicErr := executeStage(stage, rc)
		rc.Timings[stage.Name()] = time.Since(start)

		if panicErr != nil {
			return DenyFault(ReasonInternal, panicErr), true, panicErr
		}

		decision = stageDecision
		if !decision.IsAllow() {
			if preAudit {
				return decision, false, nil
			}
			return DenyFault(ReasonInternal, fmt.Errorf("post-audit stage %q failed", stage.Name())), false, nil
		}
	}

	return decision, false, nil
}

func executeStage(stage Stage, rc *RequestContext) (decision Decision, panicErr error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			panicErr = fmt.Errorf("stage %q panicked: %v", stage.Name(), recovered)
		}
	}()
	return stage.Execute(rc), nil
}

func normalizeDecision(decision Decision) Decision {
	// Only explicit allow or deny values may cross the audit boundary. This
	// converts forgotten assignments and unsupported future states into faults.
	switch decision.Disposition() {
	case DispositionAllow, DispositionDeny:
		return decision
	case DispositionInvalid:
		return DenyFault(ReasonInternal, fmt.Errorf("invalid decision"))
	case DispositionPending:
		return DenyFault(ReasonInternal, fmt.Errorf("pending decision"))
	default:
		return DenyFault(ReasonInternal, fmt.Errorf("unknown disposition %v", decision.Disposition()))
	}
}

func (p *Pipeline) audit(rc *RequestContext, decision Decision) error {
	if p.auditSink == nil {
		return errors.New("audit sink is nil")
	}

	start := time.Now()
	// Request cancellation is agent-controlled. Detaching prevents a client
	// disconnect from suppressing its decision record, while the private
	// deadline still bounds sink stalls.
	auditCtx, cancel := context.WithTimeout(context.Background(), p.timeout())
	defer cancel()

	err := p.auditSink.Record(auditCtx, p.buildAuditEvent(rc, decision))
	rc.Timings["audit"] = time.Since(start)
	return err
}

func (p *Pipeline) timeout() time.Duration {
	if p == nil || p.auditTimeout <= 0 {
		return defaultAuditTimeout
	}
	return p.auditTimeout
}

func (p *Pipeline) buildAuditEvent(rc *RequestContext, decision Decision) AuditEvent {
	credentialID := "none"
	if rc.TokenResult.Resolved.Identity != "" {
		credentialID = rc.TokenResult.Resolved.Identity
	} else if rc.MatchResult.Credential != nil {
		// Acquisition can fail before returning resolved metadata. Deriving the
		// same stable identity here keeps the failed credential auditable.
		sel := toTokenSelector(rc.MatchResult.Credential)
		if resolved, err := token.Resolve(sel); err == nil {
			credentialID = resolved.Identity
		}
	}

	return AuditEvent{
		Timestamp:     time.Now(),
		RequestID:     rc.RequestID,
		Identity:      rc.Facts.Identity,
		Method:        rc.Facts.Method,
		Path:          rc.Facts.Path,
		Port:          rc.Facts.Port,
		Disposition:   decision.Disposition(),
		DenyReason:    decision.Reason,
		Fault:         decision.Fault,
		FaultClass:    faultClass(decision),
		PolicyVersion: rc.MatchResult.Version,
		RuleName:      rc.MatchResult.PolicyRef,
		CredentialID:  credentialID,
		CacheHit:      rc.TokenResult.CacheHit,
		Ambiguous:     rc.MatchResult.Ambiguous,

		// Pod attribution and service account are per-process startup constants
		// (S5 Downward API), resolved once and held on the Pipeline; replicas
		// share a ServiceAccount, so the pod triple is the only attribution that
		// distinguishes them (ADR-S0-06).
		PodNamespace:        p.identity.PodNamespace,
		PodName:             p.identity.PodName,
		PodUID:              p.identity.PodUID,
		AgentServiceAccount: p.identity.ServiceAccount,

		// EvaluatorVersion is always recorded: the policy hash attests the rule
		// inputs, not the evaluator's behaviour (S2 §6), so it cannot stand in
		// for the build that actually enforced the decision.
		EvaluatorVersion: policy.EvaluatorVersion,

		Timings: buildTimings(rc),
	}
}

// buildTimings maps the pipeline's per-stage stopwatch (rc.Timings) onto the
// audit record's typed durations.
//
// Total is measured from rc.StartTime to now, but "now" here is audit-build
// time, which is deliberately BEFORE the post-audit stages (inject/forward)
// run — audit records the decision before the credential is materialised (S4).
// It is therefore time-to-audit, an honest lower bound on request latency, not
// the full request duration; naming it Total keeps the §2 timings block schema
// while this comment records what it actually measures.
//
// Audit is intentionally left at its zero value. rc.Timings["audit"] is written
// only AFTER this event has been built and handed to the sink — a record cannot
// contain the time taken to write itself. Rather than fabricate a value or
// borrow another request's (which would also require sharing mutable state
// across the per-request goroutine boundary), the field is left zero and this
// structural unavailability is documented on AuditTimings.Audit.
func buildTimings(rc *RequestContext) AuditTimings {
	return AuditTimings{
		Total:   time.Since(rc.StartTime),
		Match:   rc.Timings["match"],
		Acquire: rc.Timings["acquire"],
	}
}

func faultClass(decision Decision) FaultClass {
	if !decision.Fault {
		return FaultClassNone
	}

	// Collapse implementation errors into a closed classification so audit
	// never serialises arbitrary error strings that may contain sensitive data.
	var acquireErr *token.AcquireError
	if errors.As(decision.Cause, &acquireErr) {
		switch acquireErr.Class {
		case token.AcquireErrorTransient:
			return FaultClassTransient
		case token.AcquireErrorPermanent:
			return FaultClassPermanent
		case token.AcquireErrorLocal:
			return FaultClassLocal
		}
	}

	if errors.Is(decision.Cause, context.Canceled) || errors.Is(decision.Cause, context.DeadlineExceeded) {
		return FaultClassTransient
	}

	return FaultClassLocal
}
