package pipeline

import (
	"context"
	"fmt"
	"time"

	"github.com/girishmotwani/aksh/internal/policy"
)

const defaultMaxStaleness = 5 * time.Minute

type MatchStage struct {
	Store        policy.PolicyStore
	Matcher      policy.Matcher
	MaxStaleness time.Duration
}

func (s *MatchStage) Name() string { return "match" }

func (s *MatchStage) maxStaleness() time.Duration {
	if s.MaxStaleness > 0 {
		return s.MaxStaleness
	}
	return defaultMaxStaleness
}

func (s *MatchStage) Execute(rc *RequestContext) Decision {
	if s == nil || s.Store == nil || s.Matcher == nil {
		return DenyFault(ReasonInternal, fmt.Errorf("match stage is not configured"))
	}

	snap, age, ok := s.Store.Current()
	if !ok {
		return DenyFault(ReasonNoSnapshot, nil)
	}
	// The boundary is inclusive and two-sided fail-closed: once the snapshot
	// reaches the configured limit, continuing would authorise from policy
	// explicitly deemed stale. A negative age can only arise from a clock
	// anomaly (a rolled-back or corrupted publication time); treating it as
	// fresh would be fail-OPEN, so it is denied as stale as well.
	if age < 0 || age >= s.maxStaleness() {
		return DenyFault(ReasonSnapshotStale, nil)
	}

	matchCtx := context.Background()
	if rc != nil && rc.Request != nil {
		// Evaluation is request-scoped; a disconnected client should not keep
		// consuming matcher capacity.
		matchCtx = rc.Request.Context()
	}

	result, err := s.Matcher.Match(matchCtx, snap, rc.Facts)
	if err != nil {
		return DenyFault(ReasonMatcherFault, err)
	}
	if !result.Matched {
		return Deny(ReasonNoMatch, nil)
	}

	// Preserve the complete match result because later acquisition and audit
	// must agree on the exact rule, version, and credential that authorised.
	rc.MatchResult = result
	return Allow()
}
