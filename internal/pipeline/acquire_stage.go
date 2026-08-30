package pipeline

import (
	"context"
	"fmt"

	v1alpha1 "github.com/girishmotwani/aksh/api/v1alpha1"
	"github.com/girishmotwani/aksh/internal/token"
)

type TokenGetter interface {
	// Get returns token material to the pipeline only; policy code receives
	// selectors and resolved metadata, never the acquired credential.
	Get(ctx context.Context, sel token.CredentialSelector) (token.TokenResult, error)
}

type AcquireStage struct {
	Cache TokenGetter
}

func (s *AcquireStage) Name() string { return "acquire" }

func (s *AcquireStage) Execute(rc *RequestContext) Decision {
	if rc == nil {
		return DenyFault(ReasonInternal, fmt.Errorf("request context is nil"))
	}
	if rc.MatchResult.Credential == nil {
		// Explicitly clear the result so a credential-free match cannot inherit
		// token state if a RequestContext is reused accidentally.
		rc.TokenResult = token.TokenResult{}
		return Allow()
	}
	if s == nil || s.Cache == nil {
		return DenyFault(ReasonInternal, fmt.Errorf("acquire stage cache is not configured"))
	}

	getCtx := context.Background()
	if rc.Request != nil {
		// Acquisition follows request cancellation; unlike audit, it has no
		// security reason to outlive a client that has gone away.
		getCtx = rc.Request.Context()
	}

	result, err := s.Cache.Get(getCtx, toTokenSelector(rc.MatchResult.Credential))
	if err != nil {
		return DenyFault(ReasonTokenUnavailable, err)
	}

	rc.TokenResult = result
	return Allow()
}

func toTokenSelector(sel *v1alpha1.CredentialSelector) token.CredentialSelector {
	if sel == nil {
		return token.CredentialSelector{}
	}

	scopes := make([]string, len(sel.Scopes))
	// Keep policy snapshots immutable from the token layer's perspective.
	copy(scopes, sel.Scopes)
	return token.CredentialSelector{
		Provider: sel.Provider,
		Resource: sel.Resource,
		Scopes:   scopes,
	}
}
