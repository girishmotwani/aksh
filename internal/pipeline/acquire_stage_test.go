package pipeline

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	v1alpha1 "github.com/girishmotwani/aksh/api/v1alpha1"
	"github.com/girishmotwani/aksh/internal/policy"
	"github.com/girishmotwani/aksh/internal/token"
)

type testCache struct {
	result token.TokenResult
	err    error
	gotSel token.CredentialSelector
}

func (c *testCache) Get(_ context.Context, sel token.CredentialSelector) (token.TokenResult, error) {
	c.gotSel = sel
	return c.result, c.err
}

func TestAcquireStage_WithCredentialStoresTokenResult(t *testing.T) {
	cache := &testCache{
		result: token.TokenResult{
			Token: token.NewToken("secret", time.Now().Add(time.Hour)),
			Resolved: token.ResolvedCredential{
				Identity: "cred-id",
			},
		},
	}
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	rc := &RequestContext{
		Request: req,
		MatchResult: policy.MatchResult{
			Credential: &v1alpha1.CredentialSelector{
				Provider: "entra",
				Resource: "api://example",
				Scopes:   []string{"write", "read"},
			},
		},
	}
	stage := &AcquireStage{Cache: cache}

	decision := stage.Execute(rc)

	if !decision.IsAllow() {
		t.Fatalf("Execute() disposition = %v, want allow", decision.Disposition())
	}
	if rc.TokenResult.Resolved.Identity != "cred-id" {
		t.Fatalf("stored token result = %+v, want cred-id", rc.TokenResult)
	}
	if cache.gotSel.Provider != "entra" || cache.gotSel.Resource != "api://example" || len(cache.gotSel.Scopes) != 2 {
		t.Fatalf("selector = %+v, want converted selector", cache.gotSel)
	}
}

func TestAcquireStage_NoCredentialAllowsWithoutToken(t *testing.T) {
	rc := &RequestContext{}

	decision := (&AcquireStage{}).Execute(rc)

	if !decision.IsAllow() {
		t.Fatalf("Execute() disposition = %v, want allow", decision.Disposition())
	}
	if rc.TokenResult.Token.Reveal() != "" {
		t.Fatalf("TokenResult.Token = %q, want empty", rc.TokenResult.Token.Reveal())
	}
}

func TestAcquireStage_AcquisitionFailureDeniesFault(t *testing.T) {
	cache := &testCache{err: errors.New("unavailable")}
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	rc := &RequestContext{
		Request: req,
		MatchResult: policy.MatchResult{
			Credential: &v1alpha1.CredentialSelector{Provider: "entra"},
		},
	}

	decision := (&AcquireStage{Cache: cache}).Execute(rc)

	if decision.Reason != ReasonTokenUnavailable || !decision.Fault {
		t.Fatalf("Execute() = %+v, want token unavailable fault", decision)
	}
}
