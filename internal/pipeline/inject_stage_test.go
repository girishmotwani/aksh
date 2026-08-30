package pipeline

import (
	"net/http"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/token"
)

func TestInjectStage_TokenInjectedAsBearer(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	rc := &RequestContext{
		Request: req,
		TokenResult: token.TokenResult{
			Token: token.NewToken("secret-value", time.Now().Add(time.Hour)),
		},
	}

	decision := (&InjectStage{}).Execute(rc)

	if !decision.IsAllow() {
		t.Fatalf("Execute() disposition = %v, want allow", decision.Disposition())
	}
	if got := req.Header.Get("Authorization"); got != "Bearer secret-value" {
		t.Fatalf("Authorization = %q, want Bearer secret-value", got)
	}
}

func TestInjectStage_NoTokenLeavesHeaderUnset(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	decision := (&InjectStage{}).Execute(&RequestContext{Request: req})

	if !decision.IsAllow() {
		t.Fatalf("Execute() disposition = %v, want allow", decision.Disposition())
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("Authorization = %q, want empty", got)
	}
}
