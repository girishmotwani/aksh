package pipeline

import (
	"net/http"
	"testing"
)

func TestSanitiseStage_StripsSensitiveHeaders(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Add("Authorization", "Bearer one")
	req.Header.Add("Authorization", "Bearer two")
	req.Header.Set("Proxy-Authorization", "Basic abc")
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Forwarded-Host", "proxy")
	req.Header.Set("X-Forwarded-Proto", "http")
	req.Header.Set("X-Real-IP", "1.2.3.4")
	req.Header.Set("Forwarded", "for=1.2.3.4")
	req.Header.Set("Via", "proxy")
	req.Header.Set("X-Envoy-External-Address", "1.2.3.4")
	req.Header.Set("X-Aksh-Test", "internal")
	req.Header.Set("Accept", "application/json")

	rc := &RequestContext{Request: req}

	decision := (&SanitiseStage{}).Execute(rc)

	if !decision.IsAllow() {
		t.Fatalf("Execute() disposition = %v, want allow", decision.Disposition())
	}
	for _, key := range []string{
		"Authorization",
		"Proxy-Authorization",
		"X-Forwarded-For",
		"X-Forwarded-Host",
		"X-Forwarded-Proto",
		"X-Real-IP",
		"Forwarded",
		"Via",
		"X-Envoy-External-Address",
		"X-Aksh-Test",
	} {
		if values := req.Header.Values(key); len(values) != 0 {
			t.Fatalf("header %q = %v, want stripped", key, values)
		}
	}
	if got := req.Header.Get("Accept"); got != "application/json" {
		t.Fatalf("Accept header = %q, want preserved", got)
	}
}

func TestSanitiseStage_NilRequestContext(t *testing.T) {
	d := (&SanitiseStage{}).Execute(nil)
	if d.IsAllow() {
		t.Fatal("nil rc should DenyFault, not Allow")
	}
}

func TestSanitiseStage_StripsHopByHopHeaders(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Keep-Alive", "timeout=5")
	req.Header.Set("Te", "trailers")
	req.Header.Set("Proxy-Connection", "keep-alive")
	req.Header.Set("Accept", "text/html")

	rc := &RequestContext{Request: req}
	(&SanitiseStage{}).Execute(rc)

	for _, key := range []string{"Connection", "Keep-Alive", "Te", "Proxy-Connection"} {
		if req.Header.Get(key) != "" {
			t.Fatalf("hop-by-hop header %q not stripped", key)
		}
	}
	if req.Header.Get("Accept") != "text/html" {
		t.Fatal("Accept should be preserved")
	}
}

func TestSanitiseStage_StripsConnectionNominated(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	req.Header.Set("Connection", "X-Custom-Hop, X-Another")
	req.Header.Set("X-Custom-Hop", "value")
	req.Header.Set("X-Another", "value2")
	req.Header.Set("Accept", "text/html")

	rc := &RequestContext{Request: req}
	(&SanitiseStage{}).Execute(rc)

	if req.Header.Get("X-Custom-Hop") != "" {
		t.Fatal("Connection-nominated header X-Custom-Hop not stripped")
	}
	if req.Header.Get("X-Another") != "" {
		t.Fatal("Connection-nominated header X-Another not stripped")
	}
}

func TestSanitiseStage_StripsTrailers(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "https://example.com", nil)
	req.Trailer = http.Header{
		"Authorization":       {"Bearer smuggled"},
		"Proxy-Authorization": {"Basic smuggled"},
		"X-Safe-Trailer":      {"ok"},
	}

	rc := &RequestContext{Request: req}
	(&SanitiseStage{}).Execute(rc)

	if req.Trailer.Get("Authorization") != "" {
		t.Fatal("trailer Authorization not stripped")
	}
	if req.Trailer.Get("Proxy-Authorization") != "" {
		t.Fatal("trailer Proxy-Authorization not stripped")
	}
	if req.Trailer.Get("X-Safe-Trailer") != "ok" {
		t.Fatal("safe trailer should be preserved")
	}
}
