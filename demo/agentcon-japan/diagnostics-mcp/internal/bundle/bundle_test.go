package bundle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeBundle(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func fixedLoader(t *testing.T, path string, cfg Config, max int64) *Loader {
	t.Helper()
	cfg.BundlePath = path
	cfg.MaxBytes = max
	l := New(cfg)
	l.cfg.now = func() time.Time { return time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC) }
	l.cfg.randHex = func() (string, error) { return "deadbeefcafef00d", nil }
	return l
}

func TestBuild_EnvelopeAndMetadata(t *testing.T) {
	p := writeBundle(t, `{"cluster":{"name":"demo"},"pods":41}`)
	l := fixedLoader(t, p, Config{ClusterID: "c1", Pod: "diag-0", Namespace: "kagent", Node: "n1", UID: "u-1"}, 0)

	out, err := l.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var env Envelope
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if env.Schema != SchemaVersion {
		t.Errorf("schema = %q", env.Schema)
	}
	// Top-level collector wire fields must be present.
	if env.ClusterID != "c1" || env.Namespace != "kagent" || env.Pod != "diag-0" {
		t.Errorf("collector fields = %+v", env)
	}
	if env.Tool != ToolName || env.RequestID != "deadbeefcafef00d" {
		t.Errorf("request meta: tool=%q id=%q", env.Tool, env.RequestID)
	}
	if env.GeneratedAt != "2026-09-03T12:00:00Z" {
		t.Errorf("generatedAt = %q", env.GeneratedAt)
	}
	if env.Source.Pod != "diag-0" || env.Source.Namespace != "kagent" {
		t.Errorf("source = %+v", env.Source)
	}
	diag, ok := env.Diagnostics.(map[string]any)
	if !ok {
		t.Fatalf("diagnostics type %T", env.Diagnostics)
	}
	if _, ok := diag["cluster"]; !ok {
		t.Errorf("diagnostics missing cluster: %v", diag)
	}
}

func TestBuild_FillsCollectorDefaults(t *testing.T) {
	p := writeBundle(t, `{"a":1}`)
	l := fixedLoader(t, p, Config{}, 0)
	out, err := l.Build()
	if err != nil {
		t.Fatal(err)
	}
	var env Envelope
	_ = json.Unmarshal(out, &env)
	if env.ClusterID != defaultClusterID || env.Namespace != defaultNamespace || env.Pod != defaultPod {
		t.Errorf("defaults not applied: %+v", env)
	}
	if env.Summary != defaultSummary {
		t.Errorf("summary = %q", env.Summary)
	}
}

func TestBuild_RedactsSecretShapedKeys(t *testing.T) {
	p := writeBundle(t, `{
		"ok":"keep",
		"api_key":"AKIA-leak",
		"authToken":"leak",
		"nested":{"password":"leak","kept":"keep"},
		"list":[{"secretValue":"leak","fine":"keep"}]
	}`)
	l := fixedLoader(t, p, Config{}, 0)
	out, err := l.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	s := string(out)
	if strings.Contains(s, "leak") {
		t.Fatalf("redaction failed, leaked value present: %s", s)
	}
	if !strings.Contains(s, redactedMarker) {
		t.Errorf("expected redaction marker in %s", s)
	}
	if !strings.Contains(s, `"kept":"keep"`) || !strings.Contains(s, `"fine":"keep"`) {
		t.Errorf("non-secret values were dropped: %s", s)
	}
}

func TestBuild_BoundsSourceMetadata(t *testing.T) {
	p := writeBundle(t, `{"a":1}`)
	long := strings.Repeat("x", 500) + "\x00\x07bad"
	l := fixedLoader(t, p, Config{Pod: long}, 0)
	out, err := l.Build()
	if err != nil {
		t.Fatal(err)
	}
	var env Envelope
	_ = json.Unmarshal(out, &env)
	if len(env.Source.Pod) > maxMetaLen {
		t.Errorf("pod not truncated: len=%d", len(env.Source.Pod))
	}
	if strings.ContainsAny(env.Source.Pod, "\x00\x07") {
		t.Errorf("control chars not stripped: %q", env.Source.Pod)
	}
}

func TestBuild_RejectsOversizeBundle(t *testing.T) {
	p := writeBundle(t, `{"blob":"`+strings.Repeat("a", 2048)+`"}`)
	l := fixedLoader(t, p, Config{}, 512)
	if _, err := l.Build(); err == nil || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("expected size cap error, got %v", err)
	}

}

func TestBuild_RejectsEnvelopeExpansionBeyondCollectorLimit(t *testing.T) {
	p := writeBundle(t, `{"blob":"`+strings.Repeat("<", 12*1024)+`"}`)
	l := fixedLoader(t, p, Config{}, DefaultMaxBytes)
	if _, err := l.Build(); err == nil || !strings.Contains(err.Error(), "collector limit") {
		t.Fatalf("expected final envelope limit error, got %v", err)
	}
}

func TestBuild_RejectsNonObject(t *testing.T) {
	p := writeBundle(t, `[1,2,3]`)
	l := fixedLoader(t, p, Config{}, 0)
	if _, err := l.Build(); err == nil || !strings.Contains(err.Error(), "must be a JSON object") {
		t.Fatalf("expected object error, got %v", err)
	}
}

func TestBuild_RejectsInvalidJSON(t *testing.T) {
	p := writeBundle(t, `{not json`)
	l := fixedLoader(t, p, Config{}, 0)
	if _, err := l.Build(); err == nil || !strings.Contains(err.Error(), "valid JSON") {
		t.Fatalf("expected JSON error, got %v", err)
	}
}

func TestBuild_MissingFile(t *testing.T) {
	l := fixedLoader(t, filepath.Join(t.TempDir(), "nope.json"), Config{}, 0)
	if _, err := l.Build(); err == nil {
		t.Fatal("expected error for missing bundle")
	}
}
