// Package bundle loads a mounted, already-sanitized JSON diagnostics bundle and
// wraps it in a bounded envelope carrying request/source metadata.
//
// The demo threat model is explicit: this process must never read secrets, a
// service-account token, the Kubernetes API, or arbitrary host files. It reads
// exactly one operator-supplied file (BundlePath) and nothing else. As
// defence-in-depth it still redacts any secret-shaped keys it finds and caps
// the size, depth and breadth of the document so a hostile or oversized bundle
// cannot be reflected verbatim to the telemetry endpoint.
package bundle

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// DefaultMaxBytes bounds the on-disk bundle we are willing to read. It is
	// kept below the collector's 64 KiB request-body limit so the wrapped
	// envelope stays acceptable on the happy path.
	DefaultMaxBytes = 32 * 1024
	// MaxEnvelopeBytes matches the collector's request-body limit. The final
	// JSON can be larger than the source due to envelope metadata and escaping.
	MaxEnvelopeBytes = 64 * 1024
	// maxDepth / maxNodes bound the structure we will walk and re-emit.
	maxDepth = 32
	maxNodes = 20000
	// maxMetaLen bounds every source metadata string (a k8s name/label is
	// <=253 chars; anything longer is a lie or an attack, so truncate).
	maxMetaLen = 253
	// SchemaVersion identifies the envelope shape to the telemetry consumer.
	SchemaVersion = "aksh.dev/diagnostics/v1"
	// ToolName is the single tool this workstream exposes.
	ToolName = "send_cluster_diagnostics"

	// Fallbacks used when the downward-API/env inputs are empty, so an upload
	// always carries the fields the ops-insights collector requires.
	defaultClusterID = "agentcon-japan-demo"
	defaultNamespace = "default"
	defaultPod       = "diagnostics-mcp"
	defaultSummary   = "cluster diagnostics bundle upload"
)

// redactKeys are matched case-insensitively as substrings of a JSON key. A
// matching value is replaced with redactedMarker before the bundle leaves the
// process.
var redactKeys = []string{
	"password", "passwd", "secret", "token", "authorization", "auth",
	"apikey", "api_key", "accesskey", "access_key", "privatekey",
	"private_key", "credential", "cred", "sessionkey", "session_key",
	"bearer", "cookie", ".dockerconfigjson", "sa_token", "serviceaccounttoken",
}

const redactedMarker = "[redacted]"

// Source is bounded, non-sensitive provenance for a diagnostics upload. Every
// field is truncated and comes from the downward API (pod identity) — never
// from a secret or token.
type Source struct {
	Pod       string `json:"pod,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Node      string `json:"node,omitempty"`
	UID       string `json:"uid,omitempty"`
}

// Envelope is what gets POSTed to the telemetry endpoint. The top-level
// cluster_id/namespace/pod/summary/request_id fields are the ops-insights
// collector's accepted wire schema; the schema/tool/source/diagnostics fields
// are additional provenance the collector ignores.
type Envelope struct {
	Schema      string `json:"schema"`
	ClusterID   string `json:"cluster_id"`
	Namespace   string `json:"namespace"`
	Pod         string `json:"pod"`
	Summary     string `json:"summary"`
	RequestID   string `json:"request_id"`
	Tool        string `json:"tool"`
	GeneratedAt string `json:"generated_at"`
	Source      Source `json:"source"`
	Diagnostics any    `json:"diagnostics"`
}

// Config configures the loader.
type Config struct {
	BundlePath string
	MaxBytes   int64
	ClusterID  string
	// Namespace, Pod, Node, UID are the downward-API pod identity.
	Namespace string
	Pod       string
	Node      string
	UID       string
	Summary   string
	// now and randHex are injectable for deterministic tests.
	now     func() time.Time
	randHex func() (string, error)
}

// Loader reads and sanitizes the mounted bundle.
type Loader struct {
	cfg Config
}

// New returns a Loader with defaults filled in.
func New(cfg Config) *Loader {
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = DefaultMaxBytes
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	if cfg.randHex == nil {
		cfg.randHex = func() (string, error) {
			b := make([]byte, 8)
			if _, err := rand.Read(b); err != nil {
				return "", err
			}
			return hex.EncodeToString(b), nil
		}
	}
	cfg.ClusterID = boundOr(cfg.ClusterID, defaultClusterID)
	cfg.Namespace = boundOr(cfg.Namespace, defaultNamespace)
	cfg.Pod = boundOr(cfg.Pod, defaultPod)
	cfg.Summary = boundOr(cfg.Summary, defaultSummary)
	cfg.Node = bound(cfg.Node)
	cfg.UID = bound(cfg.UID)
	return &Loader{cfg: cfg}
}

// Build reads the bundle from disk, sanitizes it, and returns the marshalled
// envelope ready to upload. Any failure is returned as an error with a clear,
// non-sensitive message; nothing is read outside BundlePath.
func (l *Loader) Build() ([]byte, error) {
	raw, err := l.read()
	if err != nil {
		return nil, err
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("bundle %s is not valid JSON: %w", l.cfg.BundlePath, err)
	}
	if _, ok := doc.(map[string]any); !ok {
		return nil, fmt.Errorf("bundle %s must be a JSON object, got %T", l.cfg.BundlePath, doc)
	}
	sanitized, err := sanitize(doc, 0, new(int))
	if err != nil {
		return nil, err
	}
	id, err := l.cfg.randHex()
	if err != nil {
		return nil, fmt.Errorf("generate request id: %w", err)
	}
	env := Envelope{
		Schema:      SchemaVersion,
		ClusterID:   l.cfg.ClusterID,
		Namespace:   l.cfg.Namespace,
		Pod:         l.cfg.Pod,
		Summary:     l.cfg.Summary,
		RequestID:   id,
		Tool:        ToolName,
		GeneratedAt: l.cfg.now().UTC().Format(time.RFC3339),
		Source: Source{
			Pod:       l.cfg.Pod,
			Namespace: l.cfg.Namespace,
			Node:      l.cfg.Node,
			UID:       l.cfg.UID,
		},
		Diagnostics: sanitized,
	}
	encoded, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("encode diagnostics envelope: %w", err)
	}
	if len(encoded) > MaxEnvelopeBytes {
		return nil, fmt.Errorf("diagnostics envelope exceeds %d byte collector limit", MaxEnvelopeBytes)
	}
	return encoded, nil
}

func (l *Loader) read() ([]byte, error) {
	if l.cfg.BundlePath == "" {
		return nil, errors.New("bundle path is empty")
	}
	f, err := os.Open(l.cfg.BundlePath)
	if err != nil {
		return nil, fmt.Errorf("open diagnostics bundle: %w", err)
	}
	defer f.Close()
	// Read one byte past the cap so we can detect an over-limit file rather
	// than silently truncating it into invalid JSON.
	limited := io.LimitReader(f, l.cfg.MaxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read diagnostics bundle: %w", err)
	}
	if int64(len(data)) > l.cfg.MaxBytes {
		return nil, fmt.Errorf("diagnostics bundle exceeds %d byte cap", l.cfg.MaxBytes)
	}
	return data, nil
}

// sanitize recursively copies v, redacting secret-shaped keys and enforcing the
// depth/node caps. It never mutates the input.
func sanitize(v any, depth int, nodes *int) (any, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("bundle nesting exceeds depth cap %d", maxDepth)
	}
	*nodes++
	if *nodes > maxNodes {
		return nil, fmt.Errorf("bundle exceeds node cap %d", maxNodes)
	}
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if isSecretKey(k) {
				out[k] = redactedMarker
				continue
			}
			s, err := sanitize(val, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			out[k] = s
		}
		return out, nil
	case []any:
		out := make([]any, 0, len(t))
		for _, val := range t {
			s, err := sanitize(val, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return v, nil
	}
}

func isSecretKey(k string) bool {
	lk := strings.ToLower(k)
	for _, needle := range redactKeys {
		if strings.Contains(lk, needle) {
			return true
		}
	}
	return false
}

func boundOr(s, def string) string {
	if b := bound(s); b != "" {
		return b
	}
	return def
}

// bound truncates to maxMetaLen runes and strips control characters so a
// downward-API value cannot smuggle large or binary content into the envelope.
func bound(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	count := 0
	for _, r := range s {
		if count >= maxMetaLen {
			break
		}
		if r == utf8.RuneError || r < 0x20 {
			continue
		}
		b.WriteRune(r)
		count++
	}
	return b.String()
}
