package config

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/dataplane/capture"
)

// akshEnvKeys is the full set of AKSH_* override keys plus the config-file
// selector, used by tests to establish a deterministic empty environment.
var akshEnvKeys = []string{
	"AKSH_CONFIG_FILE",
	"AKSH_LISTENER_ADDRESS",
	"AKSH_CA_PRIV_DIR",
	"AKSH_CA_PUB_DIR",
	"AKSH_POLICY_NAMESPACE",
	"AKSH_POLICY_MAX_STALENESS",
	"AKSH_SA_TOKEN_PATH",
	"AKSH_ENTRA_TENANT_ID",
	"AKSH_ENTRA_CLIENT_ID",
	"AKSH_ENTRA_AUTHORITY",
	"AKSH_STATIC_TOKEN_PATH",
	"AKSH_AUDIT_SINK",
}

func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range akshEnvKeys {
		t.Setenv(k, "")
	}
}

func emptyGetenv(string) string { return "" }

func mapGetenv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// validConfig returns a Config that passes Validate; individual tests mutate a
// single field to exercise one validation rule.
func validConfig() Config {
	return Config{
		Listener: ListenerConfig{Address: "127.0.0.1:15001"},
		CA:       CAConfig{PrivDir: "/var/run/aksh/ca-priv", PubDir: "/var/run/aksh/ca-pub"},
		Policy:   PolicyConfig{Namespace: "aksh-system", MaxStaleness: 45 * time.Second},
		Token: TokenConfig{
			SATokenPath: "/var/run/secrets/aksh/token",
			Entra: EntraConfig{
				TenantID:  "tenant-1",
				ClientID:  "client-1",
				Authority: "https://login.microsoftonline.com",
			},
		},
		Audit:   AuditConfig{Sink: "stdout"},
		Capture: validCaptureConfig(),
	}
}

// validCaptureConfig returns a CaptureConfig mirroring capture.DefaultOptions()
// with the mandatory PodPath set, so it passes both Config.Validate and the
// downstream capture.Options.Validate.
func validCaptureConfig() CaptureConfig {
	d := capture.DefaultOptions()
	return CaptureConfig{
		PodPath:             "/host/sys/fs/cgroup/pod",
		HostCgroupMount:     d.HostCgroupMount,
		LocalCgroupMount:    d.LocalCgroupMount,
		ProcCgroupPath:      d.ProcCgroupPath,
		ProxyUID:            d.ProxyUID,
		ProxyGID:            d.ProxyGID,
		CaptureIPv6:         d.CaptureIPv6,
		MountBPFFS:          d.MountBPFFS,
		BlockNonTCP:         d.BlockNonTCP,
		RunProbe:            d.RunProbe,
		AllowUnsafeStartup:  d.AllowUnsafeStartup,
		AttachCheckInterval: d.AttachCheckInterval,
		PinLinks:            d.PinLinks,
		PinRoot:             d.PinRoot,
		PinRootPrivate:      d.PinRootPrivate,
		MapEntries:          d.MapEntries,
		DestMaxAge:          d.DestMaxAge,
		MinKernel:           d.MinKernel,
	}
}

func writeFile(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(contents), 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}
	return p
}

// 1
func TestLoad_DefaultsOnly_ReturnsLoopbackAndFailClosedDefaults(t *testing.T) {
	clearEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Listener.Address != "127.0.0.1:15001" {
		t.Errorf("Listener.Address = %q, want 127.0.0.1:15001", cfg.Listener.Address)
	}
	if cfg.Policy.MaxStaleness != 45*time.Second {
		t.Errorf("Policy.MaxStaleness = %v, want 45s", cfg.Policy.MaxStaleness)
	}
	if cfg.Audit.Sink != "stdout" {
		t.Errorf("Audit.Sink = %q, want stdout", cfg.Audit.Sink)
	}
	if cfg.Token.Entra.Authority != "https://login.microsoftonline.com" {
		t.Errorf("Authority = %q, want https default", cfg.Token.Entra.Authority)
	}
	if cfg.Token.SATokenPath != "/var/run/secrets/aksh/token" {
		t.Errorf("SATokenPath = %q, want default", cfg.Token.SATokenPath)
	}
	if cfg.Token.Static.Path != "" {
		t.Errorf("Token.Static.Path = %q, want empty by default (no static provider)", cfg.Token.Static.Path)
	}
	if cfg.CA.PrivDir != "/var/run/aksh/ca-priv" {
		t.Errorf("CA.PrivDir = %q, want default", cfg.CA.PrivDir)
	}
	if cfg.CA.PubDir != "/var/run/aksh/ca-pub" {
		t.Errorf("CA.PubDir = %q, want default", cfg.CA.PubDir)
	}
}

// 2
func TestLoadFrom_FileValues_OverrideDefaults(t *testing.T) {
	path := writeFile(t, `
ca:
  privDir: /custom/priv
  pubDir: /custom/pub
policy:
  namespace: my-namespace
token:
  saTokenPath: /custom/token
  entra:
    authority: https://login.example.gov
audit:
  sink: file:///var/log/aksh
`)
	cfg, err := LoadFrom(path, emptyGetenv)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if cfg.CA.PrivDir != "/custom/priv" || cfg.CA.PubDir != "/custom/pub" {
		t.Errorf("CA dirs = %q,%q", cfg.CA.PrivDir, cfg.CA.PubDir)
	}
	if cfg.Policy.Namespace != "my-namespace" {
		t.Errorf("Namespace = %q", cfg.Policy.Namespace)
	}
	if cfg.Token.SATokenPath != "/custom/token" {
		t.Errorf("SATokenPath = %q", cfg.Token.SATokenPath)
	}
	if cfg.Token.Entra.Authority != "https://login.example.gov" {
		t.Errorf("Authority = %q", cfg.Token.Entra.Authority)
	}
	if cfg.Audit.Sink != "file:///var/log/aksh" {
		t.Errorf("Audit.Sink = %q", cfg.Audit.Sink)
	}
	// Untouched fields keep defaults.
	if cfg.Listener.Address != "127.0.0.1:15001" {
		t.Errorf("Listener.Address = %q, want default", cfg.Listener.Address)
	}
}

// TestLoadFrom_StaticTokenPath_FileAndEnv verifies the optional static bearer
// credential path is read from YAML (token.static.path) and overridden by the
// AKSH_STATIC_TOKEN_PATH env var, mirroring every other Token field's
// precedence. No token literal is ever accepted — only a file path.
func TestLoadFrom_StaticTokenPath_FileAndEnv(t *testing.T) {
	path := writeFile(t, `
policy:
  namespace: ns
token:
  static:
    path: /file/static-token
`)
	cfg, err := LoadFrom(path, emptyGetenv)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if cfg.Token.Static.Path != "/file/static-token" {
		t.Fatalf("Static.Path from file = %q, want /file/static-token", cfg.Token.Static.Path)
	}

	env := mapGetenv(map[string]string{"AKSH_STATIC_TOKEN_PATH": "/env/static-token"})
	cfg, err = LoadFrom(path, env)
	if err != nil {
		t.Fatalf("LoadFrom() with env error = %v", err)
	}
	if cfg.Token.Static.Path != "/env/static-token" {
		t.Fatalf("Static.Path from env = %q, want /env/static-token", cfg.Token.Static.Path)
	}
}

// 3
func TestLoadFrom_EnvValues_OverrideFileValues(t *testing.T) {
	path := writeFile(t, `
listener:
  address: 127.0.0.1:9
policy:
  namespace: file-ns
  maxStaleness: 90s
token:
  saTokenPath: /file/token
  entra:
    tenantID: file-tenant
    clientID: file-client
    authority: https://file.example
audit:
  sink: file-sink
`)
	env := mapGetenv(map[string]string{
		"AKSH_LISTENER_ADDRESS":     "127.0.0.1:15001",
		"AKSH_POLICY_NAMESPACE":     "env-ns",
		"AKSH_POLICY_MAX_STALENESS": "30s",
		"AKSH_SA_TOKEN_PATH":        "/env/token",
		"AKSH_ENTRA_TENANT_ID":      "env-tenant",
		"AKSH_ENTRA_CLIENT_ID":      "env-client",
		"AKSH_ENTRA_AUTHORITY":      "https://env.example",
		"AKSH_AUDIT_SINK":           "env-sink",
	})
	cfg, err := LoadFrom(path, env)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if cfg.Listener.Address != "127.0.0.1:15001" {
		t.Errorf("Listener.Address = %q, want env", cfg.Listener.Address)
	}
	if cfg.Policy.Namespace != "env-ns" {
		t.Errorf("Namespace = %q, want env", cfg.Policy.Namespace)
	}
	if cfg.Policy.MaxStaleness != 30*time.Second {
		t.Errorf("MaxStaleness = %v, want 30s", cfg.Policy.MaxStaleness)
	}
	if cfg.Token.SATokenPath != "/env/token" {
		t.Errorf("SATokenPath = %q, want env", cfg.Token.SATokenPath)
	}
	if cfg.Token.Entra.TenantID != "env-tenant" {
		t.Errorf("TenantID = %q, want env", cfg.Token.Entra.TenantID)
	}
	if cfg.Token.Entra.ClientID != "env-client" {
		t.Errorf("ClientID = %q, want env", cfg.Token.Entra.ClientID)
	}
	if cfg.Token.Entra.Authority != "https://env.example" {
		t.Errorf("Authority = %q, want env", cfg.Token.Entra.Authority)
	}
	if cfg.Audit.Sink != "env-sink" {
		t.Errorf("Audit.Sink = %q, want env", cfg.Audit.Sink)
	}
}

// 4
func TestLoadFrom_UnknownConfigKey_ReturnsError(t *testing.T) {
	path := writeFile(t, "token:\n  disableValidation: true\n")
	if _, err := LoadFrom(path, emptyGetenv); err == nil {
		t.Fatal("LoadFrom() error = nil, want error for unknown key")
	}
}

// 5
func TestValidate_MissingTenantID_ReturnsError(t *testing.T) {
	c := validConfig()
	c.Token.Entra.TenantID = ""
	if err := c.Validate(); err == nil {
		t.Fatal("Validate() = nil, want error")
	}
}

// 6
func TestValidate_MissingClientID_ReturnsError(t *testing.T) {
	c := validConfig()
	c.Token.Entra.ClientID = ""
	if err := c.Validate(); err == nil {
		t.Fatal("Validate() = nil, want error")
	}
}

// 7
func TestValidate_MissingSATokenPath_ReturnsError(t *testing.T) {
	c := validConfig()
	c.Token.SATokenPath = ""
	if err := c.Validate(); err == nil {
		t.Fatal("Validate() = nil, want error")
	}
}

// 8
func TestValidate_NonHTTPSAuthority_ReturnsError(t *testing.T) {
	for _, a := range []string{"http://login.example", "login.example", "ftp://login.example"} {
		c := validConfig()
		c.Token.Entra.Authority = a
		if err := c.Validate(); err == nil {
			t.Errorf("Validate() authority=%q = nil, want error", a)
		}
	}
}

// 9
func TestValidate_NonLoopbackListenerAddress_ReturnsError(t *testing.T) {
	for _, a := range []string{"0.0.0.0:15001", "10.0.0.5:15001", "example.com:15001", "localhost:15001", "[::1]:15001"} {
		c := validConfig()
		c.Listener.Address = a
		if err := c.Validate(); err == nil {
			t.Errorf("Validate() address=%q = nil, want error", a)
		}
	}
}

// 10
func TestValidate_LoopbackPortZero_ReturnsNil(t *testing.T) {
	c := validConfig()
	c.Listener.Address = "127.0.0.1:0"
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

// 11
func TestValidate_NegativeMaxStaleness_ReturnsError(t *testing.T) {
	// Zero now defaults to 45s (Slice S3, UT #54); only a negative staleness
	// remains invalid and fail-closed.
	for _, d := range []time.Duration{-1 * time.Second, -5 * time.Minute} {
		c := validConfig()
		c.Policy.MaxStaleness = d
		if err := c.Validate(); err == nil {
			t.Errorf("Validate() staleness=%v = nil, want error", d)
		}
	}
}

// 12
func TestLoadFrom_DefaultFileEnvPrecedence_ProducesDeterministicConfig(t *testing.T) {
	path := writeFile(t, "policy:\n  namespace: file-ns\n")
	env := mapGetenv(map[string]string{"AKSH_AUDIT_SINK": "env-sink"})
	a, err := LoadFrom(path, env)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	b, err := LoadFrom(path, env)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("LoadFrom not deterministic:\n a=%+v\n b=%+v", a, b)
	}
}

// 13
func TestLoadFrom_DurationEnvOverride_ParsesGoDuration(t *testing.T) {
	env := mapGetenv(map[string]string{"AKSH_POLICY_MAX_STALENESS": "30s"})
	cfg, err := LoadFrom("", env)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if cfg.Policy.MaxStaleness != 30*time.Second {
		t.Fatalf("MaxStaleness = %v, want 30s", cfg.Policy.MaxStaleness)
	}
}

// 14
func TestLoadFrom_InvalidDuration_ReturnsBoundedError(t *testing.T) {
	env := mapGetenv(map[string]string{
		"AKSH_POLICY_MAX_STALENESS": "never",
		"AKSH_ENTRA_CLIENT_ID":      "secret-client-value",
	})
	_, err := LoadFrom("", env)
	if err == nil {
		t.Fatal("LoadFrom() = nil, want bounded error")
	}
	if !strings.Contains(err.Error(), "AKSH_POLICY_MAX_STALENESS") {
		t.Errorf("error %q does not name the field", err)
	}
	if strings.Contains(err.Error(), "secret-client-value") {
		t.Errorf("error %q dumped an unrelated env value", err)
	}
}

// 15
func TestLoadFrom_WhitespaceRequiredFields_TrimmedAndRejected(t *testing.T) {
	env := mapGetenv(map[string]string{
		"AKSH_ENTRA_TENANT_ID":  "   ",
		"AKSH_ENTRA_CLIENT_ID":  "\t",
		"AKSH_POLICY_NAMESPACE": "  ",
		"AKSH_SA_TOKEN_PATH":    " ",
	})
	cfg, err := LoadFrom("", env)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if cfg.Token.Entra.TenantID != "" {
		t.Errorf("TenantID = %q, want trimmed empty", cfg.Token.Entra.TenantID)
	}
	if cfg.Token.Entra.ClientID != "" {
		t.Errorf("ClientID = %q, want trimmed empty", cfg.Token.Entra.ClientID)
	}
	if cfg.Policy.Namespace != "" {
		t.Errorf("Namespace = %q, want trimmed empty", cfg.Policy.Namespace)
	}
	if cfg.Token.SATokenPath != "" {
		t.Errorf("SATokenPath = %q, want trimmed empty", cfg.Token.SATokenPath)
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() = nil, want error for empty required fields")
	}
}

// 16
func TestValidate_AuditSinkEmpty_ReturnsError(t *testing.T) {
	c := validConfig()
	c.Audit.Sink = ""
	if err := c.Validate(); err == nil {
		t.Fatal("Validate() = nil, want error")
	}
}

// 17
func TestLoad_UsesProcessEnvironment_DelegatesToLoadFrom(t *testing.T) {
	clearEnv(t)
	t.Setenv("AKSH_LISTENER_ADDRESS", "127.0.0.1:20000")
	t.Setenv("AKSH_AUDIT_SINK", "env-sink")
	got, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.Listener.Address != "127.0.0.1:20000" {
		t.Errorf("Listener.Address = %q, want env value", got.Listener.Address)
	}
	want, err := LoadFrom("", os.Getenv)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Load() = %+v, want %+v via LoadFrom", got, want)
	}
}

// TestLoadFrom_DefaultsCaptureProcCgroupPath verifies the Go startup cgroup
// derivation has a proc cgroup path even though the injector never sets
// AKSH_CAPTURE_PROC_CGROUP_PATH: config seeds the default so
// derivePodCgroupCandidate does not fail closed at startup.
func TestLoadFrom_DefaultsCaptureProcCgroupPath(t *testing.T) {
	cfg, err := LoadFrom("", func(string) string { return "" })
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if cfg.Capture.ProcCgroupPath != "/proc/self/cgroup" {
		t.Fatalf("Capture.ProcCgroupPath = %q, want default %q", cfg.Capture.ProcCgroupPath, "/proc/self/cgroup")
	}
}

// fakePreBindRuntime models a startup path that validates config before
// constructing/binding the listener.
type fakePreBindRuntime struct {
	bindCalls int
}

func (f *fakePreBindRuntime) start(c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	f.bindCalls++
	return nil
}

// 18
func TestValidate_RuntimePreBindFailure_ReturnsBeforeBind(t *testing.T) {
	c := validConfig()
	c.Token.Entra.TenantID = ""
	f := &fakePreBindRuntime{}
	if err := f.start(c); err == nil {
		t.Fatal("start() = nil, want validation error")
	}
	if f.bindCalls != 0 {
		t.Fatalf("bindCalls = %d, want 0", f.bindCalls)
	}
}

// 19
func TestLoadFrom_ConfigLoadedLog_EmitsBoundedSourceSummary(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	env := mapGetenv(map[string]string{
		"AKSH_ENTRA_TENANT_ID": "super-secret-tenant",
		"AKSH_SA_TOKEN_PATH":   "/super/secret/token/path",
	})
	if _, err := loadFromWithLogger("", env, log); err != nil {
		t.Fatalf("loadFromWithLogger() error = %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "aksh-proxy: config loaded") {
		t.Errorf("log %q missing config-loaded message", out)
	}
	if strings.Contains(out, "super-secret-tenant") {
		t.Errorf("log %q leaked secret tenant value", out)
	}
	if strings.Contains(out, "/super/secret/token/path") {
		t.Errorf("log %q leaked SA token path value", out)
	}
}

// 20
func TestValidate_ErrorMessage_DoesNotIncludeSecretMaterial(t *testing.T) {
	c := validConfig()
	c.Token.Entra.TenantID = "super-secret-tenant-value"
	c.Token.SATokenPath = ""
	err := c.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error")
	}
	if strings.Contains(err.Error(), "super-secret-tenant-value") {
		t.Errorf("error %q leaked secret material", err)
	}
}

// 21
func TestLoadFrom_DisableTLSVerifyKey_ReturnsError(t *testing.T) {
	path := writeFile(t, "token:\n  entra:\n    disableTLSVerify: true\n")
	if _, err := LoadFrom(path, emptyGetenv); err == nil {
		t.Fatal("LoadFrom() = nil, want error for disableTLSVerify")
	}
}

// 22
func TestLoadFrom_DisableAuditKey_ReturnsError(t *testing.T) {
	path := writeFile(t, "audit:\n  disabled: true\n")
	if _, err := LoadFrom(path, emptyGetenv); err == nil {
		t.Fatal("LoadFrom() = nil, want error for audit.disabled")
	}
}

// 23
func TestLoadFrom_DisableDefaultDenyKey_ReturnsError(t *testing.T) {
	path := writeFile(t, "policy:\n  defaultAllow: true\n")
	if _, err := LoadFrom(path, emptyGetenv); err == nil {
		t.Fatal("LoadFrom() = nil, want error for policy.defaultAllow")
	}
}

// 24
func TestLoadFrom_DisableStalenessKey_ReturnsError(t *testing.T) {
	path := writeFile(t, "policy:\n  disableStalenessFailClosed: true\n")
	if _, err := LoadFrom(path, emptyGetenv); err == nil {
		t.Fatal("LoadFrom() = nil, want error for policy.disableStalenessFailClosed")
	}
}

// ---------------------------------------------------------------------------
// Slice S3 (Gap 6) — Group B: config expansion. Tests #27-#55.
// CaptureOptionsFromConfig mapping (#27-#35) and Config.Validate (#36-#55).
// ---------------------------------------------------------------------------

// 27
func TestCaptureOptionsFromConfig_ExplicitCtx_SetsOptionsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := validConfig()
	opts := CaptureOptionsFromConfig(ctx, c, audit.NopMetricsRecorder{})
	if opts.Context != ctx {
		t.Fatalf("Options.Context = %p, want the passed daemon ctx %p", opts.Context, ctx)
	}
}

// 28
func TestCaptureOptionsFromConfig_AllFieldsPopulated_MapsEveryFieldGroup(t *testing.T) {
	c := validConfig()
	c.Listener.Address = "127.0.0.1:15001"
	c.Capture = CaptureConfig{
		PodPath:             "/host/sys/fs/cgroup/pod-xyz",
		HostCgroupMount:     "/host/cg",
		LocalCgroupMount:    "/local/cg",
		ProcCgroupPath:      "/proc/self/other",
		ProxyUID:            2000,
		ProxyGID:            2001,
		DNSServer:           "10.0.0.10:53",
		CaptureIPv6:         false,
		MountBPFFS:          true,
		BlockNonTCP:         true,
		RunProbe:            true,
		AllowUnsafeStartup:  false,
		AttachCheckInterval: 45 * time.Second,
		PinLinks:            true,
		PinRoot:             "/custom/bpf",
		PinRootPrivate:      true,
		MapEntries:          2048,
		DestMaxAge:          30 * time.Second,
		MinKernel:           capture.KernelVersion{Major: 6, Minor: 1},
	}
	opts := CaptureOptionsFromConfig(context.Background(), c, audit.NopMetricsRecorder{})

	if opts.PodPath != "/host/sys/fs/cgroup/pod-xyz" {
		t.Errorf("PodPath = %q", opts.PodPath)
	}
	if opts.HostCgroupMount != "/host/cg" || opts.LocalCgroupMount != "/local/cg" || opts.ProcCgroupPath != "/proc/self/other" {
		t.Errorf("mount fields = %q/%q/%q", opts.HostCgroupMount, opts.LocalCgroupMount, opts.ProcCgroupPath)
	}
	if opts.ProxyUID != 2000 || opts.ProxyGID != 2001 {
		t.Errorf("ProxyUID/GID = %d/%d, want 2000/2001", opts.ProxyUID, opts.ProxyGID)
	}
	if !opts.MountBPFFS || !opts.BlockNonTCP || !opts.RunProbe || opts.AllowUnsafeStartup || !opts.PinLinks || !opts.PinRootPrivate || opts.CaptureIPv6 {
		t.Errorf("bool group mismatch: %+v", opts)
	}
	if opts.AttachCheckInterval != 45*time.Second {
		t.Errorf("AttachCheckInterval = %v, want 45s", opts.AttachCheckInterval)
	}
	if opts.PinRoot != "/custom/bpf" {
		t.Errorf("PinRoot = %q", opts.PinRoot)
	}
	if opts.MapEntries != 2048 {
		t.Errorf("MapEntries = %d, want 2048", opts.MapEntries)
	}
	if opts.DestMaxAge != 30*time.Second {
		t.Errorf("DestMaxAge = %v, want 30s", opts.DestMaxAge)
	}
	if opts.MinKernel != (capture.KernelVersion{Major: 6, Minor: 1}) {
		t.Errorf("MinKernel = %v, want 6.1", opts.MinKernel)
	}
}

// 29
func TestCaptureOptionsFromConfig_ZeroValueNumericFields_ApplyDefaultOptionsDefaults(t *testing.T) {
	c := validConfig()
	c.Capture = CaptureConfig{PodPath: "/host/sys/fs/cgroup/pod"}
	opts := CaptureOptionsFromConfig(context.Background(), c, audit.NopMetricsRecorder{})
	d := capture.DefaultOptions()
	if opts.AttachCheckInterval != d.AttachCheckInterval {
		t.Errorf("AttachCheckInterval = %v, want default %v", opts.AttachCheckInterval, d.AttachCheckInterval)
	}
	if opts.MapEntries != d.MapEntries {
		t.Errorf("MapEntries = %d, want default %d", opts.MapEntries, d.MapEntries)
	}
	if opts.DestMaxAge != d.DestMaxAge {
		t.Errorf("DestMaxAge = %v, want default %v", opts.DestMaxAge, d.DestMaxAge)
	}
}

// 30
func TestCaptureOptionsFromConfig_InjectsMetricsRecorder_NotFromYAML(t *testing.T) {
	m := audit.NopMetricsRecorder{}
	opts := CaptureOptionsFromConfig(context.Background(), validConfig(), m)
	if opts.Metrics != audit.MetricsRecorder(m) {
		t.Fatalf("Options.Metrics = %v, want the injected recorder", opts.Metrics)
	}
}

// 31
func TestCaptureOptionsFromConfig_NilMetricsRecorder_ProducesOptionsRejectedByValidate(t *testing.T) {
	opts := CaptureOptionsFromConfig(context.Background(), validConfig(), nil)
	if opts.Metrics != nil {
		t.Fatalf("Options.Metrics = %v, want nil (mapping must not substitute a noop)", opts.Metrics)
	}
	if err := opts.Validate(); !errors.Is(err, capture.ErrMissingMetrics) {
		t.Fatalf("Options.Validate() = %v, want ErrMissingMetrics", err)
	}
}

// 32
func TestCaptureOptionsFromConfig_ListenerAddrParsed_SetsListenAddr(t *testing.T) {
	c := validConfig()
	c.Listener.Address = "127.0.0.1:15001"
	opts := CaptureOptionsFromConfig(context.Background(), c, audit.NopMetricsRecorder{})
	want := netip.MustParseAddrPort("127.0.0.1:15001")
	if opts.ListenerAddr != want {
		t.Fatalf("Options.ListenerAddr = %v, want %v", opts.ListenerAddr, want)
	}
}

// 33
func TestCaptureOptionsFromConfig_DNSServerSet_ParsesHostPort(t *testing.T) {
	c := validConfig()
	c.Capture.DNSServer = "10.0.0.10:53"
	opts := CaptureOptionsFromConfig(context.Background(), c, audit.NopMetricsRecorder{})
	want := netip.MustParseAddrPort("10.0.0.10:53")
	if opts.DNSServer != want {
		t.Fatalf("Options.DNSServer = %v, want %v", opts.DNSServer, want)
	}
}

// 34
func TestCaptureOptionsFromConfig_DNSServerUnset_LeavesDNSDisabled(t *testing.T) {
	c := validConfig()
	c.Capture.DNSServer = ""
	opts := CaptureOptionsFromConfig(context.Background(), c, audit.NopMetricsRecorder{})
	if opts.DNSServer.IsValid() {
		t.Fatalf("Options.DNSServer = %v, want zero (DNS disabled)", opts.DNSServer)
	}
}

// 35
func TestCaptureOptionsFromConfig_ProxyUIDGIDUnset_DefaultTo1774(t *testing.T) {
	c := validConfig()
	c.Capture = CaptureConfig{PodPath: "/host/sys/fs/cgroup/pod"}
	opts := CaptureOptionsFromConfig(context.Background(), c, audit.NopMetricsRecorder{})
	if opts.ProxyUID != 1774 || opts.ProxyGID != 1774 {
		t.Fatalf("ProxyUID/GID = %d/%d, want 1774/1774", opts.ProxyUID, opts.ProxyGID)
	}
}

// 36
func TestValidate_EmptyCapturePodPath_ReturnsErrMissingPodPath(t *testing.T) {
	c := validConfig()
	c.Capture.PodPath = ""
	if err := c.Validate(); !errors.Is(err, ErrMissingPodPath) {
		t.Fatalf("Validate() = %v, want ErrMissingPodPath", err)
	}
}

// 37
func TestValidate_ZeroValueCapturePodPath_ReturnsErrMissingPodPath(t *testing.T) {
	c := validConfig()
	c.Capture = CaptureConfig{} // zero value: PodPath unset
	if err := c.Validate(); !errors.Is(err, ErrMissingPodPath) {
		t.Fatalf("Validate() = %v, want ErrMissingPodPath", err)
	}
}

// 38
func TestValidate_CaptureProxyUIDZero_ReturnsErrInvalidProxyUID(t *testing.T) {
	c := validConfig()
	c.Capture.ProxyUID = 0
	if err := c.Validate(); !errors.Is(err, ErrInvalidProxyUID) {
		t.Fatalf("Validate() = %v, want ErrInvalidProxyUID", err)
	}
}

// 39
func TestValidate_CaptureIPv6True_ReturnsErrIPv6Unsupported(t *testing.T) {
	c := validConfig()
	c.Capture.CaptureIPv6 = true
	if err := c.Validate(); !errors.Is(err, ErrIPv6Unsupported) {
		t.Fatalf("Validate() = %v, want ErrIPv6Unsupported", err)
	}
}

// 40
func TestValidate_CaptureAttachCheckIntervalOutOfRange_ReturnsErrInvalidInterval(t *testing.T) {
	for _, d := range []time.Duration{5 * time.Second, 61 * time.Second} {
		c := validConfig()
		c.Capture.AttachCheckInterval = d
		if err := c.Validate(); !errors.Is(err, ErrInvalidInterval) {
			t.Fatalf("Validate() interval=%v = %v, want ErrInvalidInterval", d, err)
		}
	}
}

// 41
func TestValidate_CaptureMapEntriesOutOfRange_ReturnsErrInvalidMapEntries(t *testing.T) {
	for _, n := range []uint32{1023, 65537} {
		c := validConfig()
		c.Capture.MapEntries = n
		if err := c.Validate(); !errors.Is(err, ErrInvalidMapEntries) {
			t.Fatalf("Validate() mapEntries=%d = %v, want ErrInvalidMapEntries", n, err)
		}
	}
}

// TestValidate_CaptureDNSServerUnparseable_ReturnsErrInvalidDNSServer pins the
// fail-fast behaviour added with the sock_create DNS relaxation. An unparseable
// value used to be dropped silently by CaptureOptionsFromConfig, which left the
// DEV-01 exception disabled and every name lookup in the pod failing with no
// explanation.
func TestValidate_CaptureDNSServerUnparseable_ReturnsErrInvalidDNSServer(t *testing.T) {
	for _, s := range []string{"10.96.0.10", "not-an-address", "10.96.0.10:", ":53", "10.96.0.10:notaport"} {
		c := validConfig()
		c.Capture.DNSServer = s
		if err := c.Validate(); !errors.Is(err, ErrInvalidDNSServer) {
			t.Fatalf("Validate() dnsServer=%q = %v, want ErrInvalidDNSServer", s, err)
		}
	}
}

// TestValidate_CaptureDNSServerValidOrEmpty_Accepted is the positive control:
// unset must stay valid (the exception is simply disabled) and a well-formed
// host:port must pass.
func TestValidate_CaptureDNSServerValidOrEmpty_Accepted(t *testing.T) {
	for _, s := range []string{"", "  ", "10.96.0.10:53", "127.0.0.1:5353"} {
		c := validConfig()
		c.Capture.DNSServer = s
		if err := c.Validate(); err != nil {
			t.Fatalf("Validate() dnsServer=%q = %v, want nil", s, err)
		}
	}
}

// 42
func TestValidate_CaptureDestMaxAgeOutOfRange_ReturnsErrInvalidDestMaxAge(t *testing.T) {
	for _, d := range []time.Duration{500 * time.Millisecond, 121 * time.Second} {
		c := validConfig()
		c.Capture.DestMaxAge = d
		if err := c.Validate(); !errors.Is(err, ErrInvalidDestMaxAge) {
			t.Fatalf("Validate() destMaxAge=%v = %v, want ErrInvalidDestMaxAge", d, err)
		}
	}
}

// 43
func TestValidate_CapturePinLinksTrueWithoutPinRoot_ReturnsErrMissingPinRoot(t *testing.T) {
	c := validConfig()
	c.Capture.PinLinks = true
	c.Capture.PinRoot = ""
	if err := c.Validate(); !errors.Is(err, ErrMissingPinRoot) {
		t.Fatalf("Validate() = %v, want ErrMissingPinRoot", err)
	}
}

// 44
func TestValidate_CaptureBlockNonTCPFalseWithoutAllowUnsafeStartup_ReturnsErrRequiresUnsafeStartup(t *testing.T) {
	c := validConfig()
	c.Capture.BlockNonTCP = false
	c.Capture.AllowUnsafeStartup = false
	if err := c.Validate(); !errors.Is(err, ErrRequiresUnsafeStartup) {
		t.Fatalf("Validate() = %v, want ErrRequiresUnsafeStartup", err)
	}
}

// 45
func TestValidate_CaptureRunProbeFalseWithoutAllowUnsafeStartup_ReturnsErrRequiresUnsafeStartup(t *testing.T) {
	c := validConfig()
	c.Capture.RunProbe = false
	c.Capture.AllowUnsafeStartup = false
	if err := c.Validate(); !errors.Is(err, ErrRequiresUnsafeStartup) {
		t.Fatalf("Validate() = %v, want ErrRequiresUnsafeStartup", err)
	}
}

// 46
func TestValidate_CaptureDefaults_PassOptionsValidate(t *testing.T) {
	c := validConfig()
	c.Capture = validCaptureConfig() // defaults from DefaultOptions() + PodPath
	if err := c.Validate(); err != nil {
		t.Fatalf("Config.Validate() = %v, want nil for capture defaults", err)
	}
	opts := CaptureOptionsFromConfig(context.Background(), c, audit.NopMetricsRecorder{})
	if err := opts.Validate(); err != nil {
		t.Fatalf("downstream Options.Validate() = %v, want nil for capture defaults", err)
	}
}

// 47
func TestValidate_EmptyControlPlaneAddress_Accepted(t *testing.T) {
	c := validConfig()
	c.ControlPlane.Address = ""
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil for empty ControlPlane.Address", err)
	}
}

// 48
func TestValidate_LoopbackControlPlaneHost_AcceptedByValidateNoLoopbackCheck(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "0.0.0.0", "10.1.2.3"} {
		c := validConfig()
		c.ControlPlane.Address = host
		if err := c.Validate(); err != nil {
			t.Fatalf("Validate() host=%q = %v, want nil (no loopback check at config time)", host, err)
		}
	}
}

// 49
func TestValidate_ControlPlanePortZero_DefaultsToPort15020(t *testing.T) {
	c := validConfig()
	c.ControlPlane.Port = 0
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil for zero port", err)
	}
	if got := c.ControlPlane.EffectivePort(); got != 15020 {
		t.Fatalf("effectivePort() = %d, want default 15020", got)
	}
	c.ControlPlane.Port = 9443
	if got := c.ControlPlane.EffectivePort(); got != 9443 {
		t.Fatalf("effectivePort() = %d, want explicit override 9443", got)
	}
}

// 50
func TestValidate_EmptyPolicyNamespace_ReturnsErrMissingNamespace(t *testing.T) {
	c := validConfig()
	c.Policy.Namespace = ""
	if err := c.Validate(); !errors.Is(err, ErrMissingNamespace) {
		t.Fatalf("Validate() = %v, want ErrMissingNamespace", err)
	}
}

// 51
func TestValidate_ZeroValuePolicyNamespace_ReturnsErrMissingNamespace(t *testing.T) {
	c := validConfig()
	c.Policy = PolicyConfig{} // zero value: Namespace unset
	if err := c.Validate(); !errors.Is(err, ErrMissingNamespace) {
		t.Fatalf("Validate() = %v, want ErrMissingNamespace", err)
	}
}

// 52
func TestValidate_PolicyFirstSnapshotTimeoutZero_DefaultsTo30s(t *testing.T) {
	c := validConfig()
	c.Policy.FirstSnapshotTimeout = 0
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil for zero FirstSnapshotTimeout", err)
	}
	if got := c.Policy.EffectiveFirstSnapshotTimeout(); got != 30*time.Second {
		t.Fatalf("effectiveFirstSnapshotTimeout() = %v, want 30s", got)
	}
}

// 53
func TestValidate_PolicyResyncZero_PassthroughReserved(t *testing.T) {
	c := validConfig()
	c.Policy.Resync = 0
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil (Resync==0 is reserved, unactioned)", err)
	}
}

// 54
func TestValidate_PolicyMaxStalenessZero_DefaultsTo45s(t *testing.T) {
	c := validConfig()
	c.Policy.MaxStaleness = 0
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil for zero MaxStaleness (defaulted)", err)
	}
	if got := c.Policy.EffectiveMaxStaleness(); got != 45*time.Second {
		t.Fatalf("effectiveMaxStaleness() = %v, want 45s", got)
	}
}

// 55
func TestValidate_PolicyDefaults_Pass(t *testing.T) {
	c := validConfig()
	c.Policy = PolicyConfig{Namespace: "aksh-system"} // valid namespace, default (zero) timeouts
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil for policy defaults", err)
	}
}
