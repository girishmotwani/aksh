package config

import (
	"strings"
	"testing"
	"time"
)

// captureYAML is a full capture: + controlPlane: + extended policy: document
// exercising every YAML-surfaced field of the SI-S3-1 loader plumbing.
const captureYAML = `
policy:
  namespace: aksh-system
  resync: 5m
  firstSnapshotTimeout: 20s
token:
  entra:
    tenantID: tenant-1
    clientID: client-1
capture:
  podPath: /host/sys/fs/cgroup/pod-abc
  hostCgroupMount: /host/sys/fs/cgroup
  localCgroupMount: /sys/fs/cgroup
  procCgroupPath: /proc/self/cgroup
  proxyUID: 1774
  proxyGID: 1775
  dnsServer: 10.0.0.10:53
  captureIPv6: false
  mountBPFFS: true
  blockNonTCP: true
  runProbe: true
  allowUnsafeStartup: false
  attachCheckInterval: 45s
  pinLinks: true
  pinRoot: /sys/fs/bpf
  pinRootPrivate: true
  mapEntries: 32768
  destMaxAge: 20s
controlPlane:
  address: 10.1.2.3
  port: 16000
`

// SI-S3-1: a full capture:/controlPlane:/policy YAML file loads into the
// expected Config, proving the loader now reads the Slice-3 struct surface.
func TestLoad_CaptureYAMLRoundTrip(t *testing.T) {
	path := writeFile(t, captureYAML)
	cfg, err := LoadFrom(path, emptyGetenv)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	c := cfg.Capture
	if c.PodPath != "/host/sys/fs/cgroup/pod-abc" {
		t.Errorf("PodPath = %q", c.PodPath)
	}
	if c.HostCgroupMount != "/host/sys/fs/cgroup" {
		t.Errorf("HostCgroupMount = %q", c.HostCgroupMount)
	}
	if c.LocalCgroupMount != "/sys/fs/cgroup" {
		t.Errorf("LocalCgroupMount = %q", c.LocalCgroupMount)
	}
	if c.ProxyUID != 1774 || c.ProxyGID != 1775 {
		t.Errorf("ProxyUID/GID = %d/%d, want 1774/1775", c.ProxyUID, c.ProxyGID)
	}
	if c.DNSServer != "10.0.0.10:53" {
		t.Errorf("DNSServer = %q", c.DNSServer)
	}
	if !c.MountBPFFS || !c.PinLinks || !c.PinRootPrivate {
		t.Errorf("bool fields = %+v, want MountBPFFS/PinLinks/PinRootPrivate true", c)
	}
	if c.AttachCheckInterval != 45*time.Second {
		t.Errorf("AttachCheckInterval = %v, want 45s", c.AttachCheckInterval)
	}
	if c.DestMaxAge != 20*time.Second {
		t.Errorf("DestMaxAge = %v, want 20s", c.DestMaxAge)
	}
	if c.MapEntries != 32768 {
		t.Errorf("MapEntries = %d, want 32768", c.MapEntries)
	}
	if cfg.ControlPlane.Address != "10.1.2.3" || cfg.ControlPlane.Port != 16000 {
		t.Errorf("ControlPlane = %+v, want {10.1.2.3 16000}", cfg.ControlPlane)
	}
	if cfg.Policy.Resync != 5*time.Minute {
		t.Errorf("Policy.Resync = %v, want 5m", cfg.Policy.Resync)
	}
	if cfg.Policy.FirstSnapshotTimeout != 20*time.Second {
		t.Errorf("Policy.FirstSnapshotTimeout = %v, want 20s", cfg.Policy.FirstSnapshotTimeout)
	}
}

// SI-S3-1: representative AKSH_CAPTURE_*/AKSH_CONTROLPLANE_*/AKSH_POLICY_*
// overrides applied through the injected getenv populate the Config.
func TestLoad_CaptureEnvRoundTrip(t *testing.T) {
	env := mapGetenv(map[string]string{
		"AKSH_CAPTURE_POD_PATH":              "/host/sys/fs/cgroup/env-pod",
		"AKSH_CAPTURE_PROXY_UID":             "2000",
		"AKSH_CAPTURE_MAP_ENTRIES":           "4096",
		"AKSH_CAPTURE_MOUNT_BPFFS":           "true",
		"AKSH_CAPTURE_ATTACH_CHECK_INTERVAL": "50s",
		"AKSH_CAPTURE_DEST_MAX_AGE":          "10s",
		"AKSH_CONTROLPLANE_ADDRESS":          "10.9.9.9",
		"AKSH_CONTROLPLANE_PORT":             "17000",
		"AKSH_POLICY_RESYNC":                 "2m",
		"AKSH_POLICY_FIRST_SNAPSHOT_TIMEOUT": "15s",
	})
	cfg, err := LoadFrom("", env)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if cfg.Capture.PodPath != "/host/sys/fs/cgroup/env-pod" {
		t.Errorf("PodPath = %q", cfg.Capture.PodPath)
	}
	if cfg.Capture.ProxyUID != 2000 {
		t.Errorf("ProxyUID = %d, want 2000", cfg.Capture.ProxyUID)
	}
	if cfg.Capture.MapEntries != 4096 {
		t.Errorf("MapEntries = %d, want 4096", cfg.Capture.MapEntries)
	}
	if !cfg.Capture.MountBPFFS {
		t.Errorf("MountBPFFS = false, want true")
	}
	if cfg.Capture.AttachCheckInterval != 50*time.Second {
		t.Errorf("AttachCheckInterval = %v, want 50s", cfg.Capture.AttachCheckInterval)
	}
	if cfg.Capture.DestMaxAge != 10*time.Second {
		t.Errorf("DestMaxAge = %v, want 10s", cfg.Capture.DestMaxAge)
	}
	if cfg.ControlPlane.Address != "10.9.9.9" || cfg.ControlPlane.Port != 17000 {
		t.Errorf("ControlPlane = %+v, want {10.9.9.9 17000}", cfg.ControlPlane)
	}
	if cfg.Policy.Resync != 2*time.Minute {
		t.Errorf("Policy.Resync = %v, want 2m", cfg.Policy.Resync)
	}
	if cfg.Policy.FirstSnapshotTimeout != 15*time.Second {
		t.Errorf("Policy.FirstSnapshotTimeout = %v, want 15s", cfg.Policy.FirstSnapshotTimeout)
	}
}

// SI-S3-1: env overrides YAML for a capture field (precedence defaults->file->env).
func TestLoad_CaptureEnvOverridesYAML(t *testing.T) {
	path := writeFile(t, captureYAML)
	env := mapGetenv(map[string]string{
		"AKSH_CAPTURE_POD_PATH":  "/host/sys/fs/cgroup/env-wins",
		"AKSH_CONTROLPLANE_PORT": "19000",
	})
	cfg, err := LoadFrom(path, env)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if cfg.Capture.PodPath != "/host/sys/fs/cgroup/env-wins" {
		t.Errorf("PodPath = %q, want env override", cfg.Capture.PodPath)
	}
	if cfg.ControlPlane.Port != 19000 {
		t.Errorf("ControlPlane.Port = %d, want env override 19000", cfg.ControlPlane.Port)
	}
	// A field only present in YAML is preserved.
	if cfg.Capture.MapEntries != 32768 {
		t.Errorf("MapEntries = %d, want YAML value 32768", cfg.Capture.MapEntries)
	}
}

// SI-S3-1 crux: LoadFrom now yields a Config whose mandatory Capture.PodPath is
// populated end-to-end, so Validate() passes.
func TestLoad_PopulatesMandatoryPodPath_PassesValidate(t *testing.T) {
	path := writeFile(t, `
policy:
  namespace: aksh-system
token:
  saTokenPath: /var/run/secrets/aksh/token
  entra:
    tenantID: tenant-1
    clientID: client-1
    authority: https://login.microsoftonline.com
audit:
  sink: stdout
capture:
  podPath: /host/sys/fs/cgroup/pod-abc
  proxyUID: 1774
  blockNonTCP: true
  runProbe: true
`)
	cfg, err := LoadFrom(path, emptyGetenv)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if cfg.Capture.PodPath == "" {
		t.Fatal("Capture.PodPath is empty; loader did not surface it")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil (PodPath must be populatable end-to-end)", err)
	}
}

// SI-S3-1: strict decode still rejects an unknown key under capture:.
func TestLoadFrom_UnknownCaptureKey_ReturnsError(t *testing.T) {
	path := writeFile(t, "capture:\n  disableEbpf: true\n")
	_, err := LoadFrom(path, emptyGetenv)
	if err == nil {
		t.Fatal("LoadFrom() = nil, want error for unknown capture key")
	}
	if !strings.Contains(err.Error(), "disableEbpf") {
		t.Errorf("error %q should name the unknown key disableEbpf (proves strict decode, not an unrelated failure)", err)
	}
}

// SI-S3-1: strict decode must reject a `capture.minKernel` key — MinKernel is a
// security floor that must NOT be lowerable via config.
func TestLoadFrom_MinKernelNotSurfaceable_RejectedByStrictDecode(t *testing.T) {
	path := writeFile(t, "capture:\n  minKernel: \"4.0\"\n")
	_, err := LoadFrom(path, emptyGetenv)
	if err == nil {
		t.Fatal("LoadFrom() = nil, want strict-decode rejection of capture.minKernel (security floor must not be a knob)")
	}
	if !strings.Contains(err.Error(), "minKernel") {
		t.Errorf("error %q should name the rejected unknown key minKernel", err)
	}
}

// SI-S3-1: config must NOT read POD_IP; ControlPlane.Address stays empty by
// default so S5 wire-time reconciliation owns POD_IP resolution.
func TestLoad_ControlPlaneAddressEmptyByDefault_IgnoresPodIP(t *testing.T) {
	env := mapGetenv(map[string]string{
		"POD_IP":                "10.5.5.5",
		"AKSH_POLICY_NAMESPACE": "aksh-system",
	})
	cfg, err := LoadFrom("", env)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if cfg.ControlPlane.Address != "" {
		t.Errorf("ControlPlane.Address = %q, want empty (config must not read POD_IP; S5 owns it)", cfg.ControlPlane.Address)
	}
}

// SI-S3-1: negative durations/ports on the newly operator-surfaced fields must
// be rejected by Validate with a bounded error rather than silently accepted.
func TestValidate_NegativeSurfacedNumerics_Rejected(t *testing.T) {
	base := func() Config {
		return Config{
			Listener:     ListenerConfig{Address: "127.0.0.1:15001"},
			CA:           CAConfig{PrivDir: "/p", PubDir: "/q"},
			Policy:       PolicyConfig{Namespace: "aksh-system"},
			Token:        TokenConfig{SATokenPath: "/t", Entra: EntraConfig{TenantID: "a", ClientID: "b", Authority: "https://login.microsoftonline.com"}},
			Audit:        AuditConfig{Sink: "stdout"},
			Capture:      CaptureConfig{PodPath: "/pod", ProxyUID: 1774, BlockNonTCP: true, RunProbe: true},
			ControlPlane: ControlPlaneConfig{Address: "10.0.0.1"},
		}
	}
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"negative resync", func(c *Config) { c.Policy.Resync = -1 * time.Second }, "Policy.Resync"},
		{"negative firstSnapshotTimeout", func(c *Config) { c.Policy.FirstSnapshotTimeout = -1 * time.Second }, "Policy.FirstSnapshotTimeout"},
		{"negative control-plane port", func(c *Config) { c.ControlPlane.Port = -1 }, "ControlPlane.Port"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("Validate() = nil, want rejection of %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q should name %s", err, tc.want)
			}
		})
	}
}

// SI-S3-1: an invalid capture duration in YAML yields a bounded error naming
// the field and not dumping values.
func TestLoadFrom_InvalidCaptureDuration_ReturnsBoundedError(t *testing.T) {
	path := writeFile(t, "capture:\n  attachCheckInterval: never\n")
	_, err := LoadFrom(path, emptyGetenv)
	if err == nil {
		t.Fatal("LoadFrom() = nil, want bounded error")
	}
	if !strings.Contains(err.Error(), "capture.attachCheckInterval") {
		t.Errorf("error %q does not name the field", err)
	}
}

// SI-S3-1: an invalid numeric capture env yields a bounded error naming the
// offending variable without leaking unrelated secret env values.
func TestLoadFrom_InvalidCaptureNumericEnv_ReturnsBoundedError(t *testing.T) {
	env := mapGetenv(map[string]string{
		"AKSH_CAPTURE_MAP_ENTRIES": "notanumber",
		"AKSH_ENTRA_CLIENT_ID":     "secret-client-value",
	})
	_, err := LoadFrom("", env)
	if err == nil {
		t.Fatal("LoadFrom() = nil, want bounded error")
	}
	if !strings.Contains(err.Error(), "AKSH_CAPTURE_MAP_ENTRIES") {
		t.Errorf("error %q does not name the variable", err)
	}
	if strings.Contains(err.Error(), "secret-client-value") {
		t.Errorf("error %q leaked an unrelated env value", err)
	}
}
