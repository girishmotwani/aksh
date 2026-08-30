package config

import (
	"testing"
)

// TestLoadFrom_PodIdentityEnv_Parsed proves the S5 Downward API pod attribution
// and service account are read from the AKSH_POD_* / AKSH_AGENT_SERVICE_ACCOUNT
// environment into PodConfig. Without this plumbing every audit record's pod
// block is empty in production (issue #62).
func TestLoadFrom_PodIdentityEnv_Parsed(t *testing.T) {
	getenv := mapGetenv(map[string]string{
		"AKSH_POD_NAMESPACE":         "aksh-e2e",
		"AKSH_POD_NAME":              "aksh-e2e-abc123",
		"AKSH_POD_UID":               "11111111-2222-3333-4444-555555555555",
		"AKSH_AGENT_SERVICE_ACCOUNT": "aksh-proxy",
	})

	cfg, err := LoadFrom("", getenv)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}

	if cfg.Pod.Namespace != "aksh-e2e" {
		t.Errorf("Pod.Namespace = %q, want %q", cfg.Pod.Namespace, "aksh-e2e")
	}
	if cfg.Pod.Name != "aksh-e2e-abc123" {
		t.Errorf("Pod.Name = %q, want %q", cfg.Pod.Name, "aksh-e2e-abc123")
	}
	if cfg.Pod.UID != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("Pod.UID = %q, want %q", cfg.Pod.UID, "11111111-2222-3333-4444-555555555555")
	}
	if cfg.Pod.ServiceAccount != "aksh-proxy" {
		t.Errorf("Pod.ServiceAccount = %q, want %q", cfg.Pod.ServiceAccount, "aksh-proxy")
	}
}

// TestLoadFrom_PodIdentityEnv_Normalised proves surrounding whitespace is
// trimmed like every other string field, so a stray newline from a Downward API
// projection cannot leak into an audit record.
func TestLoadFrom_PodIdentityEnv_Normalised(t *testing.T) {
	getenv := mapGetenv(map[string]string{
		"AKSH_POD_NAMESPACE":         "  aksh-e2e\n",
		"AKSH_POD_NAME":              "\taksh-e2e-abc123 ",
		"AKSH_POD_UID":               " uid-1 ",
		"AKSH_AGENT_SERVICE_ACCOUNT": "  aksh-proxy  ",
	})

	cfg, err := LoadFrom("", getenv)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}

	if cfg.Pod.Namespace != "aksh-e2e" {
		t.Errorf("Pod.Namespace = %q, want %q", cfg.Pod.Namespace, "aksh-e2e")
	}
	if cfg.Pod.Name != "aksh-e2e-abc123" {
		t.Errorf("Pod.Name = %q, want %q", cfg.Pod.Name, "aksh-e2e-abc123")
	}
	if cfg.Pod.UID != "uid-1" {
		t.Errorf("Pod.UID = %q, want %q", cfg.Pod.UID, "uid-1")
	}
	if cfg.Pod.ServiceAccount != "aksh-proxy" {
		t.Errorf("Pod.ServiceAccount = %q, want %q", cfg.Pod.ServiceAccount, "aksh-proxy")
	}
}

// TestLoadFrom_PodIdentityEnv_AbsentIsEmpty proves the fields are attribution
// only: absent Downward API env leaves them empty and does not error, so a
// non-Kubernetes run still loads.
func TestLoadFrom_PodIdentityEnv_AbsentIsEmpty(t *testing.T) {
	cfg, err := LoadFrom("", emptyGetenv)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if cfg.Pod != (PodConfig{}) {
		t.Errorf("Pod = %+v, want zero value", cfg.Pod)
	}
}

// TestLoadFrom_PodLabelsPath_DefaultAndOverride proves the policy pod-labels
// file has the downward-API default and is overridable from the environment.
// The path feeds AkshPolicy selector matching, so an unset value would fail
// startup closed rather than silently widen egress (#35).
func TestLoadFrom_PodLabelsPath_DefaultsToDownwardAPIMount(t *testing.T) {
	cfg, err := LoadFrom("", mapGetenv(map[string]string{}))
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if cfg.Policy.PodLabelsPath != "/etc/aksh/podinfo/labels" {
		t.Errorf("Policy.PodLabelsPath = %q, want /etc/aksh/podinfo/labels", cfg.Policy.PodLabelsPath)
	}
}

func TestLoadFrom_PodLabelsPathEnv_OverridesAndTrims(t *testing.T) {
	getenv := mapGetenv(map[string]string{"AKSH_POLICY_POD_LABELS_PATH": "  /custom/labels\n"})
	cfg, err := LoadFrom("", getenv)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if cfg.Policy.PodLabelsPath != "/custom/labels" {
		t.Errorf("Policy.PodLabelsPath = %q, want /custom/labels", cfg.Policy.PodLabelsPath)
	}
}
