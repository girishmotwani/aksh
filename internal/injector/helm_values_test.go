package injector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// chartFile reads a file from the aksh-injector Helm chart relative to this
// package.
func chartFile(t *testing.T, rel string) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "deploy", "helm", "aksh-injector", rel)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read chart file %s: %v", rel, err)
	}
	return raw
}

// helmValues mirrors the runtimeProfile block of values.yaml so the test fails
// if a key is renamed or a default drifts away from the injector's expectations.
type helmValues struct {
	RuntimeProfile struct {
		Entra struct {
			TenantID  string `json:"tenantId"`
			ClientID  string `json:"clientId"`
			Authority string `json:"authority"`
		} `json:"entra"`
		Cgroup struct {
			HostMount  string `json:"hostMount"`
			LocalMount string `json:"localMount"`
		} `json:"cgroup"`
		Capture struct {
			DNSServer   string `json:"dnsServer"`
			BypassCIDRs string `json:"bypassCidrs"`
		} `json:"capture"`
		CA struct {
			SecretName    string `json:"secretName"`
			CertKey       string `json:"certKey"`
			PrivateKeyKey string `json:"privateKeyKey"`
			PublicCertKey string `json:"publicCertKey"`
		} `json:"ca"`
		StaticToken struct {
			SecretName string `json:"secretName"`
			SecretKey  string `json:"secretKey"`
		} `json:"staticToken"`
		PodAttribution bool `json:"podAttribution"`
	} `json:"runtimeProfile"`
}

func TestHelmValues_RuntimeProfileDefaults(t *testing.T) {
	var v helmValues
	if err := yaml.Unmarshal(chartFile(t, "values.yaml"), &v); err != nil {
		t.Fatalf("unmarshal values.yaml: %v", err)
	}
	rp := v.RuntimeProfile
	// Legacy-preserving defaults: everything empty except CA key names and
	// pod attribution, so a default install reproduces the placeholder profile
	// (emptyDir CA volumes, empty Entra, default cgroup mount).
	if rp.Entra.TenantID != "" || rp.Entra.ClientID != "" || rp.Entra.Authority != "" {
		t.Fatalf("entra defaults not empty: %#v", rp.Entra)
	}
	if rp.Cgroup.HostMount != "" || rp.Cgroup.LocalMount != "" {
		t.Fatalf("cgroup defaults not empty: %#v", rp.Cgroup)
	}
	if rp.Capture.DNSServer != "" || rp.Capture.BypassCIDRs != "" {
		t.Fatalf("capture defaults not empty: %#v", rp.Capture)
	}
	if rp.CA.SecretName != "" {
		t.Fatalf("ca.secretName default not empty: %q", rp.CA.SecretName)
	}
	if rp.CA.CertKey != "tls.crt" || rp.CA.PrivateKeyKey != "tls.key" || rp.CA.PublicCertKey != "tls.crt" {
		t.Fatalf("ca key defaults = %#v want tls.crt/tls.key/tls.crt", rp.CA)
	}
	if rp.StaticToken.SecretName != "" {
		t.Fatalf("staticToken.secretName default not empty: %q", rp.StaticToken.SecretName)
	}
	if rp.StaticToken.SecretKey != "token" {
		t.Fatalf("staticToken.secretKey default = %q want token", rp.StaticToken.SecretKey)
	}
	if !rp.PodAttribution {
		t.Fatal("podAttribution default should be true")
	}

	// The defaults must be accepted by the injector constructor and, because
	// they are all empty/legacy, must produce the zero-equivalent profile.
	opts := testOptions()
	opts.RuntimeProfile = RuntimeProfile{
		EntraTenantID:         rp.Entra.TenantID,
		EntraClientID:         rp.Entra.ClientID,
		EntraAuthority:        rp.Entra.Authority,
		HostCgroupMount:       rp.Cgroup.HostMount,
		LocalCgroupMount:      rp.Cgroup.LocalMount,
		DNSServer:             rp.Capture.DNSServer,
		BypassCIDRs:           rp.Capture.BypassCIDRs,
		CASecretName:          rp.CA.SecretName,
		CACertKey:             rp.CA.CertKey,
		CAPrivateKeyKey:       rp.CA.PrivateKeyKey,
		CAPublicCertKey:       rp.CA.PublicCertKey,
		StaticTokenSecretName: rp.StaticToken.SecretName,
		StaticTokenSecretKey:  rp.StaticToken.SecretKey,
		PodAttribution:        rp.PodAttribution,
	}
	if _, err := NewSidecarInjector(opts); err != nil {
		t.Fatalf("chart default profile rejected by constructor: %v", err)
	}
}

// TestHelmDeployment_WiresEveryProfileEnv asserts the deployment template wires
// each AKSH_INJECTOR_* profile env the injector reads, so a values change is not
// silently dropped on the way to the container.
func TestHelmDeployment_WiresEveryProfileEnv(t *testing.T) {
	tmpl := string(chartFile(t, filepath.Join("templates", "deployment.yaml")))
	envNames := []string{
		"AKSH_INJECTOR_ENTRA_TENANT_ID",
		"AKSH_INJECTOR_ENTRA_CLIENT_ID",
		"AKSH_INJECTOR_ENTRA_AUTHORITY",
		"AKSH_INJECTOR_HOST_CGROUP_MOUNT",
		"AKSH_INJECTOR_LOCAL_CGROUP_MOUNT",
		"AKSH_INJECTOR_CAPTURE_DNS_SERVER",
		"AKSH_INJECTOR_CAPTURE_BYPASS_CIDRS",
		"AKSH_INJECTOR_CA_SECRET_NAME",
		"AKSH_INJECTOR_CA_CERT_KEY",
		"AKSH_INJECTOR_CA_PRIVATE_KEY_KEY",
		"AKSH_INJECTOR_CA_PUBLIC_CERT_KEY",
		"AKSH_INJECTOR_STATIC_TOKEN_SECRET_NAME",
		"AKSH_INJECTOR_STATIC_TOKEN_SECRET_KEY",
		"AKSH_INJECTOR_POD_ATTRIBUTION",
	}
	for _, name := range envNames {
		if !strings.Contains(tmpl, name) {
			t.Fatalf("deployment template does not wire %s", name)
		}
	}
	valuePaths := []string{
		".Values.runtimeProfile.entra.tenantId",
		".Values.runtimeProfile.cgroup.hostMount",
		".Values.runtimeProfile.capture.bypassCidrs",
		".Values.runtimeProfile.ca.secretName",
		".Values.runtimeProfile.staticToken.secretName",
		".Values.runtimeProfile.podAttribution",
	}
	for _, p := range valuePaths {
		if !strings.Contains(tmpl, p) {
			t.Fatalf("deployment template does not reference %s", p)
		}
	}
}
