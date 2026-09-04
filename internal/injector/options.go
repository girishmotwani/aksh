package injector

import "time"

// InjectorOptions configures the sidecar injector.
type InjectorOptions struct {
	ProxyImage       string
	ReservedUID      int64
	ReservedGID      int64
	OptInLabelKey    string
	OptInLabelValue  string
	InjectionVersion string
	// RuntimeProfile carries the optional, environment-specific runtime settings
	// stamped into the injected aksh sidecar. Its zero value reproduces the
	// historical placeholder profile exactly, so existing deployments, golden
	// fixtures, and tests are unchanged when it is left unset.
	RuntimeProfile RuntimeProfile
}

// RuntimeProfile is the narrow, backward-compatible set of environment-specific
// runtime settings the injector stamps into the aksh sidecar so a
// controller-generated pod becomes a functional Aksh pod after injection.
//
// Every field is optional and typed (no free-form user-supplied env injection).
// A zero RuntimeProfile is the legacy profile: empty Entra placeholders, the
// default host cgroup mount, no DNS/bypass/local-cgroup env, emptyDir CA
// volumes, and no pod attribution env. When a field IS set, the canonical
// mutation stamps it and the canonical/validation predicates compare against it
// exactly (value-locked), so a tampered pod is still rejected fail-closed.
//
// All fields are comparable (strings/bools only, no slices/maps) so
// SidecarInjector remains == comparable.
type RuntimeProfile struct {
	// Entra startup identity. Each set value is stamped verbatim as the
	// corresponding AKSH_ENTRA_* env var and then value-locked by the canonical
	// predicate. Dummy-but-valid values are permitted when the policy carries no
	// real credentials. Unset falls back to the historical empty placeholder,
	// which the canonical predicate treats as presence-only (config-sourced).
	EntraTenantID  string
	EntraClientID  string
	EntraAuthority string

	// HostCgroupMount overrides the in-container path the proxy is told the host
	// cgroup2 root is bind-mounted at (AKSH_CAPTURE_HOST_CGROUP_MOUNT). Unset
	// keeps the default "/host/sys/fs/cgroup" (presence-only, per-node topology).
	// The hostcgroup volume/mount shape is unchanged; only the env value varies.
	HostCgroupMount string
	// LocalCgroupMount, when set, additionally emits AKSH_CAPTURE_LOCAL_CGROUP_MOUNT
	// (the proxy's own cgroup2 mount, preflight gate P3). Value-locked when set.
	LocalCgroupMount string

	// DNSServer, when set, emits AKSH_CAPTURE_DNS_SERVER as an exact "host:port"
	// address (value-locked). Validated at construction.
	DNSServer string
	// BypassCIDRs, when set, emits AKSH_CAPTURE_BYPASS_CIDRS verbatim (exact,
	// value-locked): a comma-separated CIDR-prefix list of destinations never
	// policed. Validated at construction; validation is only tightened here.
	BypassCIDRs string

	// CASecretName, when set, backs the ca-priv and ca-pub volumes with this
	// Secret instead of emptyDir: ca-priv projects the CA certificate and private
	// key, ca-pub the public certificate only. The three key names select which
	// Secret data keys map to the files the proxy reads.
	CASecretName    string
	CACertKey       string
	CAPrivateKeyKey string
	CAPublicCertKey string

	// PodAttribution, when true, adds the downward-API pod-triple and service
	// account env vars (AKSH_POD_NAMESPACE/NAME/UID, AKSH_AGENT_SERVICE_ACCOUNT)
	// used for audit attribution, matching the production e2e oracle. Off in the
	// zero profile so the legacy 16-var env is preserved.
	PodAttribution bool

	// StaticTokenSecretName, when set, mounts a Secret holding a static bearer
	// credential (e.g. an OpenAI API key) read-only into the aksh container ONLY,
	// at a fixed path, and stamps AKSH_STATIC_TOKEN_PATH so a policy credential
	// selector with provider "static" injects it as Authorization: Bearer <key>.
	// The Secret is never mounted into application containers, so the agent never
	// holds the real key. StaticTokenSecretKey selects which Secret data key maps
	// to the on-disk token file; both must be set together (validated at
	// construction). Unset preserves the legacy profile exactly.
	StaticTokenSecretName string
	StaticTokenSecretKey  string
}

// caFileName is the on-disk CA certificate filename the proxy reads from both
// AKSH_CA_PRIV_DIR and AKSH_CA_PUB_DIR (internal/pki caCertFile).
const caCertFileName = "ca-cert.pem"

// caKeyFileName is the on-disk CA private-key filename the proxy reads from
// AKSH_CA_PRIV_DIR (internal/pki privKeyFile).
const caKeyFileName = "ca-key.pem"

// Static bearer credential mount shape. When the runtime profile sets a static
// token Secret, the injector adds a read-only Secret volume mounted ONLY into
// the aksh container at staticTokenMountPath and stamps AKSH_STATIC_TOKEN_PATH
// = staticTokenMountPath + "/" + staticTokenFileName. These are fixed so the
// pod-side path is value-locked and cannot be steered by the workload.
const (
	staticTokenVolumeName = "aksh-static-token"
	staticTokenMountPath  = "/var/run/secrets/aksh-static"
	staticTokenFileName   = "token"
	staticTokenEnvVar     = "AKSH_STATIC_TOKEN_PATH"
)

// WebhookServerOptions configures the webhook server, its serving material, the
// service identity encoded into the serving certificate, and caBundle
// reconciliation targets.
type WebhookServerOptions struct {
	Addr                           string
	CertDir                        string
	ServiceName                    string
	ServiceNamespace               string
	MutatingWebhookConfiguration   string
	ValidatingWebhookConfiguration string
	CABundlePatchInterval          time.Duration
}
