// Package config loads and validates the aksh-proxy runtime configuration.
//
// Precedence is defaults -> YAML file -> AKSH_* process environment. Unknown
// YAML keys are rejected (strict decode) so no invariant-weakening knob such
// as disabling TLS verification, audit, default-deny, or staleness fail-closed
// can ever be silently accepted.
package config

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/dataplane/capture"
	yaml "go.yaml.in/yaml/v2"
)

// Config is the fully resolved aksh-proxy configuration.
type Config struct {
	Listener     ListenerConfig
	CA           CAConfig
	Policy       PolicyConfig
	Token        TokenConfig
	Audit        AuditConfig
	Capture      CaptureConfig
	ControlPlane ControlPlaneConfig
	Pod          PodConfig
}

// ListenerConfig holds the data-plane bind address.
type ListenerConfig struct{ Address string }

// CAConfig holds the private and public CA material directories.
type CAConfig struct{ PrivDir, PubDir string }

// PolicyConfig holds the policy namespace and deny-all staleness threshold.
type PolicyConfig struct {
	Namespace            string
	MaxStaleness         time.Duration
	Resync               time.Duration
	FirstSnapshotTimeout time.Duration
	// PodLabelsPath is the downward-API labels file holding this pod's own
	// labels. Unlike PodConfig, which is attribution-only, this value is an
	// authorization input: it decides which AkshPolicy selectors match this
	// pod. Startup fails closed if the file cannot be read (#35).
	PodLabelsPath string
}

// CaptureConfig is the YAML-surfaced subset of capture.Options. It mirrors
// every capture.Options field except Metrics and Context, which are injected by
// CaptureOptionsFromConfig and are never YAML-expressible, and ListenerAddr,
// which is sourced from the top-level Listener.Address (single source of truth,
// UT #32). DNSServer is a "host:port" string here (parsed in the mapping,
// UT #33/#34); every other field mirrors its capture.Options counterpart. Field
// defaults come from capture.DefaultOptions() and are applied in the mapping;
// PodPath is mandatory with no default.
type CaptureConfig struct {
	PodPath          string
	HostCgroupMount  string
	LocalCgroupMount string
	ProcCgroupPath   string
	ProxyUID         uint32
	ProxyGID         uint32
	DNSServer        string
	// BypassCIDRs is a comma-separated list of IPv4 prefixes that are never
	// captured and therefore never policed (parsed in the mapping). It exists
	// so a pod can reach its own in-cluster control plane, which aksh would
	// otherwise capture and reject as plaintext. Empty is the default.
	BypassCIDRs         string
	CaptureIPv6         bool
	MountBPFFS          bool
	BlockNonTCP         bool
	RunProbe            bool
	AllowUnsafeStartup  bool
	AttachCheckInterval time.Duration
	PinLinks            bool
	PinRoot             string
	PinRootPrivate      bool
	MapEntries          uint32
	DestMaxAge          time.Duration
	MinKernel           capture.KernelVersion
}

// ControlPlaneConfig holds the control-plane bind host and port. Address is a
// bind HOST only (no port); wire-time reconciliation resolves an empty host to
// the pod IP and rejects loopback (S5/Group D #80/#81). Config.Validate
// deliberately performs no loopback check here (single-stage ownership).
type ControlPlaneConfig struct {
	Address string
	Port    int
}

// PodConfig holds the S5 Downward API pod attribution and the workload service
// account. These are per-process constants injected by Kubernetes (metadata
// namespace/name/uid and spec.serviceAccountName); the audit record stamps them
// so replicas sharing a ServiceAccount can still be told apart (ADR-S0-06).
// They are attribution-only: empty values degrade traceability but must not
// fail the proxy closed, so Validate does not require them.
type PodConfig struct {
	Namespace      string
	Name           string
	UID            string
	ServiceAccount string
}

// TokenConfig holds the projected SA token path and Entra WIF settings.
type TokenConfig struct {
	SATokenPath string
	Entra       EntraConfig
}

// EntraConfig holds the explicit Entra workload-identity-federation settings.
type EntraConfig struct{ TenantID, ClientID, Authority string }

// AuditConfig holds the rejection/decision sink; it cannot be disabled.
type AuditConfig struct{ Sink string }

// Capture/control-plane/policy defaulting and bounds. The bounds must equal the
// capture package bounds (capture keeps them unexported); MinKernel and mount
// defaults come from capture.DefaultOptions() at mapping time.
const (
	// defaultControlPlanePort must equal runtime.Port15020; config cannot import
	// runtime (runtime imports config, so importing it back would be a cycle).
	defaultControlPlanePort = 15020

	defaultFirstSnapshotTimeout = 30 * time.Second

	minAttachCheckInterval        = 10 * time.Second
	maxAttachCheckInterval        = 60 * time.Second
	minMapEntries          uint32 = 1024
	maxMapEntries          uint32 = 65536
	minDestMaxAge                 = 1 * time.Second
	maxDestMaxAge                 = 120 * time.Second
)

// Config-layer validation sentinels for the capture and policy surfaces.
// Messages are bounded field names only and never carry secret material.
var (
	ErrMissingPodPath        = errors.New("config: Capture.PodPath is required")
	ErrInvalidProxyUID       = errors.New("config: Capture.ProxyUID must not be zero")
	ErrIPv6Unsupported       = errors.New("config: Capture.CaptureIPv6 is unsupported")
	ErrInvalidInterval       = errors.New("config: Capture.AttachCheckInterval is outside [10s, 60s]")
	ErrInvalidMapEntries     = errors.New("config: Capture.MapEntries is outside [1024, 65536]")
	ErrInvalidDestMaxAge     = errors.New("config: Capture.DestMaxAge is outside [1s, 120s]")
	ErrMissingPinRoot        = errors.New("config: Capture.PinRoot is required when PinLinks is set")
	ErrInvalidDNSServer      = errors.New("config: Capture.DNSServer must be a host:port address")
	ErrInvalidBypassCIDRs    = errors.New("config: Capture.BypassCIDRs must be a comma-separated list of IPv4 prefixes of /8 or longer with no host bits set")
	ErrRequiresUnsafeStartup = errors.New("config: fail-open capture setting requires AllowUnsafeStartup")
	ErrMissingNamespace      = errors.New("config: Policy.Namespace is required")
)

const (
	defaultListenerAddress = "127.0.0.1:15001"
	defaultCAPrivDir       = "/var/run/aksh/ca-priv"
	defaultCAPubDir        = "/var/run/aksh/ca-pub"
	defaultMaxStaleness    = 45 * time.Second
	// defaultPodLabelsPath is the downward-API labels file mounted into the
	// sidecar. It is the only way to obtain the pod's whole label map, which
	// policy selector evaluation requires (#35).
	defaultPodLabelsPath = "/etc/aksh/podinfo/labels"
	defaultSATokenPath   = "/var/run/secrets/aksh/token"
	defaultAuthority     = "https://login.microsoftonline.com"
	defaultAuditSink     = "stdout"
	// defaultCaptureProcCgroupPath is the process cgroup file the Go startup
	// derivation reads to compute the pod cgroup candidate. The injector sets
	// only AKSH_CAPTURE_HOST_CGROUP_MOUNT, not this path, so it must default
	// here or derivePodCgroupCandidate would fail closed at startup.
	defaultCaptureProcCgroupPath = "/proc/self/cgroup"

	envConfigFile    = "AKSH_CONFIG_FILE"
	envListenerAddr  = "AKSH_LISTENER_ADDRESS"
	envCAPrivDir     = "AKSH_CA_PRIV_DIR"
	envCAPubDir      = "AKSH_CA_PUB_DIR"
	envNamespace     = "AKSH_POLICY_NAMESPACE"
	envPodLabelsPath = "AKSH_POLICY_POD_LABELS_PATH"
	envMaxStaleness  = "AKSH_POLICY_MAX_STALENESS"
	envResync        = "AKSH_POLICY_RESYNC"
	envFirstSnapshot = "AKSH_POLICY_FIRST_SNAPSHOT_TIMEOUT"
	envSATokenPath   = "AKSH_SA_TOKEN_PATH"
	envEntraTenantID = "AKSH_ENTRA_TENANT_ID"
	envEntraClientID = "AKSH_ENTRA_CLIENT_ID"
	envEntraAuthorit = "AKSH_ENTRA_AUTHORITY"
	envAuditSink     = "AKSH_AUDIT_SINK"

	// Pod attribution and service account are injected by the S5 Downward API
	// (metadata namespace/name/uid and spec.serviceAccountName). They feed the
	// audit record's pod/agent blocks so replicas sharing a ServiceAccount stay
	// distinguishable (ADR-S0-06). Attribution only — never used for authz.
	envPodNamespace      = "AKSH_POD_NAMESPACE"
	envPodName           = "AKSH_POD_NAME"
	envPodUID            = "AKSH_POD_UID"
	envAgentServiceAccnt = "AKSH_AGENT_SERVICE_ACCOUNT"

	envCapturePodPath             = "AKSH_CAPTURE_POD_PATH"
	envCaptureHostCgroupMount     = "AKSH_CAPTURE_HOST_CGROUP_MOUNT"
	envCaptureLocalCgroupMount    = "AKSH_CAPTURE_LOCAL_CGROUP_MOUNT"
	envCaptureProcCgroupPath      = "AKSH_CAPTURE_PROC_CGROUP_PATH"
	envCaptureProxyUID            = "AKSH_CAPTURE_PROXY_UID"
	envCaptureProxyGID            = "AKSH_CAPTURE_PROXY_GID"
	envCaptureDNSServer           = "AKSH_CAPTURE_DNS_SERVER"
	envCaptureBypassCIDRs         = "AKSH_CAPTURE_BYPASS_CIDRS"
	envCaptureIPv6                = "AKSH_CAPTURE_IPV6"
	envCaptureMountBPFFS          = "AKSH_CAPTURE_MOUNT_BPFFS"
	envCaptureBlockNonTCP         = "AKSH_CAPTURE_BLOCK_NON_TCP"
	envCaptureRunProbe            = "AKSH_CAPTURE_RUN_PROBE"
	envCaptureAllowUnsafeStartup  = "AKSH_CAPTURE_ALLOW_UNSAFE_STARTUP"
	envCaptureAttachCheckInterval = "AKSH_CAPTURE_ATTACH_CHECK_INTERVAL"
	envCapturePinLinks            = "AKSH_CAPTURE_PIN_LINKS"
	envCapturePinRoot             = "AKSH_CAPTURE_PIN_ROOT"
	envCapturePinRootPrivate      = "AKSH_CAPTURE_PIN_ROOT_PRIVATE"
	envCaptureMapEntries          = "AKSH_CAPTURE_MAP_ENTRIES"
	envCaptureDestMaxAge          = "AKSH_CAPTURE_DEST_MAX_AGE"

	// envControlPlaneAddress is an explicit bind-host override only. When it is
	// empty, config leaves ControlPlane.Address empty and S5 wire-time
	// reconciliation resolves the host from the downward-API POD_IP; config
	// never reads POD_IP itself (single-owner boundary).
	envControlPlaneAddress = "AKSH_CONTROLPLANE_ADDRESS"
	envControlPlanePort    = "AKSH_CONTROLPLANE_PORT"
)

// defaults returns the baseline Config before file and environment overlays.
func defaults() Config {
	return Config{
		Listener: ListenerConfig{Address: defaultListenerAddress},
		CA:       CAConfig{PrivDir: defaultCAPrivDir, PubDir: defaultCAPubDir},
		Policy:   PolicyConfig{MaxStaleness: defaultMaxStaleness, PodLabelsPath: defaultPodLabelsPath},
		Token: TokenConfig{
			SATokenPath: defaultSATokenPath,
			Entra:       EntraConfig{Authority: defaultAuthority},
		},
		Audit: AuditConfig{Sink: defaultAuditSink},
		// The Go startup cgroup derivation reads Capture.ProcCgroupPath; the
		// injector does not set AKSH_CAPTURE_PROC_CGROUP_PATH, so seed the
		// default here (env/YAML still override).
		Capture: CaptureConfig{ProcCgroupPath: defaultCaptureProcCgroupPath},
	}
}

// yamlConfig mirrors the accepted YAML schema with pointer fields so that an
// absent key leaves the corresponding default untouched. UnmarshalStrict on
// this type rejects any unknown key at any nesting level.
type yamlConfig struct {
	Listener *struct {
		Address *string `yaml:"address"`
	} `yaml:"listener"`
	CA *struct {
		PrivDir *string `yaml:"privDir"`
		PubDir  *string `yaml:"pubDir"`
	} `yaml:"ca"`
	Policy *struct {
		Namespace            *string `yaml:"namespace"`
		MaxStaleness         *string `yaml:"maxStaleness"`
		Resync               *string `yaml:"resync"`
		FirstSnapshotTimeout *string `yaml:"firstSnapshotTimeout"`
		PodLabelsPath        *string `yaml:"podLabelsPath"`
	} `yaml:"policy"`
	// Capture mirrors the YAML-surfaced subset of CaptureConfig. MinKernel is
	// intentionally NOT surfaced: it is a security floor (>= 5.15, capture gate
	// P2) sourced from capture.DefaultOptions() and must not be lowered via
	// config, so exposing it as a knob would only invite weakening it.
	Capture *struct {
		PodPath             *string `yaml:"podPath"`
		HostCgroupMount     *string `yaml:"hostCgroupMount"`
		LocalCgroupMount    *string `yaml:"localCgroupMount"`
		ProcCgroupPath      *string `yaml:"procCgroupPath"`
		ProxyUID            *uint32 `yaml:"proxyUID"`
		ProxyGID            *uint32 `yaml:"proxyGID"`
		DNSServer           *string `yaml:"dnsServer"`
		BypassCIDRs         *string `yaml:"bypassCIDRs"`
		CaptureIPv6         *bool   `yaml:"captureIPv6"`
		MountBPFFS          *bool   `yaml:"mountBPFFS"`
		BlockNonTCP         *bool   `yaml:"blockNonTCP"`
		RunProbe            *bool   `yaml:"runProbe"`
		AllowUnsafeStartup  *bool   `yaml:"allowUnsafeStartup"`
		AttachCheckInterval *string `yaml:"attachCheckInterval"`
		PinLinks            *bool   `yaml:"pinLinks"`
		PinRoot             *string `yaml:"pinRoot"`
		PinRootPrivate      *bool   `yaml:"pinRootPrivate"`
		MapEntries          *uint32 `yaml:"mapEntries"`
		DestMaxAge          *string `yaml:"destMaxAge"`
	} `yaml:"capture"`
	// ControlPlane carries only the bind host and optional port. An empty
	// Address is deliberate: S5 wire-time reconciliation resolves it from the
	// downward-API POD_IP, so config never reads POD_IP itself.
	ControlPlane *struct {
		Address *string `yaml:"address"`
		Port    *int    `yaml:"port"`
	} `yaml:"controlPlane"`
	Token *struct {
		SATokenPath *string `yaml:"saTokenPath"`
		Entra       *struct {
			TenantID  *string `yaml:"tenantID"`
			ClientID  *string `yaml:"clientID"`
			Authority *string `yaml:"authority"`
		} `yaml:"entra"`
	} `yaml:"token"`
	Audit *struct {
		Sink *string `yaml:"sink"`
	} `yaml:"audit"`
	// Pod carries the S5 Downward API attribution. Surfaced in YAML for parity
	// with every other field, though in production it is set from the Downward
	// API env, not a file.
	Pod *struct {
		Namespace      *string `yaml:"namespace"`
		Name           *string `yaml:"name"`
		UID            *string `yaml:"uid"`
		ServiceAccount *string `yaml:"serviceAccount"`
	} `yaml:"pod"`
}

// Load resolves configuration from the process environment. The optional
// config-file path comes from AKSH_CONFIG_FILE; when it is empty only defaults
// and AKSH_* overrides apply.
func Load() (Config, error) {
	return LoadFrom(os.Getenv(envConfigFile), os.Getenv)
}

// LoadFrom resolves configuration from an optional YAML file at path and the
// AKSH_* variables read through getenv, applying defaults -> file -> env
// precedence.
func LoadFrom(path string, getenv func(string) string) (Config, error) {
	return loadFromWithLogger(path, getenv, slog.Default())
}

// loadFromWithLogger is LoadFrom with an injectable logger so the bounded
// config-loaded summary can be captured in tests without leaking secrets.
func loadFromWithLogger(path string, getenv func(string) string, log *slog.Logger) (Config, error) {
	if log == nil {
		log = slog.Default()
	}
	cfg := defaults()
	sources := []string{"defaults"}

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return Config{}, fmt.Errorf("config: read file: %w", err)
		}
		var yc yamlConfig
		if err := yaml.UnmarshalStrict(data, &yc); err != nil {
			return Config{}, fmt.Errorf("config: parse file %s: %w", path, err)
		}
		if err := applyYAML(&cfg, yc); err != nil {
			return Config{}, err
		}
		sources = append(sources, "file")
	}

	envUsed, err := applyEnv(&cfg, getenv)
	if err != nil {
		return Config{}, err
	}
	if envUsed {
		sources = append(sources, "env")
	}

	trimFields(&cfg)

	log.Info("aksh-proxy: config loaded", "sources", strings.Join(sources, ","))
	return cfg, nil
}

// applyYAML overlays present YAML values onto cfg, parsing the staleness
// duration when supplied.
func applyYAML(cfg *Config, yc yamlConfig) error {
	if yc.Listener != nil && yc.Listener.Address != nil {
		cfg.Listener.Address = *yc.Listener.Address
	}
	if yc.CA != nil {
		if yc.CA.PrivDir != nil {
			cfg.CA.PrivDir = *yc.CA.PrivDir
		}
		if yc.CA.PubDir != nil {
			cfg.CA.PubDir = *yc.CA.PubDir
		}
	}
	if yc.Policy != nil {
		if yc.Policy.Namespace != nil {
			cfg.Policy.Namespace = *yc.Policy.Namespace
		}
		if yc.Policy.PodLabelsPath != nil {
			cfg.Policy.PodLabelsPath = *yc.Policy.PodLabelsPath
		}
		if yc.Policy.MaxStaleness != nil {
			d, err := time.ParseDuration(strings.TrimSpace(*yc.Policy.MaxStaleness))
			if err != nil {
				return fmt.Errorf("config: invalid duration for policy.maxStaleness: %w", err)
			}
			cfg.Policy.MaxStaleness = d
		}
		if yc.Policy.Resync != nil {
			d, err := time.ParseDuration(strings.TrimSpace(*yc.Policy.Resync))
			if err != nil {
				return fmt.Errorf("config: invalid duration for policy.resync: %w", err)
			}
			cfg.Policy.Resync = d
		}
		if yc.Policy.FirstSnapshotTimeout != nil {
			d, err := time.ParseDuration(strings.TrimSpace(*yc.Policy.FirstSnapshotTimeout))
			if err != nil {
				return fmt.Errorf("config: invalid duration for policy.firstSnapshotTimeout: %w", err)
			}
			cfg.Policy.FirstSnapshotTimeout = d
		}
	}
	if c := yc.Capture; c != nil {
		if c.PodPath != nil {
			cfg.Capture.PodPath = *c.PodPath
		}
		if c.HostCgroupMount != nil {
			cfg.Capture.HostCgroupMount = *c.HostCgroupMount
		}
		if c.LocalCgroupMount != nil {
			cfg.Capture.LocalCgroupMount = *c.LocalCgroupMount
		}
		if c.ProcCgroupPath != nil {
			cfg.Capture.ProcCgroupPath = *c.ProcCgroupPath
		}
		if c.ProxyUID != nil {
			cfg.Capture.ProxyUID = *c.ProxyUID
		}
		if c.ProxyGID != nil {
			cfg.Capture.ProxyGID = *c.ProxyGID
		}
		if c.DNSServer != nil {
			cfg.Capture.DNSServer = *c.DNSServer
		}
		if c.BypassCIDRs != nil {
			cfg.Capture.BypassCIDRs = *c.BypassCIDRs
		}
		if c.CaptureIPv6 != nil {
			cfg.Capture.CaptureIPv6 = *c.CaptureIPv6
		}
		if c.MountBPFFS != nil {
			cfg.Capture.MountBPFFS = *c.MountBPFFS
		}
		if c.BlockNonTCP != nil {
			cfg.Capture.BlockNonTCP = *c.BlockNonTCP
		}
		if c.RunProbe != nil {
			cfg.Capture.RunProbe = *c.RunProbe
		}
		if c.AllowUnsafeStartup != nil {
			cfg.Capture.AllowUnsafeStartup = *c.AllowUnsafeStartup
		}
		if c.AttachCheckInterval != nil {
			d, err := time.ParseDuration(strings.TrimSpace(*c.AttachCheckInterval))
			if err != nil {
				return fmt.Errorf("config: invalid duration for capture.attachCheckInterval: %w", err)
			}
			cfg.Capture.AttachCheckInterval = d
		}
		if c.PinLinks != nil {
			cfg.Capture.PinLinks = *c.PinLinks
		}
		if c.PinRoot != nil {
			cfg.Capture.PinRoot = *c.PinRoot
		}
		if c.PinRootPrivate != nil {
			cfg.Capture.PinRootPrivate = *c.PinRootPrivate
		}
		if c.MapEntries != nil {
			cfg.Capture.MapEntries = *c.MapEntries
		}
		if c.DestMaxAge != nil {
			d, err := time.ParseDuration(strings.TrimSpace(*c.DestMaxAge))
			if err != nil {
				return fmt.Errorf("config: invalid duration for capture.destMaxAge: %w", err)
			}
			cfg.Capture.DestMaxAge = d
		}
	}
	if yc.ControlPlane != nil {
		if yc.ControlPlane.Address != nil {
			cfg.ControlPlane.Address = *yc.ControlPlane.Address
		}
		if yc.ControlPlane.Port != nil {
			cfg.ControlPlane.Port = *yc.ControlPlane.Port
		}
	}
	if yc.Token != nil {
		if yc.Token.SATokenPath != nil {
			cfg.Token.SATokenPath = *yc.Token.SATokenPath
		}
		if yc.Token.Entra != nil {
			if yc.Token.Entra.TenantID != nil {
				cfg.Token.Entra.TenantID = *yc.Token.Entra.TenantID
			}
			if yc.Token.Entra.ClientID != nil {
				cfg.Token.Entra.ClientID = *yc.Token.Entra.ClientID
			}
			if yc.Token.Entra.Authority != nil {
				cfg.Token.Entra.Authority = *yc.Token.Entra.Authority
			}
		}
	}
	if yc.Audit != nil && yc.Audit.Sink != nil {
		cfg.Audit.Sink = *yc.Audit.Sink
	}
	if yc.Pod != nil {
		if yc.Pod.Namespace != nil {
			cfg.Pod.Namespace = *yc.Pod.Namespace
		}
		if yc.Pod.Name != nil {
			cfg.Pod.Name = *yc.Pod.Name
		}
		if yc.Pod.UID != nil {
			cfg.Pod.UID = *yc.Pod.UID
		}
		if yc.Pod.ServiceAccount != nil {
			cfg.Pod.ServiceAccount = *yc.Pod.ServiceAccount
		}
	}
	return nil
}

// applyEnv overlays non-empty AKSH_* variables onto cfg and reports whether any
// override was applied. An invalid staleness duration yields a bounded error
// that names the offending variable without dumping the environment.
func applyEnv(cfg *Config, getenv func(string) string) (bool, error) {
	used := false
	set := func(key string, target *string) {
		if v := getenv(key); v != "" {
			*target = v
			used = true
		}
	}
	setBool := func(key string, target *bool) error {
		if v := getenv(key); v != "" {
			b, err := strconv.ParseBool(strings.TrimSpace(v))
			if err != nil {
				return fmt.Errorf("config: %s must be a boolean (true/false)", key)
			}
			*target = b
			used = true
		}
		return nil
	}
	setU32 := func(key string, target *uint32) error {
		if v := getenv(key); v != "" {
			n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 32)
			if err != nil {
				return fmt.Errorf("config: %s must be an unsigned 32-bit integer", key)
			}
			*target = uint32(n)
			used = true
		}
		return nil
	}
	setInt := func(key string, target *int) error {
		if v := getenv(key); v != "" {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				return fmt.Errorf("config: %s must be an integer", key)
			}
			*target = n
			used = true
		}
		return nil
	}
	setDuration := func(key string, target *time.Duration) error {
		if v := getenv(key); v != "" {
			d, err := time.ParseDuration(strings.TrimSpace(v))
			if err != nil {
				return fmt.Errorf("config: %s must be a duration (e.g. 30s)", key)
			}
			*target = d
			used = true
		}
		return nil
	}
	set(envListenerAddr, &cfg.Listener.Address)
	set(envCAPrivDir, &cfg.CA.PrivDir)
	set(envCAPubDir, &cfg.CA.PubDir)
	set(envNamespace, &cfg.Policy.Namespace)
	set(envPodLabelsPath, &cfg.Policy.PodLabelsPath)
	set(envSATokenPath, &cfg.Token.SATokenPath)
	set(envEntraTenantID, &cfg.Token.Entra.TenantID)
	set(envEntraClientID, &cfg.Token.Entra.ClientID)
	set(envEntraAuthorit, &cfg.Token.Entra.Authority)
	set(envAuditSink, &cfg.Audit.Sink)
	set(envPodNamespace, &cfg.Pod.Namespace)
	set(envPodName, &cfg.Pod.Name)
	set(envPodUID, &cfg.Pod.UID)
	set(envAgentServiceAccnt, &cfg.Pod.ServiceAccount)
	set(envCapturePodPath, &cfg.Capture.PodPath)
	set(envCaptureHostCgroupMount, &cfg.Capture.HostCgroupMount)
	set(envCaptureLocalCgroupMount, &cfg.Capture.LocalCgroupMount)
	set(envCaptureProcCgroupPath, &cfg.Capture.ProcCgroupPath)
	set(envCaptureDNSServer, &cfg.Capture.DNSServer)
	set(envCaptureBypassCIDRs, &cfg.Capture.BypassCIDRs)
	set(envCapturePinRoot, &cfg.Capture.PinRoot)
	// ControlPlane.Address is an explicit override only; an empty env leaves it
	// empty for S5 POD_IP reconciliation (see envControlPlaneAddress doc).
	set(envControlPlaneAddress, &cfg.ControlPlane.Address)

	if v := getenv(envMaxStaleness); v != "" {
		d, err := time.ParseDuration(strings.TrimSpace(v))
		if err != nil {
			return used, fmt.Errorf("config: %s (policy.maxStaleness) must be a duration (e.g. 45s)", envMaxStaleness)
		}
		cfg.Policy.MaxStaleness = d
		used = true
	}

	for _, fn := range []func() error{
		func() error { return setDuration(envResync, &cfg.Policy.Resync) },
		func() error { return setDuration(envFirstSnapshot, &cfg.Policy.FirstSnapshotTimeout) },
		func() error { return setU32(envCaptureProxyUID, &cfg.Capture.ProxyUID) },
		func() error { return setU32(envCaptureProxyGID, &cfg.Capture.ProxyGID) },
		func() error { return setBool(envCaptureIPv6, &cfg.Capture.CaptureIPv6) },
		func() error { return setBool(envCaptureMountBPFFS, &cfg.Capture.MountBPFFS) },
		func() error { return setBool(envCaptureBlockNonTCP, &cfg.Capture.BlockNonTCP) },
		func() error { return setBool(envCaptureRunProbe, &cfg.Capture.RunProbe) },
		func() error { return setBool(envCaptureAllowUnsafeStartup, &cfg.Capture.AllowUnsafeStartup) },
		func() error { return setDuration(envCaptureAttachCheckInterval, &cfg.Capture.AttachCheckInterval) },
		func() error { return setBool(envCapturePinLinks, &cfg.Capture.PinLinks) },
		func() error { return setBool(envCapturePinRootPrivate, &cfg.Capture.PinRootPrivate) },
		func() error { return setU32(envCaptureMapEntries, &cfg.Capture.MapEntries) },
		func() error { return setDuration(envCaptureDestMaxAge, &cfg.Capture.DestMaxAge) },
		func() error { return setInt(envControlPlanePort, &cfg.ControlPlane.Port) },
	} {
		if err := fn(); err != nil {
			return used, err
		}
	}
	return used, nil
}

// trimFields normalizes surrounding whitespace so that whitespace-only values
// collapse to empty and are then rejected by Validate.
func trimFields(cfg *Config) {
	cfg.Listener.Address = strings.TrimSpace(cfg.Listener.Address)
	cfg.CA.PrivDir = strings.TrimSpace(cfg.CA.PrivDir)
	cfg.CA.PubDir = strings.TrimSpace(cfg.CA.PubDir)
	cfg.Policy.Namespace = strings.TrimSpace(cfg.Policy.Namespace)
	cfg.Policy.PodLabelsPath = strings.TrimSpace(cfg.Policy.PodLabelsPath)
	cfg.Token.SATokenPath = strings.TrimSpace(cfg.Token.SATokenPath)
	cfg.Token.Entra.TenantID = strings.TrimSpace(cfg.Token.Entra.TenantID)
	cfg.Token.Entra.ClientID = strings.TrimSpace(cfg.Token.Entra.ClientID)
	cfg.Token.Entra.Authority = strings.TrimSpace(cfg.Token.Entra.Authority)
	cfg.Audit.Sink = strings.TrimSpace(cfg.Audit.Sink)
	cfg.Pod.Namespace = strings.TrimSpace(cfg.Pod.Namespace)
	cfg.Pod.Name = strings.TrimSpace(cfg.Pod.Name)
	cfg.Pod.UID = strings.TrimSpace(cfg.Pod.UID)
	cfg.Pod.ServiceAccount = strings.TrimSpace(cfg.Pod.ServiceAccount)
	cfg.Capture.PodPath = strings.TrimSpace(cfg.Capture.PodPath)
	cfg.Capture.HostCgroupMount = strings.TrimSpace(cfg.Capture.HostCgroupMount)
	cfg.Capture.LocalCgroupMount = strings.TrimSpace(cfg.Capture.LocalCgroupMount)
	cfg.Capture.ProcCgroupPath = strings.TrimSpace(cfg.Capture.ProcCgroupPath)
	cfg.Capture.DNSServer = strings.TrimSpace(cfg.Capture.DNSServer)
	cfg.Capture.BypassCIDRs = strings.TrimSpace(cfg.Capture.BypassCIDRs)
	cfg.Capture.PinRoot = strings.TrimSpace(cfg.Capture.PinRoot)
	cfg.ControlPlane.Address = strings.TrimSpace(cfg.ControlPlane.Address)
}

// Validate returns the first configuration error in a fixed order. Error
// messages name bounded field names only and never include secret or
// environment values.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Token.Entra.TenantID) == "" {
		return fmt.Errorf("config: Token.Entra.TenantID is required")
	}
	if strings.TrimSpace(c.Token.Entra.ClientID) == "" {
		return fmt.Errorf("config: Token.Entra.ClientID is required")
	}
	if strings.TrimSpace(c.Policy.Namespace) == "" {
		return ErrMissingNamespace
	}
	if strings.TrimSpace(c.Token.SATokenPath) == "" {
		return fmt.Errorf("config: Token.SATokenPath is required")
	}
	if !isHTTPSAuthority(c.Token.Entra.Authority) {
		return fmt.Errorf("config: Token.Entra.Authority must be an https:// URL")
	}
	if err := validateLoopbackAddress(c.Listener.Address); err != nil {
		return err
	}
	if c.Policy.MaxStaleness < 0 {
		return fmt.Errorf("config: Policy.MaxStaleness must not be negative")
	}
	if c.Policy.Resync < 0 {
		return fmt.Errorf("config: Policy.Resync must not be negative")
	}
	if c.Policy.FirstSnapshotTimeout < 0 {
		return fmt.Errorf("config: Policy.FirstSnapshotTimeout must not be negative")
	}
	if c.ControlPlane.Port < 0 {
		return fmt.Errorf("config: ControlPlane.Port must not be negative")
	}
	if strings.TrimSpace(c.Audit.Sink) == "" {
		return fmt.Errorf("config: Audit.Sink is required")
	}
	if err := validateCapture(c.Capture); err != nil {
		return err
	}
	return nil
}

// validateCapture enforces the capture surface's fail-closed rules in a fixed
// order. Numeric fields left at their zero value are accepted as "use the
// default" (resolved in CaptureOptionsFromConfig, UT #29); only explicitly set
// out-of-range values are rejected. ProxyUID is the deliberate exception: zero
// is always rejected (UT #38), never defaulted at validation time.
func validateCapture(c CaptureConfig) error {
	if strings.TrimSpace(c.PodPath) == "" {
		return ErrMissingPodPath
	}
	if c.ProxyUID == 0 {
		return ErrInvalidProxyUID
	}
	if c.CaptureIPv6 {
		return ErrIPv6Unsupported
	}
	if !c.BlockNonTCP && !c.AllowUnsafeStartup {
		return ErrRequiresUnsafeStartup
	}
	if !c.RunProbe && !c.AllowUnsafeStartup {
		return ErrRequiresUnsafeStartup
	}
	if c.AttachCheckInterval != 0 && (c.AttachCheckInterval < minAttachCheckInterval || c.AttachCheckInterval > maxAttachCheckInterval) {
		return ErrInvalidInterval
	}
	if c.MapEntries != 0 && (c.MapEntries < minMapEntries || c.MapEntries > maxMapEntries) {
		return ErrInvalidMapEntries
	}
	if c.DestMaxAge != 0 && (c.DestMaxAge < minDestMaxAge || c.DestMaxAge > maxDestMaxAge) {
		return ErrInvalidDestMaxAge
	}
	if c.PinLinks && strings.TrimSpace(c.PinRoot) == "" {
		return ErrMissingPinRoot
	}
	// A set DNSServer must parse. CaptureOptionsFromConfig drops an unparseable
	// value and leaves the DEV-01 exception disabled, which before the
	// sock_create relaxation was indistinguishable from "DNS never worked
	// anyway". Now that a captured workload's only route to a resolver is this
	// exception, silently dropping a typo means every name lookup in the pod
	// fails with no indication why. Reject it at startup instead. The narrower
	// IPv4-and-non-zero-port rule that the BPF config map can actually express
	// stays where it was, on capture.Options (ErrInvalidDNSServer there).
	if s := strings.TrimSpace(c.DNSServer); s != "" {
		if _, err := netip.ParseAddrPort(s); err != nil {
			return ErrInvalidDNSServer
		}
	}
	// A set BypassCIDRs must parse here rather than being dropped in the
	// mapping. Every entry is a destination that will NOT be policed, so a typo
	// that silently vanished would leave the deployer believing a hole exists
	// where it does not -- or, worse, quietly capturing traffic they arranged
	// to exempt, which shows up as an unexplained outage. The narrower rules
	// the kernel map can express (IPv4, /8 or longer, no host bits, at most 64
	// entries) live on capture.Options and are re-checked there.
	if _, err := ParseBypassCIDRs(c.BypassCIDRs); err != nil {
		return ErrInvalidBypassCIDRs
	}
	return nil
}

// ParseBypassCIDRs splits a comma-separated prefix list into netip.Prefix
// values. Empty entries produced by trailing or doubled commas are skipped, so
// "10.96.0.0/12," parses; anything else that does not parse is an error rather
// than a skipped entry.
func ParseBypassCIDRs(list string) ([]netip.Prefix, error) {
	fields := strings.Split(list, ",")
	out := make([]netip.Prefix, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		p, err := netip.ParsePrefix(f)
		if err != nil {
			return nil, fmt.Errorf("config: Capture.BypassCIDRs entry %q is not a CIDR prefix", f)
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// isHTTPSAuthority reports whether authority is a well-formed https:// URL.
func isHTTPSAuthority(authority string) bool {
	u, err := url.Parse(strings.TrimSpace(authority))
	if err != nil {
		return false
	}
	return u.Scheme == "https" && u.Host != ""
}

// validateLoopbackAddress enforces IPv4 loopback host-only binding; port 0 is
// accepted so tests can request an OS-assigned loopback port.
func validateLoopbackAddress(address string) error {
	ap, err := netip.ParseAddrPort(strings.TrimSpace(address))
	if err != nil {
		return fmt.Errorf("config: Listener.Address must be an IPv4 loopback host:port")
	}
	addr := ap.Addr().Unmap()
	if !addr.Is4() || !addr.IsLoopback() {
		return fmt.Errorf("config: Listener.Address must bind IPv4 loopback only")
	}
	return nil
}

// EffectivePort resolves a zero (unset) control-plane port to the
// defaultControlPlanePort; an explicit non-zero port overrides it (UT #49).
// Exported (S5 reconciliation, Findings SI-S3-3) so cmd/aksh-proxy run()
// wiring can resolve the control-plane port default.
func (cp ControlPlaneConfig) EffectivePort() int {
	if cp.Port == 0 {
		return defaultControlPlanePort
	}
	return cp.Port
}

// EffectiveFirstSnapshotTimeout resolves a zero first-snapshot timeout to the
// 30s default (UT #52). Exported (S5 reconciliation, Findings SI-S3-3) so
// cmd/aksh-proxy run() can bound the policy first-snapshot wait.
func (p PolicyConfig) EffectiveFirstSnapshotTimeout() time.Duration {
	if p.FirstSnapshotTimeout == 0 {
		return defaultFirstSnapshotTimeout
	}
	return p.FirstSnapshotTimeout
}

// EffectiveMaxStaleness resolves a zero staleness threshold to the existing 45s
// default (UT #54). Exported (S5 reconciliation, Findings SI-S3-3) so
// cmd/aksh-proxy run() wiring can derive the watcher staleness bound.
func (p PolicyConfig) EffectiveMaxStaleness() time.Duration {
	if p.MaxStaleness == 0 {
		return defaultMaxStaleness
	}
	return p.MaxStaleness
}

// CaptureOptionsFromConfig is the single config -> capture.Options mapping. The
// explicit ctx is the daemon context and becomes Options.Context (UT #27); m is
// the mandatory metrics recorder injected verbatim into Options.Metrics -- it is
// never sourced from YAML and a nil m is passed through unchanged so the
// resulting Options.Validate fails closed on nil Metrics (UT #30/#31).
//
// Defaulting placement: numeric/string/mount capture defaults are applied here
// by starting from capture.DefaultOptions() and overlaying only non-zero cfg
// fields (UT #29/#35). Control-plane and policy defaulting that UT #49/#52/#54
// assert live on the value-receiver accessors above, because Config.Validate is
// a value receiver and cannot mutate the caller's Config.
//
// Exported (S5 reconciliation, Findings SI-S3-3) so cmd/aksh-proxy (package
// main) run() wiring can build capture.Options for the eager LoadAndAttach.
func CaptureOptionsFromConfig(ctx context.Context, cfg Config, m audit.MetricsRecorder) capture.Options {
	opts := capture.DefaultOptions()
	opts.Context = ctx
	opts.Metrics = m

	c := cfg.Capture
	if c.PodPath != "" {
		opts.PodPath = c.PodPath
	}
	if c.HostCgroupMount != "" {
		opts.HostCgroupMount = c.HostCgroupMount
	}
	if c.LocalCgroupMount != "" {
		opts.LocalCgroupMount = c.LocalCgroupMount
	}
	if c.ProcCgroupPath != "" {
		opts.ProcCgroupPath = c.ProcCgroupPath
	}
	if c.ProxyUID != 0 {
		opts.ProxyUID = c.ProxyUID
	}
	if c.ProxyGID != 0 {
		opts.ProxyGID = c.ProxyGID
	}
	opts.CaptureIPv6 = c.CaptureIPv6
	opts.MountBPFFS = c.MountBPFFS
	opts.BlockNonTCP = c.BlockNonTCP
	opts.RunProbe = c.RunProbe
	opts.AllowUnsafeStartup = c.AllowUnsafeStartup
	if c.AttachCheckInterval != 0 {
		opts.AttachCheckInterval = c.AttachCheckInterval
	}
	opts.PinLinks = c.PinLinks
	if c.PinRoot != "" {
		opts.PinRoot = c.PinRoot
	}
	opts.PinRootPrivate = c.PinRootPrivate
	if c.MapEntries != 0 {
		opts.MapEntries = c.MapEntries
	}
	if c.DestMaxAge != 0 {
		opts.DestMaxAge = c.DestMaxAge
	}
	if c.MinKernel != (capture.KernelVersion{}) {
		opts.MinKernel = c.MinKernel
	}

	// ListenerAddr is sourced from the top-level Listener.Address (UT #32); an
	// unparseable address leaves the DefaultOptions loopback default in place.
	if ap, err := netip.ParseAddrPort(strings.TrimSpace(cfg.Listener.Address)); err == nil {
		opts.ListenerAddr = ap
	}
	// A set DNSServer is parsed as host:port (UT #33); unset leaves DNS capture
	// disabled (UT #34).
	if s := strings.TrimSpace(c.DNSServer); s != "" {
		if ap, err := netip.ParseAddrPort(s); err == nil {
			opts.DNSServer = ap
		}
	}
	// Validate() already rejected an unparseable list, so a parse failure here
	// can only mean a caller built the Config by hand; leaving BypassCIDRs
	// empty in that case fails closed (everything stays captured).
	if prefixes, err := ParseBypassCIDRs(c.BypassCIDRs); err == nil {
		opts.BypassCIDRs = prefixes
	}
	return opts
}
