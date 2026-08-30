package config

import (
	"errors"
	"net/netip"
	"testing"
)

// TestParseBypassCIDRs covers the comma-separated list parser. Nothing here is
// silently dropped except empty fields, because a dropped entry means a
// destination stays captured that the deployer arranged to exempt -- which
// presents as an unexplained outage rather than as a config error.
func TestParseBypassCIDRs(t *testing.T) {
	t.Run("ParseBypassCIDRs_Empty_ReturnsNil", func(t *testing.T) {
		got, err := ParseBypassCIDRs("")
		if err != nil {
			t.Fatalf("ParseBypassCIDRs(\"\") error = %v", err)
		}
		if got != nil {
			t.Fatalf("ParseBypassCIDRs(\"\") = %v, want nil", got)
		}
	})

	t.Run("ParseBypassCIDRs_SinglePrefix_ReturnsOneEntry", func(t *testing.T) {
		got, err := ParseBypassCIDRs("10.96.0.0/12")
		if err != nil {
			t.Fatalf("error = %v", err)
		}
		want := []netip.Prefix{netip.MustParsePrefix("10.96.0.0/12")}
		if len(got) != 1 || got[0] != want[0] {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("ParseBypassCIDRs_MultiplePrefixesWithSpaces_AreTrimmed", func(t *testing.T) {
		got, err := ParseBypassCIDRs(" 10.96.0.0/12 , 10.244.0.0/16 ")
		if err != nil {
			t.Fatalf("error = %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d entries, want 2 (%v)", len(got), got)
		}
		if got[0] != netip.MustParsePrefix("10.96.0.0/12") || got[1] != netip.MustParsePrefix("10.244.0.0/16") {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("ParseBypassCIDRs_TrailingAndDoubledCommas_AreSkipped", func(t *testing.T) {
		got, err := ParseBypassCIDRs("10.96.0.0/12,,10.244.0.0/16,")
		if err != nil {
			t.Fatalf("error = %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d entries, want 2 (%v)", len(got), got)
		}
	})

	t.Run("ParseBypassCIDRs_OnlyCommas_ReturnsNil", func(t *testing.T) {
		got, err := ParseBypassCIDRs(", ,")
		if err != nil {
			t.Fatalf("error = %v", err)
		}
		if got != nil {
			t.Fatalf("got %v, want nil", got)
		}
	})

	for _, bad := range []string{
		"10.96.0.0",      // an address, not a prefix
		"10.96.0.0/33",   // out of range for IPv4
		"not-a-cidr",     //
		"10.96.0.0/12 x", //
	} {
		t.Run("ParseBypassCIDRs_Invalid_"+bad+"_ReturnsError", func(t *testing.T) {
			if _, err := ParseBypassCIDRs(bad); err == nil {
				t.Fatalf("ParseBypassCIDRs(%q) error = nil, want an error", bad)
			}
		})
	}

	t.Run("ParseBypassCIDRs_OneBadEntry_FailsWholeListRatherThanSkipping", func(t *testing.T) {
		if _, err := ParseBypassCIDRs("10.96.0.0/12,nonsense,10.244.0.0/16"); err == nil {
			t.Fatal("error = nil, want an error: a skipped entry would be a silent outage")
		}
	})
}

// TestCaptureConfigValidateBypassCIDRs proves an unparseable list is rejected at
// startup rather than dropped in the mapping.
func TestCaptureConfigValidateBypassCIDRs(t *testing.T) {
	base := func() CaptureConfig {
		return CaptureConfig{
			PodPath:             "/host/sys/fs/cgroup/pod-abc",
			ProxyUID:            1774,
			BlockNonTCP:         true,
			RunProbe:            true,
			AttachCheckInterval: 30_000_000_000,
		}
	}

	t.Run("Validate_UnsetBypassCIDRs_IsAccepted", func(t *testing.T) {
		if err := validateCapture(base()); err != nil {
			t.Fatalf("Validate() = %v, want nil", err)
		}
	})

	t.Run("Validate_GoodBypassCIDRs_IsAccepted", func(t *testing.T) {
		c := base()
		c.BypassCIDRs = "10.96.0.0/12,10.244.0.0/16"
		if err := validateCapture(c); err != nil {
			t.Fatalf("Validate() = %v, want nil", err)
		}
	})

	t.Run("Validate_UnparseableBypassCIDRs_ReturnsErrInvalidBypassCIDRs", func(t *testing.T) {
		c := base()
		c.BypassCIDRs = "10.96.0.0/12,nonsense"
		if err := validateCapture(c); !errors.Is(err, ErrInvalidBypassCIDRs) {
			t.Fatalf("Validate() = %v, want ErrInvalidBypassCIDRs", err)
		}
	})
}

// TestLoad_BypassCIDRs covers the YAML key and the environment override, which
// is how the sidecar will actually be configured.
func TestLoad_BypassCIDRs(t *testing.T) {
	const yaml = `
policy:
  namespace: aksh-system
token:
  entra:
    tenantID: tenant-1
    clientID: client-1
capture:
  podPath: /host/sys/fs/cgroup/pod-abc
  bypassCIDRs: 10.96.0.0/12
`

	t.Run("Load_BypassCIDRsFromYAML_IsRead", func(t *testing.T) {
		path := writeFile(t, yaml)
		cfg, err := LoadFrom(path, emptyGetenv)
		if err != nil {
			t.Fatalf("LoadFrom() error = %v", err)
		}
		if cfg.Capture.BypassCIDRs != "10.96.0.0/12" {
			t.Fatalf("BypassCIDRs = %q, want %q", cfg.Capture.BypassCIDRs, "10.96.0.0/12")
		}
	})

	t.Run("Load_BypassCIDRsFromEnv_OverridesYAML", func(t *testing.T) {
		path := writeFile(t, yaml)
		getenv := func(k string) string {
			if k == envCaptureBypassCIDRs {
				return " 10.244.0.0/16 "
			}
			return ""
		}
		cfg, err := LoadFrom(path, getenv)
		if err != nil {
			t.Fatalf("LoadFrom() error = %v", err)
		}
		// Trimmed by normalise, so the surrounding whitespace must be gone.
		if cfg.Capture.BypassCIDRs != "10.244.0.0/16" {
			t.Fatalf("BypassCIDRs = %q, want %q", cfg.Capture.BypassCIDRs, "10.244.0.0/16")
		}
	})
}
