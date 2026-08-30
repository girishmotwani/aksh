package capture

import (
	"errors"
	"net/netip"
	"testing"
	"unsafe"

	"github.com/girishmotwani/aksh/internal/audit"
)

// TestBypassKeyLayout pins the wire layout of the LPM trie key against
// `struct bypass_key` in aksh_capture.c. The kernel reads these bytes directly,
// so a reordered or repadded struct here would silently match the wrong
// destinations rather than fail to compile.
func TestBypassKeyLayout(t *testing.T) {
	t.Run("BypassKey_SizeOf_MatchesKernelABI", func(t *testing.T) {
		if got := unsafe.Sizeof(bypassKey{}); got != BypassKeySize {
			t.Fatalf("unsafe.Sizeof(bypassKey{}) = %d, want %d", got, BypassKeySize)
		}
	})

	t.Run("BypassKey_FieldOffsets_MatchKernelABI", func(t *testing.T) {
		if got := unsafe.Offsetof(bypassKey{}.PrefixLen); got != 0 {
			t.Errorf("PrefixLen offset = %d, want 0", got)
		}
		if got := unsafe.Offsetof(bypassKey{}.Addr); got != 4 {
			t.Errorf("Addr offset = %d, want 4", got)
		}
	})

	t.Run("BypassKey_NoImplicitPadding_MatchesPackedSize", func(t *testing.T) {
		sum := unsafe.Sizeof(uint32(0)) + unsafe.Sizeof([4]byte{})
		if sum != unsafe.Sizeof(bypassKey{}) {
			t.Fatalf("sum of field sizes = %d, struct size = %d (implicit padding present)", sum, unsafe.Sizeof(bypassKey{}))
		}
	})
}

// TestBypassKeyFor covers the translation from a netip.Prefix to the kernel key
// and the re-checks that guard it.
func TestBypassKeyFor(t *testing.T) {
	t.Run("BypassKeyFor_IPv4Prefix_EncodesPrefixLenAndNetworkOrderAddr", func(t *testing.T) {
		got, err := bypassKeyFor(netip.MustParsePrefix("10.96.0.0/12"))
		if err != nil {
			t.Fatalf("bypassKeyFor: %v", err)
		}
		if got.PrefixLen != 12 {
			t.Errorf("PrefixLen = %d, want 12", got.PrefixLen)
		}
		// Network order: the first octet of the dotted-quad is the first byte.
		if got.Addr != [4]byte{10, 96, 0, 0} {
			t.Errorf("Addr = %v, want [10 96 0 0]", got.Addr)
		}
	})

	t.Run("BypassKeyFor_SlashThirtyTwoHostRoute_IsAccepted", func(t *testing.T) {
		got, err := bypassKeyFor(netip.MustParsePrefix("10.96.93.18/32"))
		if err != nil {
			t.Fatalf("bypassKeyFor: %v", err)
		}
		if got.PrefixLen != 32 || got.Addr != [4]byte{10, 96, 93, 18} {
			t.Fatalf("got %+v, want PrefixLen 32 addr [10 96 93 18]", got)
		}
	})

	t.Run("BypassKeyFor_MappedIPv4_IsUnmappedNotRejected", func(t *testing.T) {
		// ::ffff:10.96.0.0/108 is the 4-in-6 spelling of 10.96.0.0/12. Prefix
		// bits differ, so this must be built explicitly rather than parsed.
		p := netip.PrefixFrom(netip.MustParseAddr("::ffff:10.96.0.0"), 12)
		got, err := bypassKeyFor(p)
		if err != nil {
			t.Fatalf("bypassKeyFor: %v", err)
		}
		if got.Addr != [4]byte{10, 96, 0, 0} {
			t.Fatalf("Addr = %v, want [10 96 0 0]", got.Addr)
		}
	})

	for _, tc := range []struct {
		name   string
		prefix netip.Prefix
	}{
		{"ZeroValue", netip.Prefix{}},
		{"DefaultRoute", netip.MustParsePrefix("0.0.0.0/0")},
		{"TooShort", netip.MustParsePrefix("10.0.0.0/7")},
		{"HostBitsSet", netip.PrefixFrom(netip.MustParseAddr("10.96.0.5"), 12)},
		{"IPv6", netip.MustParsePrefix("2001:db8::/32")},
	} {
		t.Run("BypassKeyFor_"+tc.name+"_ReturnsErrInvalidBypassCIDR", func(t *testing.T) {
			_, err := bypassKeyFor(tc.prefix)
			if !errors.Is(err, ErrInvalidBypassCIDR) {
				t.Fatalf("bypassKeyFor(%v) error = %v, want ErrInvalidBypassCIDR", tc.prefix, err)
			}
		})
	}
}

// TestValidateBypassCIDRs covers Options.Validate's bypass rules. They are the
// only thing standing between a typo and an unpoliced destination, so each
// rejection reason is asserted separately rather than as one table of "errors".
func TestValidateBypassCIDRs(t *testing.T) {
	t.Run("Validate_NoBypassCIDRs_IsAccepted", func(t *testing.T) {
		if err := validateBypassCIDRs(nil); err != nil {
			t.Fatalf("validateBypassCIDRs(nil) = %v, want nil", err)
		}
	})

	t.Run("Validate_TypicalClusterPrefixes_AreAccepted", func(t *testing.T) {
		in := []netip.Prefix{
			netip.MustParsePrefix("10.96.0.0/12"),  // service CIDR
			netip.MustParsePrefix("10.244.0.0/16"), // pod CIDR
			netip.MustParsePrefix("172.16.0.0/12"),
		}
		if err := validateBypassCIDRs(in); err != nil {
			t.Fatalf("validateBypassCIDRs(%v) = %v, want nil", in, err)
		}
	})

	t.Run("Validate_DefaultRoute_IsRejected", func(t *testing.T) {
		err := validateBypassCIDRs([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")})
		if !errors.Is(err, ErrInvalidBypassCIDR) {
			t.Fatalf("error = %v, want ErrInvalidBypassCIDR", err)
		}
	})

	t.Run("Validate_PrefixShorterThanMinimum_IsRejected", func(t *testing.T) {
		err := validateBypassCIDRs([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/7")})
		if !errors.Is(err, ErrInvalidBypassCIDR) {
			t.Fatalf("error = %v, want ErrInvalidBypassCIDR", err)
		}
	})

	t.Run("Validate_PrefixAtExactMinimum_IsAccepted", func(t *testing.T) {
		if err := validateBypassCIDRs([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}); err != nil {
			t.Fatalf("validateBypassCIDRs(10.0.0.0/8) = %v, want nil", err)
		}
	})

	t.Run("Validate_HostBitsSet_IsRejectedNotMasked", func(t *testing.T) {
		// The point of rejecting rather than masking: 10.0.0.5/8 silently
		// widened to 10.0.0.0/8 is 16M unpoliced addresses the deployer did
		// not ask for.
		err := validateBypassCIDRs([]netip.Prefix{netip.PrefixFrom(netip.MustParseAddr("10.0.0.5"), 8)})
		if !errors.Is(err, ErrInvalidBypassCIDR) {
			t.Fatalf("error = %v, want ErrInvalidBypassCIDR", err)
		}
	})

	t.Run("Validate_IPv6Prefix_IsRejected", func(t *testing.T) {
		err := validateBypassCIDRs([]netip.Prefix{netip.MustParsePrefix("2001:db8::/32")})
		if !errors.Is(err, ErrInvalidBypassCIDR) {
			t.Fatalf("error = %v, want ErrInvalidBypassCIDR", err)
		}
	})

	t.Run("Validate_ListAtCapacity_IsAccepted", func(t *testing.T) {
		in := make([]netip.Prefix, 0, maxBypassCIDRs)
		for i := 0; i < maxBypassCIDRs; i++ {
			in = append(in, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i), 0, 0}), 16))
		}
		if err := validateBypassCIDRs(in); err != nil {
			t.Fatalf("validateBypassCIDRs(%d entries) = %v, want nil", len(in), err)
		}
	})

	t.Run("Validate_ListOverCapacity_IsRejected", func(t *testing.T) {
		in := make([]netip.Prefix, 0, maxBypassCIDRs+1)
		for i := 0; i <= maxBypassCIDRs; i++ {
			in = append(in, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i), 0, 0}), 16))
		}
		err := validateBypassCIDRs(in)
		if !errors.Is(err, ErrInvalidBypassCIDR) {
			t.Fatalf("error = %v, want ErrInvalidBypassCIDR", err)
		}
	})

	t.Run("Validate_OneBadEntryAmongGoodOnes_IsRejected", func(t *testing.T) {
		in := []netip.Prefix{
			netip.MustParsePrefix("10.96.0.0/12"),
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("10.244.0.0/16"),
		}
		if err := validateBypassCIDRs(in); !errors.Is(err, ErrInvalidBypassCIDR) {
			t.Fatalf("error = %v, want ErrInvalidBypassCIDR", err)
		}
	})
}

// TestOptionsValidateBypassCIDRs proves the bypass rules are reachable through
// the public Options.Validate, not just the unexported helper.
func TestOptionsValidateBypassCIDRs(t *testing.T) {
	base := func() Options {
		o := DefaultOptions()
		o.PodPath = "/sys/fs/cgroup/kubepods/pod"
		o.Metrics = audit.NopMetricsRecorder{}
		return o
	}

	t.Run("OptionsValidate_GoodBypassCIDR_IsAccepted", func(t *testing.T) {
		o := base()
		o.BypassCIDRs = []netip.Prefix{netip.MustParsePrefix("10.96.0.0/12")}
		if err := o.Validate(); err != nil {
			t.Fatalf("Validate() = %v, want nil", err)
		}
	})

	t.Run("OptionsValidate_DefaultRouteBypass_IsRejectedEvenWithAllowUnsafeStartup", func(t *testing.T) {
		// There is deliberately no escape hatch: AllowUnsafeStartup relaxes the
		// fail-open combinations of design section 18, not this one.
		o := base()
		o.AllowUnsafeStartup = true
		o.BypassCIDRs = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
		if err := o.Validate(); !errors.Is(err, ErrInvalidBypassCIDR) {
			t.Fatalf("Validate() = %v, want ErrInvalidBypassCIDR", err)
		}
	})
}
