package injector

import (
	"strings"
	"testing"
)

// profileDNS / profileBypass build a minimal profile that sets only the field
// under test, so the constructor exercises exactly one validator.
func profileDNS(dns string) InjectorOptions {
	o := testOptions()
	o.RuntimeProfile = RuntimeProfile{DNSServer: dns}
	return o
}
func profileBypass(cidrs string) InjectorOptions {
	o := testOptions()
	o.RuntimeProfile = RuntimeProfile{BypassCIDRs: cidrs}
	return o
}

func assertProfileRejected(t *testing.T, opts InjectorOptions, field, reasonSubstr string) {
	t.Helper()
	_, err := NewSidecarInjector(opts)
	if err == nil {
		t.Fatalf("expected rejection for field %s", field)
	}
	ae, ok := err.(AdmissionError)
	if !ok {
		t.Fatalf("error type %T, want AdmissionError", err)
	}
	if ae.Field != field {
		t.Fatalf("field = %q, want %q (reason=%q)", ae.Field, field, ae.Reason)
	}
	if !strings.Contains(ae.Reason, reasonSubstr) {
		t.Fatalf("reason = %q, want containing %q", ae.Reason, reasonSubstr)
	}
}

func assertProfileAccepted(t *testing.T, opts InjectorOptions) {
	t.Helper()
	if _, err := NewSidecarInjector(opts); err != nil {
		t.Fatalf("profile wrongly rejected: %v", err)
	}
}

// --- DNS server invariants (IPv4, non-zero port) ---------------------------

func TestValidateProfile_DNSServer_ValidIPv4_Accepted(t *testing.T) {
	assertProfileAccepted(t, profileDNS("10.96.0.10:53"))
}

func TestValidateProfile_DNSServer_Unset_Accepted(t *testing.T) {
	assertProfileAccepted(t, profileDNS(""))
}

func TestValidateProfile_DNSServer_Garbage_Rejected(t *testing.T) {
	assertProfileRejected(t, profileDNS("not-a-host-port"), "runtimeProfile.dnsServer", "host:port")
}

func TestValidateProfile_DNSServer_MissingPort_Rejected(t *testing.T) {
	assertProfileRejected(t, profileDNS("10.96.0.10"), "runtimeProfile.dnsServer", "host:port")
}

func TestValidateProfile_DNSServer_ZeroPort_Rejected(t *testing.T) {
	assertProfileRejected(t, profileDNS("10.96.0.10:0"), "runtimeProfile.dnsServer", "non-zero port")
}

func TestValidateProfile_DNSServer_IPv6_Rejected(t *testing.T) {
	// IPv6 cannot be written into the 32-bit IPv4 field of aksh_config.
	assertProfileRejected(t, profileDNS("[2001:db8::1]:53"), "runtimeProfile.dnsServer", "IPv4")
}

func TestValidateProfile_DNSServer_IPv6Loopback_Rejected(t *testing.T) {
	assertProfileRejected(t, profileDNS("[::1]:53"), "runtimeProfile.dnsServer", "IPv4")
}

func TestValidateProfile_DNSServer_MappedIPv4_Accepted(t *testing.T) {
	// A 4-in-6 mapped address unmaps to IPv4 and is acceptable.
	assertProfileAccepted(t, profileDNS("[::ffff:10.0.0.10]:53"))
}

// --- bypass CIDR invariants (IPv4, /8 or longer, no host bits, <=64) --------

func TestValidateProfile_Bypass_ValidList_Accepted(t *testing.T) {
	assertProfileAccepted(t, profileBypass("10.96.0.0/12,10.0.0.0/8,192.168.0.0/16"))
}

func TestValidateProfile_Bypass_TrailingComma_Accepted(t *testing.T) {
	assertProfileAccepted(t, profileBypass("10.96.0.0/12,"))
}

func TestValidateProfile_Bypass_Empty_Accepted(t *testing.T) {
	assertProfileAccepted(t, profileBypass(""))
}

func TestValidateProfile_Bypass_SlashZero_Rejected(t *testing.T) {
	assertProfileRejected(t, profileBypass("0.0.0.0/0"), "runtimeProfile.bypassCIDRs", "shorter than /8")
}

func TestValidateProfile_Bypass_ShorterThanEight_Rejected(t *testing.T) {
	assertProfileRejected(t, profileBypass("10.0.0.0/4"), "runtimeProfile.bypassCIDRs", "shorter than /8")
}

func TestValidateProfile_Bypass_HostBitsSet_Rejected(t *testing.T) {
	assertProfileRejected(t, profileBypass("10.0.0.5/8"), "runtimeProfile.bypassCIDRs", "host bits set")
}

func TestValidateProfile_Bypass_IPv6_Rejected(t *testing.T) {
	assertProfileRejected(t, profileBypass("2001:db8::/32"), "runtimeProfile.bypassCIDRs", "not IPv4")
}

func TestValidateProfile_Bypass_NotACIDR_Rejected(t *testing.T) {
	assertProfileRejected(t, profileBypass("10.0.0.0/8,notacidr"), "runtimeProfile.bypassCIDRs", "not a CIDR prefix")
}

func TestValidateProfile_Bypass_ExactlyMax_Accepted(t *testing.T) {
	assertProfileAccepted(t, profileBypass(manyPrefixes(injectorMaxBypassCIDRs)))
}

func TestValidateProfile_Bypass_OverMax_Rejected(t *testing.T) {
	assertProfileRejected(t, profileBypass(manyPrefixes(injectorMaxBypassCIDRs+1)), "runtimeProfile.bypassCIDRs", "more than the 64")
}

func TestValidateProfile_Bypass_SlashEightBoundary_Accepted(t *testing.T) {
	// Exactly /8 with no host bits is the shortest allowed prefix.
	assertProfileAccepted(t, profileBypass("10.0.0.0/8"))
}

// manyPrefixes builds n distinct host-bit-free /32 IPv4 prefixes so the entry
// count can be exercised without tripping any other invariant. /32 prefixes
// have no host bits and are longer than /8.
func manyPrefixes(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		// 10.<hi>.<lo>.0/24 — /24 has no host bits when the last octet is 0.
		hi := i / 256
		lo := i % 256
		b.WriteString("10.")
		b.WriteString(itoa(hi))
		b.WriteByte('.')
		b.WriteString(itoa(lo))
		b.WriteString(".0/24")
	}
	return b.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
