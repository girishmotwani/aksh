package capture

import (
	"fmt"
	"net/netip"
)

// BypassKeySize is the wire size of a bypass_cidr4 key: a host-order u32
// prefix length followed by the four network-order address bytes.
const BypassKeySize = 8

// bypassKey mirrors `struct bypass_key` in aksh_capture.c. It is the key of the
// LPM trie, and the kernel reads PrefixLen as a native u32 and Addr as raw
// bytes, so the field order and widths here are ABI, not a detail.
//
// Addr is [4]byte rather than uint32 so that the network-order bytes cannot be
// accidentally byte-swapped by a host-order integer conversion on the way in;
// netip.Addr.As4() already hands them over in the order the kernel compares.
type bypassKey struct {
	PrefixLen uint32
	Addr      [4]byte
}

// bypassKeyFor renders an IPv4 prefix as the LPM trie key the kernel matches
// against.
//
// It re-checks what Validate already checked. That is deliberate: this function
// is the last point before a key reaches the kernel, and an unmasked prefix
// here would silently create a bypass entry that never matches the destination
// the deployer named, which is far harder to diagnose than a load failure.
func bypassKeyFor(p netip.Prefix) (bypassKey, error) {
	canon, err := canonicalBypassPrefix(p)
	if err != nil {
		return bypassKey{}, err
	}
	return bypassKey{PrefixLen: uint32(canon.Bits()), Addr: canon.Addr().As4()}, nil
}

// canonicalBypassPrefix validates one entry and returns it as a pure IPv4
// prefix.
//
// The unmapping matters. ::ffff:10.96.0.0 is the 4-in-6 spelling of 10.96.0.0,
// and netip masks it in the IPv6 space, so comparing the caller's prefix to its
// own Masked() form would reject every mapped address as "host bits set". The
// canonical form is built first, and every check then runs on that, which is
// also what the kernel key must contain.
func canonicalBypassPrefix(p netip.Prefix) (netip.Prefix, error) {
	if !p.IsValid() {
		return netip.Prefix{}, fmt.Errorf("bypass prefix is invalid: %w", ErrInvalidBypassCIDR)
	}
	addr := p.Addr().Unmap()
	if !addr.Is4() {
		return netip.Prefix{}, fmt.Errorf("bypass prefix %v is not IPv4; 5A captures IPv4 only: %w", p, ErrInvalidBypassCIDR)
	}
	canon := netip.PrefixFrom(addr, p.Bits())
	if !canon.IsValid() {
		// Reachable when a 4-in-6 prefix carries IPv6 bits (say /108): the
		// address is IPv4 but the prefix length is not expressible as one.
		return netip.Prefix{}, fmt.Errorf("bypass prefix %v has a prefix length that is not valid for IPv4: %w", p, ErrInvalidBypassCIDR)
	}
	if canon.Bits() < minBypassPrefixBits {
		return netip.Prefix{}, fmt.Errorf("bypass prefix %v is shorter than /%d, which would leave arbitrary destinations unpoliced: %w",
			canon, minBypassPrefixBits, ErrInvalidBypassCIDR)
	}
	if canon.Masked() != canon {
		return netip.Prefix{}, fmt.Errorf("bypass prefix %v has host bits set; write it as %v if that is what you meant: %w",
			canon, canon.Masked(), ErrInvalidBypassCIDR)
	}
	return canon, nil
}
