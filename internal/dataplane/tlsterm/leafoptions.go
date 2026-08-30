package tlsterm

import (
	"crypto/tls"
	"slices"
	"time"
)

// LeafOptions configures CachedLeafSource's leaf-certificate minting and
// caching behaviour. See docs/design/S1a-dataplane-capture.md §8.2/§11.1.
type LeafOptions struct {
	CacheEntries      int // caller-supplied; must be in range [16, 65536] (no implicit default)
	CacheTTL          time.Duration
	LeafLifetime      time.Duration // must exceed CacheTTL
	Backdate          time.Duration
	MintRate          float64
	MintBurst         int
	NextProtos        []string // must be a subset of {"h2", "http/1.1"}
	MinVersion        uint16   // must be at least tls.VersionTLS12
	AllowSelfSignedCA bool
}

// allowedNextProtos is the design's fixed ALPN allow-list; see
// docs/design/S1a-dataplane-capture.md §8.2's NextProtos validation rule.
var allowedNextProtos = []string{"h2", "http/1.1"}

// Validate checks LeafOptions for the ordered set of rules in
// docs/design/S1a-dataplane-capture.md §8.2 (first failing check wins).
func (o LeafOptions) Validate() error {
	if o.LeafLifetime == 0 {
		return ErrMissingLeafLifetime
	}
	if o.CacheTTL <= 0 {
		return ErrMissingCacheTTL
	}
	if o.LeafLifetime <= o.CacheTTL {
		return ErrInvalidLifetimeOrdering
	}
	if o.MinVersion == 0 {
		return ErrMissingMinVersion
	}
	if o.MinVersion < tls.VersionTLS12 {
		return ErrMinVersionTooLow
	}
	if len(o.NextProtos) == 0 {
		return ErrMissingNextProtos
	}
	for _, proto := range o.NextProtos {
		if !slices.Contains(allowedNextProtos, proto) {
			return ErrInvalidNextProtos
		}
	}
	if o.CacheEntries < 16 || o.CacheEntries > 65536 {
		return ErrInvalidCacheEntries
	}
	if o.MintRate <= 0 {
		return ErrInvalidMintRate
	}
	if o.MintBurst < 1 {
		return ErrInvalidMintBurst
	}
	if o.Backdate < 0 {
		return ErrInvalidBackdate
	}
	return nil
}
