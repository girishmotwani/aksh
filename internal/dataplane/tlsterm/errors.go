package tlsterm

import "errors"

// Sentinel errors returned by SNI canonicalisation, LeafOptions validation,
// leaf-source construction, and the terminator's ClientHello handling.
var (
	// SNI canonicalisation (sni.go). ErrEmptySNI is returned when the raw
	// input string to CanonicaliseServerName is the empty string. See also
	// ErrNoSNI (Terminator's ClientHello.ServerName is empty) and
	// ErrEmptyServerName (CachedLeafSource's identity argument is empty) --
	// all three are "empty server name" conditions at different layers of
	// the call chain (ClientHello -> Terminator -> CachedLeafSource ->
	// CanonicaliseServerName); callers that need to treat any of them
	// uniformly should check all three explicitly.
	ErrEmptySNI   = errors.New("tlsterm: server name is empty")
	ErrSNITooLong = errors.New("tlsterm: server name exceeds 255 bytes")
	ErrInvalidSNI = errors.New("tlsterm: server name is not a valid DNS hostname")

	// LeafOptions validation (leafoptions.go).
	ErrMissingLeafLifetime     = errors.New("tlsterm: LeafLifetime is required")
	ErrMissingCacheTTL         = errors.New("tlsterm: CacheTTL is required")
	ErrInvalidLifetimeOrdering = errors.New("tlsterm: LeafLifetime must be greater than CacheTTL")
	ErrMissingMinVersion       = errors.New("tlsterm: MinVersion is required")
	ErrMinVersionTooLow        = errors.New("tlsterm: MinVersion must be at least TLS 1.2")
	ErrMissingNextProtos       = errors.New("tlsterm: NextProtos is required")
	ErrInvalidNextProtos       = errors.New("tlsterm: NextProtos contains an unsupported protocol")

	// Leaf-source construction (leafsource.go).
	ErrMissingCA      = errors.New("tlsterm: CA provider is required")
	ErrInvalidOptions = errors.New("tlsterm: LeafOptions is invalid")

	// Terminator construction (terminator.go).
	ErrMissingLeafSource = errors.New("tlsterm: leaf source is required")

	// LeafOptions validation, cont'd (leafoptions.go).
	ErrInvalidCacheEntries = errors.New("tlsterm: CacheEntries must be in range [16, 65536]")
	ErrInvalidMintRate     = errors.New("tlsterm: MintRate must be greater than zero")
	ErrInvalidMintBurst    = errors.New("tlsterm: MintBurst must be at least 1")
	ErrInvalidBackdate     = errors.New("tlsterm: Backdate must not be negative")

	// Terminator ClientHello handling (terminator.go). ErrNoSNI is returned
	// when hello.ServerName is the empty string (the field was never set
	// by the client); distinct from ErrInvalidSNI, which is returned when
	// a non-empty ServerName fails canonicalisation. See ErrEmptySNI's
	// comment above for how this relates to the other empty-name sentinels.
	ErrNoSNI = errors.New("tlsterm: ClientHello did not provide a server name")
	// ErrEmptyServerName is returned by CachedLeafSource.CertificateFor
	// when its identity argument is the empty string; distinct from
	// ErrNoSNI/ErrEmptySNI, which relate to the raw ClientHello/SNI input
	// upstream of canonicalisation. See ErrEmptySNI's comment above for how
	// this relates to the other empty-name sentinels.
	ErrEmptyServerName    = errors.New("tlsterm: leaf-source identity argument is empty")
	ErrMissingClientHello = errors.New("tlsterm: ClientHelloInfo must not be nil")

	// Terminator post-handshake assertion (terminator.go).
	ErrHandshakeAssertFailed = errors.New("tlsterm: post-handshake assertion failed")
)
