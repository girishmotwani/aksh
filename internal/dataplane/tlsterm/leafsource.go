package tlsterm

import (
	"container/list"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/pki"
)

// leafCacheKey is the comparable cache key shared identically by the LRU
// cache and the single-flight in-flight map.
// identity is always the canonicalised server name.
type leafCacheKey struct {
	identity   string
	generation uint64
}

// leafCacheEntry is the value stored in the LRU cache.
type leafCacheEntry struct {
	key      leafCacheKey
	cert     *tls.Certificate
	mintedAt time.Time
}

// inflightMint tracks a single in-progress mint operation shared by every
// waiter for the same leafCacheKey.
type inflightMint struct {
	done chan struct{}
	cert *tls.Certificate
	err  error
}

// CachedLeafSource implements dataplane.LeafSource: a generation-aware,
// per-identity leaf-certificate cache with single-flight mint coalescing.
// See docs/design/S1a-dataplane-capture.md §8.2.
type CachedLeafSource struct {
	ca      pki.CAProvider
	opts    LeafOptions
	metrics audit.MetricsRecorder

	mu       sync.Mutex
	entries  map[leafCacheKey]*list.Element // list.Element.Value is *leafCacheEntry
	order    *list.List                     // front = most recently used
	inflight map[leafCacheKey]*inflightMint
}

// NewCachedLeafSource constructs a CachedLeafSource. ca must be non-nil;
// opts is validated via LeafOptions.Validate() (see spec rows #279-330).
func NewCachedLeafSource(ca pki.CAProvider, opts LeafOptions) (*CachedLeafSource, error) {
	return NewCachedLeafSourceWithMetrics(ca, opts, audit.NopMetricsRecorder{})
}

// NewCachedLeafSourceWithMetrics is NewCachedLeafSource with an explicit
// audit.MetricsRecorder, used by tests to observe LeafCacheHit/LeafCacheMiss
// and StageDuration calls (spec rows #299-300).
func NewCachedLeafSourceWithMetrics(ca pki.CAProvider, opts LeafOptions, metrics audit.MetricsRecorder) (*CachedLeafSource, error) {
	if ca == nil {
		return nil, ErrMissingCA
	}
	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidOptions, err)
	}
	if metrics == nil {
		metrics = audit.NopMetricsRecorder{}
	}
	return &CachedLeafSource{
		ca:       ca,
		opts:     opts,
		metrics:  metrics,
		entries:  make(map[leafCacheKey]*list.Element),
		order:    list.New(),
		inflight: make(map[leafCacheKey]*inflightMint),
	}, nil
}

// CacheLen reports the current number of cached entries. Exposed for tests
// verifying the LRU eviction bound (spec #295, #303).
func (s *CachedLeafSource) CacheLen() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.order.Len()
}

// CertificateFor implements dataplane.LeafSource. See
// docs/design/S1a-dataplane-capture.md §8.2 for the full
// single-flight/coalescing protocol.
func (s *CachedLeafSource) CertificateFor(ctx context.Context, serverName string) (*tls.Certificate, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if serverName == "" {
		return nil, ErrEmptyServerName
	}

	identity, err := CanonicaliseServerName(serverName)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSNI, err)
	}

	generation := s.ca.Generation()
	key := leafCacheKey{identity: identity, generation: generation}

	s.mu.Lock()
	if elem, ok := s.entries[key]; ok {
		entry := elem.Value.(*leafCacheEntry)
		if !s.expired(entry) {
			s.order.MoveToFront(elem)
			s.mu.Unlock()
			s.metrics.LeafCacheHit()
			return entry.cert, nil
		}
		// Expired: drop it so a fresh mint replaces it below.
		s.order.Remove(elem)
		delete(s.entries, key)
	}

	if entry, ok := s.inflight[key]; ok {
		s.mu.Unlock()
		select {
		case <-entry.done:
			return entry.cert, entry.err
		case <-ctx.Done():
			select {
			case <-entry.done:
				return entry.cert, entry.err
			default:
			}
			return nil, ctx.Err()
		}
	}

	owner := &inflightMint{done: make(chan struct{})}
	s.inflight[key] = owner
	s.mu.Unlock()

	s.metrics.LeafCacheMiss()

	mintDone := make(chan struct{})
	var cert *tls.Certificate
	var mintErr error
	go func() {
		defer close(mintDone)
		start := time.Now()
		cert, mintErr = s.mint(identity)
		s.metrics.StageDuration(audit.StageLeafMint, time.Since(start))
	}()

	select {
	case <-mintDone:
	case <-ctx.Done():
		select {
		case <-mintDone:
		default:
			// The mint continues in the background; the owner goroutine
			// still populates the cache for subsequent callers, but this
			// particular caller must not block past its own cancellation.
			go func() {
				<-mintDone
				s.publish(key, cert, mintErr, owner)
			}()
			return nil, ctx.Err()
		}
	}

	s.publish(key, cert, mintErr, owner)
	if mintErr != nil {
		return nil, mintErr
	}
	return cert, nil
}

// publish records the mint result into the cache (on success only) and
// signals all waiters via owner.done. Safe to call at most once per owner.
func (s *CachedLeafSource) publish(key leafCacheKey, cert *tls.Certificate, mintErr error, owner *inflightMint) {
	s.mu.Lock()
	delete(s.inflight, key)
	if mintErr == nil {
		entry := &leafCacheEntry{key: key, cert: cert, mintedAt: time.Now()}
		elem := s.order.PushFront(entry)
		s.entries[key] = elem
		s.evictLocked()
	}
	s.mu.Unlock()

	owner.cert = cert
	owner.err = mintErr
	close(owner.done)
}

// evictLocked removes least-recently-used entries until the cache is within
// opts.CacheEntries. Caller must hold s.mu.
func (s *CachedLeafSource) evictLocked() {
	max := s.opts.CacheEntries
	if max <= 0 {
		return
	}
	for s.order.Len() > max {
		oldest := s.order.Back()
		if oldest == nil {
			return
		}
		entry := oldest.Value.(*leafCacheEntry)
		delete(s.entries, entry.key)
		s.order.Remove(oldest)
	}
}

// expired reports whether entry is past its CacheTTL, boundary-inclusive:
// an entry exactly at the TTL boundary is treated as expired (spec #296).
func (s *CachedLeafSource) expired(entry *leafCacheEntry) bool {
	return !time.Now().Before(entry.mintedAt.Add(s.opts.CacheTTL))
}

// mint creates one fresh ECDSA P-256 leaf certificate for identity, signed
// by s.ca's current CA cert/signer. identity is bound into the certificate
// via SAN (DNSNames), which is what Go's crypto/tls hostname verification
// checks (Go 1.15+ ignores CN entirely).
func (s *CachedLeafSource) mint(identity string) (*tls.Certificate, error) {
	caCert, caSigner := s.ca.Signer()
	if caCert == nil || caSigner == nil {
		return nil, fmt.Errorf("tlsterm: CA provider returned nil cert/signer for %q", identity)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("tlsterm: generate leaf key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("tlsterm: generate serial: %w", err)
	}

	notBefore := time.Now().Add(-s.opts.Backdate)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: identity},
		DNSNames:     []string{identity},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(s.opts.LeafLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caSigner)
	if err != nil {
		return nil, fmt.Errorf("tlsterm: sign leaf: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{der, caCert.Raw},
		PrivateKey:  leafKey,
	}, nil
}
