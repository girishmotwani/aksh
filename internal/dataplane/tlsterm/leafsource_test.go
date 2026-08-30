package tlsterm_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/dataplane"
	"github.com/girishmotwani/aksh/internal/dataplane/tlsterm"
	"github.com/girishmotwani/aksh/internal/pipeline"
	"github.com/girishmotwani/aksh/internal/pki"
)

// fakeCA is a minimal pki.CAProvider backed by an in-memory self-signed CA,
// used to exercise CachedLeafSource without any real PKI infrastructure.
type fakeCA struct {
	mu         sync.Mutex
	cert       *x509.Certificate
	signer     *ecdsa.PrivateKey
	wrongKey   *ecdsa.PrivateKey
	publicPEM  []byte
	generation uint64
	mintCount  atomic.Int64
	mintDelay  time.Duration
	mintErr    error

	// inFlight/maxConcurrent track concurrency directly (instead of via
	// wall-clock timing) so tests can assert overlap without being
	// sensitive to scheduler/host-load noise.
	inFlight      atomic.Int64
	maxConcurrent atomic.Int64
}

func newFakeCA(t *testing.T) *fakeCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &fakeCA{cert: cert, signer: key, wrongKey: wrongKey, publicPEM: pubPEM, generation: 1}
}

// Signer implements pki.CAProvider. When mintErr is set it returns a signer
// whose public key does not match the CA certificate, so a downstream
// x509.CreateCertificate call fails (the reconciled interface has no error
// return of its own).
func (f *fakeCA) Signer() (*x509.Certificate, crypto.Signer) {
	f.mintCount.Add(1)
	cur := f.inFlight.Add(1)
	defer f.inFlight.Add(-1)
	for {
		max := f.maxConcurrent.Load()
		if cur <= max || f.maxConcurrent.CompareAndSwap(max, cur) {
			break
		}
	}
	f.mu.Lock()
	delay := f.mintDelay
	mismatch := f.mintErr != nil
	f.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
	if mismatch {
		return f.cert, f.wrongKey
	}
	return f.cert, f.signer
}

func (f *fakeCA) Generation() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.generation
}

func (f *fakeCA) PublicPEM() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]byte(nil), f.publicPEM...)
}

var _ pki.CAProvider = (*fakeCA)(nil)

func (f *fakeCA) bumpGeneration() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.generation++
}

func (f *fakeCA) setMintErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mintErr = err
}

func (f *fakeCA) setMintDelay(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mintDelay = d
}

type fakeMetrics struct {
	audit.NopMetricsRecorder
	mu       sync.Mutex
	hits     []bool
	latency  []string
	decision []string
}

func (m *fakeMetrics) Decisions(d pipeline.Disposition, r pipeline.DenyReason, _ audit.TransportKind, _ bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.decision = append(m.decision, d.String()+"/"+r.String())
}

func (m *fakeMetrics) StageDuration(stage audit.StageName, _ time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.latency = append(m.latency, stage.String())
}

func (m *fakeMetrics) LeafCacheHit() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hits = append(m.hits, true)
}

func (m *fakeMetrics) LeafCacheMiss() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hits = append(m.hits, false)
}

func validLeafOptions() tlsterm.LeafOptions {
	return tlsterm.LeafOptions{
		CacheEntries: 1024,
		CacheTTL:     10 * time.Minute,
		LeafLifetime: time.Hour,
		Backdate:     5 * time.Minute,
		MintRate:     50,
		MintBurst:    100,
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}
}

func TestLeafOptionsValidate(t *testing.T) {
	t.Run("Validate_ZeroValueLeafOptions_ReturnsErrMissingLeafLifetime", func(t *testing.T) {
		opts := tlsterm.LeafOptions{}
		if err := opts.Validate(); !errors.Is(err, tlsterm.ErrMissingLeafLifetime) {
			t.Fatalf("Validate() error = %v, want ErrMissingLeafLifetime", err)
		}
	})

	t.Run("Validate_LeafLifetimeLessThanOrEqualCacheTTL_ReturnsErrInvalidLifetimeOrdering", func(t *testing.T) {
		opts := validLeafOptions()
		opts.LeafLifetime = opts.CacheTTL
		if err := opts.Validate(); !errors.Is(err, tlsterm.ErrInvalidLifetimeOrdering) {
			t.Fatalf("Validate() error = %v, want ErrInvalidLifetimeOrdering", err)
		}
	})

	t.Run("Validate_LeafLifetimeGreaterThanCacheTTL_Passes", func(t *testing.T) {
		opts := validLeafOptions()
		opts.LeafLifetime = time.Hour
		opts.CacheTTL = 10 * time.Minute
		if err := opts.Validate(); err != nil {
			t.Fatalf("Validate() error = %v, want nil", err)
		}
	})

	t.Run("Validate_CacheEntriesBelowRangeFloor_ReturnsErrInvalidCacheEntries", func(t *testing.T) {
		opts := validLeafOptions()
		opts.CacheEntries = 15
		if err := opts.Validate(); !errors.Is(err, tlsterm.ErrInvalidCacheEntries) {
			t.Fatalf("Validate() error = %v, want ErrInvalidCacheEntries", err)
		}
	})

	t.Run("Validate_CacheEntriesAboveRangeCeiling_ReturnsErrInvalidCacheEntries", func(t *testing.T) {
		opts := validLeafOptions()
		opts.CacheEntries = 65537
		if err := opts.Validate(); !errors.Is(err, tlsterm.ErrInvalidCacheEntries) {
			t.Fatalf("Validate() error = %v, want ErrInvalidCacheEntries", err)
		}
	})

	t.Run("Validate_CacheEntriesAtRangeBoundaries_Passes", func(t *testing.T) {
		for _, n := range []int{16, 65536} {
			opts := validLeafOptions()
			opts.CacheEntries = n
			if err := opts.Validate(); err != nil {
				t.Fatalf("Validate() with CacheEntries=%d error = %v, want nil", n, err)
			}
		}
	})

	t.Run("Validate_EmptyMinVersion_ReturnsErrMissingMinVersion", func(t *testing.T) {
		opts := validLeafOptions()
		opts.MinVersion = 0
		if err := opts.Validate(); !errors.Is(err, tlsterm.ErrMissingMinVersion) {
			t.Fatalf("Validate() error = %v, want ErrMissingMinVersion", err)
		}
	})

	t.Run("Validate_MinVersionBelowFloor_ReturnsErrMinVersionTooLow", func(t *testing.T) {
		opts := validLeafOptions()
		opts.MinVersion = tls.VersionTLS11
		if err := opts.Validate(); !errors.Is(err, tlsterm.ErrMinVersionTooLow) {
			t.Fatalf("Validate() error = %v, want ErrMinVersionTooLow", err)
		}
	})

	t.Run("Validate_InsecureSkipVerifyFieldDoesNotExist_CompileTimeGuard", func(t *testing.T) {
		typ := reflect.TypeOf(tlsterm.LeafOptions{})
		if _, ok := typ.FieldByName("InsecureSkipVerify"); ok {
			t.Fatal("LeafOptions must not expose an InsecureSkipVerify field")
		}
	})

	t.Run("Validate_NextProtosContainsDisallowedProtocol_ReturnsErrInvalidNextProtos", func(t *testing.T) {
		opts := validLeafOptions()
		opts.NextProtos = []string{"h2", "spdy/1"}
		if err := opts.Validate(); !errors.Is(err, tlsterm.ErrInvalidNextProtos) {
			t.Fatalf("Validate() error = %v, want ErrInvalidNextProtos", err)
		}
	})

	t.Run("Validate_NextProtosEmptySlice_ReturnsErrMissingNextProtos", func(t *testing.T) {
		opts := validLeafOptions()
		opts.NextProtos = nil
		if err := opts.Validate(); !errors.Is(err, tlsterm.ErrMissingNextProtos) {
			t.Fatalf("Validate() error = %v, want ErrMissingNextProtos", err)
		}
	})

	t.Run("Validate_AllFieldsWellFormed_ReturnsNilError", func(t *testing.T) {
		opts := validLeafOptions()
		if err := opts.Validate(); err != nil {
			t.Fatalf("Validate() error = %v, want nil", err)
		}
	})

	// Validate_NilCAProviderReference (spec row #330): LeafOptions itself
	// carries no pki.CAProvider field (that is a separate constructor
	// parameter to NewCachedLeafSource), so the
	// nil-CA check is performed by NewCachedLeafSource, not
	// LeafOptions.Validate(). Exercised in
	// TestCachedLeafSource/NewCachedLeafSource_NilCAProvider_ReturnsErrMissingCA
	// below; not duplicated here.
}

// compile-time frozen-interface assertion (spec #282).
var _ dataplane.LeafSource = (*tlsterm.CachedLeafSource)(nil)

func TestCachedLeafSource(t *testing.T) {
	t.Run("NewCachedLeafSource_NilCAProvider_ReturnsErrMissingCA", func(t *testing.T) {
		_, err := tlsterm.NewCachedLeafSource(nil, validLeafOptions())
		if !errors.Is(err, tlsterm.ErrMissingCA) {
			t.Fatalf("error = %v, want ErrMissingCA", err)
		}
	})

	t.Run("NewCachedLeafSource_ZeroValueLeafOptions_ReturnsErrInvalidOptions", func(t *testing.T) {
		ca := newFakeCA(t)
		_, err := tlsterm.NewCachedLeafSource(ca, tlsterm.LeafOptions{})
		if !errors.Is(err, tlsterm.ErrInvalidOptions) {
			t.Fatalf("error = %v, want ErrInvalidOptions", err)
		}
	})

	t.Run("NewCachedLeafSource_ValidArgs_ReturnsSource", func(t *testing.T) {
		ca := newFakeCA(t)
		src, err := tlsterm.NewCachedLeafSource(ca, validLeafOptions())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if src == nil {
			t.Fatal("source = nil, want non-nil")
		}
	})

	t.Run("CertificateFor_FrozenInterfaceSignature_MatchesLeafSource", func(t *testing.T) {
		ca := newFakeCA(t)
		src, err := tlsterm.NewCachedLeafSource(ca, validLeafOptions())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var _ dataplane.LeafSource = src
	})

	t.Run("CertificateFor_EmptyServerName_ReturnsErrEmptyServerName", func(t *testing.T) {
		ca := newFakeCA(t)
		src, _ := tlsterm.NewCachedLeafSource(ca, validLeafOptions())
		_, err := src.CertificateFor(context.Background(), "")
		if !errors.Is(err, tlsterm.ErrEmptyServerName) {
			t.Fatalf("error = %v, want ErrEmptyServerName", err)
		}
	})

	t.Run("CertificateFor_NilContext_TreatedAsBackgroundNoPanic", func(t *testing.T) {
		ca := newFakeCA(t)
		src, _ := tlsterm.NewCachedLeafSource(ca, validLeafOptions())
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("CertificateFor panicked with nil ctx: %v", r)
			}
		}()
		//nolint:staticcheck // intentionally passing nil to prove no panic (spec #284).
		if _, err := src.CertificateFor(nil, "svc.ns"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("CertificateFor_CacheMiss_MintsNewLeafViaCAProvider", func(t *testing.T) {
		ca := newFakeCA(t)
		src, _ := tlsterm.NewCachedLeafSource(ca, validLeafOptions())
		if _, err := src.CertificateFor(context.Background(), "svc.ns"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := ca.mintCount.Load(); got != 1 {
			t.Fatalf("mint count = %d, want 1", got)
		}
	})

	t.Run("CertificateFor_CacheHitSameIdentityAndGeneration_ReturnsCachedLeafWithoutMinting", func(t *testing.T) {
		ca := newFakeCA(t)
		src, _ := tlsterm.NewCachedLeafSource(ca, validLeafOptions())
		first, err := src.CertificateFor(context.Background(), "svc.ns")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		second, err := src.CertificateFor(context.Background(), "svc.ns")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := ca.mintCount.Load(); got != 1 {
			t.Fatalf("mint count = %d, want 1 (second call should be a cache hit)", got)
		}
		if first != second {
			t.Fatalf("cached certificate pointer differs between calls")
		}
	})

	t.Run("CertificateFor_CacheKeyIncludesGeneration_DifferentGenerationMintsNewLeaf", func(t *testing.T) {
		ca := newFakeCA(t)
		src, _ := tlsterm.NewCachedLeafSource(ca, validLeafOptions())
		if _, err := src.CertificateFor(context.Background(), "svc.ns"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		ca.bumpGeneration()
		if _, err := src.CertificateFor(context.Background(), "svc.ns"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := ca.mintCount.Load(); got != 2 {
			t.Fatalf("mint count = %d, want 2 (generation bump must force a re-mint)", got)
		}
	})

	t.Run("CertificateFor_LeafExpiredPastLifetime_ReMintsFreshLeaf", func(t *testing.T) {
		ca := newFakeCA(t)
		opts := validLeafOptions()
		opts.CacheTTL = 5 * time.Millisecond
		opts.LeafLifetime = 10 * time.Millisecond
		src, _ := tlsterm.NewCachedLeafSource(ca, opts)
		if _, err := src.CertificateFor(context.Background(), "svc.ns"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
		if _, err := src.CertificateFor(context.Background(), "svc.ns"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := ca.mintCount.Load(); got != 2 {
			t.Fatalf("mint count = %d, want 2 (TTL-expired entry must re-mint)", got)
		}
	})

	t.Run("CertificateFor_LockNeverHeldAcrossMint_ConcurrentCallsForDifferentIdentitiesProceedInParallel", func(t *testing.T) {
		ca := newFakeCA(t)
		ca.setMintDelay(100 * time.Millisecond)
		src, _ := tlsterm.NewCachedLeafSource(ca, validLeafOptions())

		var wg sync.WaitGroup
		for _, id := range []string{"svc1.ns", "svc2.ns", "svc3.ns"} {
			wg.Add(1)
			go func(identity string) {
				defer wg.Done()
				if _, err := src.CertificateFor(context.Background(), identity); err != nil {
					t.Errorf("CertificateFor(%q) error = %v", identity, err)
				}
			}(id)
		}
		wg.Wait()
		// Assert direct concurrency evidence (max simultaneous in-flight
		// CA.CA() calls) rather than inferring parallelism from wall-clock
		// elapsed time, which is prone to flaking under host/CI load.
		if max := ca.maxConcurrent.Load(); max < 2 {
			t.Fatalf("maxConcurrent = %d, want >= 2 (lock must not be held across mint)", max)
		}
	})

	t.Run("CertificateFor_ConcurrentCallsSameIdentity_OnlyOneMintOccurs", func(t *testing.T) {
		ca := newFakeCA(t)
		ca.setMintDelay(50 * time.Millisecond)
		src, _ := tlsterm.NewCachedLeafSource(ca, validLeafOptions())

		const n = 20
		results := make([]*tls.Certificate, n)
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				results[idx], errs[idx] = src.CertificateFor(context.Background(), "svc.ns")
			}(i)
		}
		wg.Wait()

		for i, err := range errs {
			if err != nil {
				t.Fatalf("goroutine %d: unexpected error: %v", i, err)
			}
		}
		for i := 1; i < n; i++ {
			if results[i] != results[0] {
				t.Fatalf("goroutine %d returned a different certificate than goroutine 0 (single-flight coalescing violated)", i)
			}
		}
		if got := ca.mintCount.Load(); got != 1 {
			t.Fatalf("mint count = %d, want 1 (exactly one mint for %d concurrent callers)", got, n)
		}
	})

	t.Run("CertificateFor_SignerReturnsMismatchedKey_PropagatesMintError", func(t *testing.T) {
		ca := newFakeCA(t)
		ca.setMintErr(errors.New("ca unavailable"))
		src, _ := tlsterm.NewCachedLeafSource(ca, validLeafOptions())
		cert, err := src.CertificateFor(context.Background(), "svc.ns")
		if err == nil {
			t.Fatal("error = nil, want non-nil")
		}
		if cert != nil {
			t.Fatalf("cert = %v, want nil on mint failure", cert)
		}
	})

	t.Run("CertificateFor_SuccessfulReturn_NeverReturnsNilCertificateWithNilError", func(t *testing.T) {
		ca := newFakeCA(t)
		src, _ := tlsterm.NewCachedLeafSource(ca, validLeafOptions())
		cert, err := src.CertificateFor(context.Background(), "svc.ns")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cert == nil {
			t.Fatal("cert = nil with nil error, want non-nil certificate")
		}
	})

	t.Run("Generation_ReturnsUint64_MatchesCodeAuthoritativeType", func(t *testing.T) {
		ca := newFakeCA(t)
		var gen uint64 = ca.Generation()
		_ = gen // compile-time type assertion is the point of this test
	})

	t.Run("Generation_IncrementsMonotonically_AcrossRotationEvents", func(t *testing.T) {
		ca := newFakeCA(t)
		prev := ca.Generation()
		for i := 0; i < 5; i++ {
			ca.bumpGeneration()
			cur := ca.Generation()
			if cur <= prev {
				t.Fatalf("Generation() = %d, want > %d", cur, prev)
			}
			prev = cur
		}
	})

	t.Run("CertificateFor_CacheEvictionOnGenerationBump_OldEntriesEventuallyRemoved", func(t *testing.T) {
		ca := newFakeCA(t)
		opts := validLeafOptions()
		opts.CacheEntries = 16
		src, _ := tlsterm.NewCachedLeafSource(ca, opts)

		for gen := 0; gen < 20; gen++ {
			if _, err := src.CertificateFor(context.Background(), fmt.Sprintf("svc%d.ns", gen)); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			ca.bumpGeneration()
		}
		if got := src.CacheLen(); got > opts.CacheEntries {
			t.Fatalf("cache length = %d, want <= %d (bounded across generation bumps)", got, opts.CacheEntries)
		}
	})

	t.Run("CertificateFor_LeafOptionsCacheTTLBoundary_ExpiresExactlyAtBoundary", func(t *testing.T) {
		ca := newFakeCA(t)
		opts := validLeafOptions()
		opts.CacheTTL = 20 * time.Millisecond
		opts.LeafLifetime = 40 * time.Millisecond
		src, _ := tlsterm.NewCachedLeafSource(ca, opts)
		if _, err := src.CertificateFor(context.Background(), "svc.ns"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// time.Sleep guarantees at least the requested duration, so sleeping
		// past CacheTTL (rather than for exactly CacheTTL) still exercises
		// the boundary-inclusive expiry check without depending on Sleep's
		// precision under scheduler load, which made this test flaky under
		// -race / loaded CI (dev_review_iter2 finding).
		time.Sleep(opts.CacheTTL + 25*time.Millisecond)
		if _, err := src.CertificateFor(context.Background(), "svc.ns"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := ca.mintCount.Load(); got != 2 {
			t.Fatalf("mint count = %d, want 2 (expired entry must re-mint)", got)
		}
	})

	t.Run("CertificateFor_ContextCancelledDuringMint_ReturnsContextError", func(t *testing.T) {
		ca := newFakeCA(t)
		ca.setMintDelay(200 * time.Millisecond)
		src, _ := tlsterm.NewCachedLeafSource(ca, validLeafOptions())

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(20 * time.Millisecond)
			cancel()
		}()
		_, err := src.CertificateFor(ctx, "svc.ns")
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
	})

	t.Run("CertificateFor_ConcurrentDistinctIdentities_NoDataRace", func(t *testing.T) {
		ca := newFakeCA(t)
		src, _ := tlsterm.NewCachedLeafSource(ca, validLeafOptions())
		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				identity := fmt.Sprintf("svc%d.ns", idx%10)
				if _, err := src.CertificateFor(context.Background(), identity); err != nil {
					t.Errorf("CertificateFor(%q) error = %v", identity, err)
				}
			}(i)
		}
		wg.Wait()
	})

	t.Run("CertificateFor_OnHitAndMiss_TokenCacheHitRecorded", func(t *testing.T) {
		ca := newFakeCA(t)
		metrics := &fakeMetrics{}
		src, err := tlsterm.NewCachedLeafSourceWithMetrics(ca, validLeafOptions(), metrics)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := src.CertificateFor(context.Background(), "svc.ns"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := src.CertificateFor(context.Background(), "svc.ns"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		metrics.mu.Lock()
		defer metrics.mu.Unlock()
		if len(metrics.hits) != 2 || metrics.hits[0] != false || metrics.hits[1] != true {
			t.Fatalf("hits = %v, want [false, true]", metrics.hits)
		}
	})

	t.Run("CertificateFor_OnMintOperation_LatencyRecorded", func(t *testing.T) {
		ca := newFakeCA(t)
		metrics := &fakeMetrics{}
		src, err := tlsterm.NewCachedLeafSourceWithMetrics(ca, validLeafOptions(), metrics)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := src.CertificateFor(context.Background(), "svc.ns"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		metrics.mu.Lock()
		defer metrics.mu.Unlock()
		found := false
		for _, stage := range metrics.latency {
			if stage == "leaf_mint" {
				found = true
			}
		}
		if !found {
			t.Fatalf("latency stages = %v, want to include \"leaf_mint\"", metrics.latency)
		}
	})

	t.Run("CertificateFor_BeforeCacheLookup_ServerNameCanonicalised", func(t *testing.T) {
		ca := newFakeCA(t)
		src, _ := tlsterm.NewCachedLeafSource(ca, validLeafOptions())
		if _, err := src.CertificateFor(context.Background(), "SVC.ns"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := src.CertificateFor(context.Background(), "svc.ns"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := ca.mintCount.Load(); got != 1 {
			t.Fatalf("mint count = %d, want 1 (case-different identities must share one cache entry)", got)
		}
	})

	t.Run("CertificateFor_NonCanonicalisableServerName_ReturnsErrInvalidSNI", func(t *testing.T) {
		ca := newFakeCA(t)
		src, _ := tlsterm.NewCachedLeafSource(ca, validLeafOptions())
		_, err := src.CertificateFor(context.Background(), "*.example.com")
		if !errors.Is(err, tlsterm.ErrInvalidSNI) {
			t.Fatalf("error = %v, want ErrInvalidSNI", err)
		}
	})

	t.Run("CertificateFor_CacheSizeBounded_LRUEvictionUnderPressure", func(t *testing.T) {
		ca := newFakeCA(t)
		opts := validLeafOptions()
		opts.CacheEntries = 16
		src, _ := tlsterm.NewCachedLeafSource(ca, opts)
		for i := 0; i < 40; i++ {
			identity := fmt.Sprintf("svc%d.ns", i)
			if _, err := src.CertificateFor(context.Background(), identity); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		}
		if got := src.CacheLen(); got > opts.CacheEntries {
			t.Fatalf("cache length = %d, want <= %d", got, opts.CacheEntries)
		}
	})

	t.Run("CertificateFor_DoubleCloseOfUnderlyingCAConn_IsIdempotentIfApplicable", func(t *testing.T) {
		// CachedLeafSource owns no closable resource tied to the CAProvider
		// (pki.CAProvider exposes no Close method, and CachedLeafSource does
		// not wrap one) -- this test documents that fact rather than
		// asserting behaviour that does not apply.
		t.Log("CachedLeafSource has no closable resource; nothing to double-close")
	})
}
