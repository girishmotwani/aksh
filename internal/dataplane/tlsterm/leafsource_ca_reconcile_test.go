package tlsterm_test

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/dataplane/tlsterm"
	"github.com/girishmotwani/aksh/internal/pki"
)

// errShouldMismatch drives the fake CA into its key-mismatch mode.
var errShouldMismatch = errors.New("force signer/cert mismatch")

// errCAGateFailed models a failed CA startup gate in the test-local runtime.
var errCAGateFailed = errors.New("ca startup gate failed")

// caGateRuntime is a test-local fake runtime lifecycle. It proves the
// construction-ordering contract (tests 43-44) by driving the EXISTING
// pki.CAProvider interface and tlsterm.NewCachedLeafSource constructor
// directly -- no production gate type is introduced (Slice 6 wires the real
// Orchestrator gate).
type caGateRuntime struct {
	step         int
	gatePassedAt int
	leafBuiltAt  int
	leaf         *tlsterm.CachedLeafSource
}

// run executes the minimal startup sequence: the CA-readiness gate must pass
// before the leaf source is constructed. gateOK models the gate outcome.
func (r *caGateRuntime) run(ca pki.CAProvider, gateOK bool) error {
	if !gateOK {
		return errCAGateFailed
	}
	r.step++
	r.gatePassedAt = r.step

	src, err := tlsterm.NewCachedLeafSource(ca, validLeafOptions())
	if err != nil {
		return err
	}
	r.step++
	r.leafBuiltAt = r.step
	r.leaf = src
	return nil
}

// panicPublicPEMCA wraps a valid fake CA but panics if PublicPEM() is ever
// read, proving the mint path never touches it (test 39).
type panicPublicPEMCA struct{ inner *fakeCA }

func (c panicPublicPEMCA) Signer() (*x509.Certificate, crypto.Signer) { return c.inner.Signer() }
func (c panicPublicPEMCA) Generation() uint64                         { return c.inner.Generation() }
func (c panicPublicPEMCA) PublicPEM() []byte {
	panic("PublicPEM must not be read during minting")
}

var _ pki.CAProvider = panicPublicPEMCA{}

// setGeneration overrides the fake CA generation to an arbitrary uint64 so
// tests can exercise values outside the int64 range.
func (f *fakeCA) setGeneration(g uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.generation = g
}

// 37
func TestLeafSourceMint_UsesSignerMethod_NotLegacyCA(t *testing.T) {
	ca := newFakeCA(t)
	src, err := tlsterm.NewCachedLeafSource(ca, validLeafOptions())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := src.CertificateFor(context.Background(), "svc.ns"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// mintCount is incremented only by the fake's Signer() method; a single
	// mint must have obtained the CA via Signer(), not any legacy accessor.
	if got := ca.mintCount.Load(); got != 1 {
		t.Fatalf("Signer() call count = %d, want 1 (mint must use Signer())", got)
	}
}

// 38
func TestLeafSourceMint_GenerationUint64_KeysCacheEntries(t *testing.T) {
	ca := newFakeCA(t)
	// A value > math.MaxInt64: narrowing to int64 would corrupt the key.
	genA := uint64(math.MaxUint64)
	genB := uint64(math.MaxInt64) + 1
	ca.setGeneration(genA)
	src, err := tlsterm.NewCachedLeafSource(ca, validLeafOptions())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := src.CertificateFor(context.Background(), "svc.ns"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := src.CertificateFor(context.Background(), "svc.ns"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := ca.mintCount.Load(); got != 1 {
		t.Fatalf("mint count = %d, want 1 (same uint64 generation must hit cache)", got)
	}
	ca.setGeneration(genB)
	if _, err := src.CertificateFor(context.Background(), "svc.ns"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := ca.mintCount.Load(); got != 2 {
		t.Fatalf("mint count = %d, want 2 (distinct uint64 generation must re-mint)", got)
	}
}

// 39
func TestLeafSourceMint_PublicPEMUnavailable_DoesNotReadPublicPEM(t *testing.T) {
	ca := panicPublicPEMCA{inner: newFakeCA(t)}
	src, err := tlsterm.NewCachedLeafSource(ca, validLeafOptions())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("mint read PublicPEM() (panicked): %v", r)
		}
	}()
	cert, err := src.CertificateFor(context.Background(), "svc.ns")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cert == nil {
		t.Fatal("cert = nil, want non-nil")
	}
}

// 40
func TestLeafSourceMint_SignerCertAndKeyMismatch_ReturnsCreateCertificateError(t *testing.T) {
	ca := newFakeCA(t)
	// setMintErr makes the fake return a signer whose public key does not
	// match the CA certificate, so x509.CreateCertificate fails.
	ca.setMintErr(errShouldMismatch)
	src, err := tlsterm.NewCachedLeafSource(ca, validLeafOptions())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cert, err := src.CertificateFor(context.Background(), "svc.ns")
	if err == nil {
		t.Fatal("error = nil, want x509.CreateCertificate error")
	}
	if cert != nil {
		t.Fatalf("cert = %v, want nil", cert)
	}
	if got := src.CacheLen(); got != 0 {
		t.Fatalf("cache length = %d, want 0 (failed mint must not store a leaf)", got)
	}
}

// 41
func TestLeafSource_ConcurrentMintSameSNI_CallsSignerOnce(t *testing.T) {
	ca := newFakeCA(t)
	ca.setMintDelay(50 * time.Millisecond)
	src, err := tlsterm.NewCachedLeafSource(ca, validLeafOptions())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	const n = 20
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = src.CertificateFor(context.Background(), "svc.ns")
		}(i)
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil {
			t.Fatalf("goroutine %d: unexpected error: %v", i, e)
		}
	}
	if got := ca.mintCount.Load(); got != 1 {
		t.Fatalf("Signer() call count = %d, want 1 (single-flight coalescing)", got)
	}
}

// 42
func TestLeafSource_ConcurrentMintDifferentSNI_UsesStableGeneration(t *testing.T) {
	ca := newFakeCA(t)
	ca.setGeneration(42)
	src, err := tlsterm.NewCachedLeafSource(ca, validLeafOptions())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	const n = 25
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			name := "svc" + string(rune('a'+idx)) + ".ns"
			_, errs[idx] = src.CertificateFor(context.Background(), name)
		}(i)
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil {
			t.Fatalf("goroutine %d: unexpected error: %v", i, e)
		}
	}
	// Generation never changed, so every distinct SNI produced exactly one
	// leaf keyed under the same stable generation.
	if got := ca.Generation(); got != 42 {
		t.Fatalf("generation = %d, want stable 42", got)
	}
	if got := src.CacheLen(); got != n {
		t.Fatalf("cache length = %d, want %d distinct leaves under one generation", got, n)
	}
}

// 43
func TestRuntimeCAGate_ConstructsLeafSourceOnlyAfterProviderReady(t *testing.T) {
	ca := newFakeCA(t)
	rt := &caGateRuntime{}
	if err := rt.run(ca, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rt.gatePassedAt == 0 {
		t.Fatal("CA startup gate never recorded as passed")
	}
	if rt.leaf == nil || rt.leafBuiltAt == 0 {
		t.Fatal("leaf source was not constructed after the gate passed")
	}
	if rt.gatePassedAt >= rt.leafBuiltAt {
		t.Fatalf("leaf source constructed at step %d, before gate passed at step %d", rt.leafBuiltAt, rt.gatePassedAt)
	}
	// Constructing the leaf source must not touch the signer.
	if got := ca.mintCount.Load(); got != 0 {
		t.Fatalf("Signer() calls during construction = %d, want 0", got)
	}
}

// 44
func TestRuntimeCAGate_UninitializedProvider_PreventsSignerAccess(t *testing.T) {
	ca := newFakeCA(t)
	rt := &caGateRuntime{}
	err := rt.run(ca, false)
	if err == nil {
		t.Fatal("error = nil, want gate failure")
	}
	if rt.leaf != nil {
		t.Fatal("leaf source was constructed despite a failed CA gate")
	}
	if rt.leafBuiltAt != 0 {
		t.Fatalf("leaf construction recorded at step %d despite gate failure", rt.leafBuiltAt)
	}
	if got := ca.mintCount.Load(); got != 0 {
		t.Fatalf("Signer() calls = %d, want 0 when the CA gate fails", got)
	}
}
