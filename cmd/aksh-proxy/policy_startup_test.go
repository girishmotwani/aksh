package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	v1alpha1 "github.com/girishmotwani/aksh/api/v1alpha1"
	"github.com/girishmotwani/aksh/internal/config"
	"github.com/girishmotwani/aksh/internal/policy/watch"
	"github.com/girishmotwani/aksh/internal/runtime"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kwatch "k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

// fakeAkshClient is a controllable watch.AkshPolicyClient test double for the
// policy-startup tests. listFn drives the first snapshot (or a persistent
// error); Watch returns a never-firing fake watch so the watcher blocks after
// the initial list.
type fakeAkshClient struct {
	listFn func() (*v1alpha1.AkshPolicyList, error)
}

func (f fakeAkshClient) List(context.Context, metav1.ListOptions) (*v1alpha1.AkshPolicyList, error) {
	if f.listFn != nil {
		return f.listFn()
	}
	return &v1alpha1.AkshPolicyList{}, nil
}

func (f fakeAkshClient) Watch(context.Context, metav1.ListOptions) (kwatch.Interface, error) {
	return kwatch.NewFake(), nil
}

// fakePolicyWatcher is a policyWatcher double whose Run/WaitFirstSnapshot return
// caller-chosen results, exercising the Run-goroutine error branches (#91-#93)
// that the real *watch.Watcher never produces.
type fakePolicyWatcher struct {
	runErr  error
	waitErr error
}

func (f *fakePolicyWatcher) Run(context.Context) error               { return f.runErr }
func (f *fakePolicyWatcher) WaitFirstSnapshot(context.Context) error { return f.waitErr }

// upstreamSeamsOK overrides the pre-watcher seams to succeed and restores them
// on cleanup, so a test can focus on the watcher/first-snapshot behaviour.
func upstreamSeamsOK(t *testing.T, client watch.AkshPolicyClient) {
	t.Helper()
	oic, odc, oac := inClusterConfig, newDynamicClient, newAkshPolicyClient
	t.Cleanup(func() { inClusterConfig, newDynamicClient, newAkshPolicyClient = oic, odc, oac })
	inClusterConfig = func() (*rest.Config, error) { return &rest.Config{}, nil }
	newDynamicClient = func(*rest.Config) (dynamic.Interface, error) { return nil, nil }
	newAkshPolicyClient = func(dynamic.Interface, string) (watch.AkshPolicyClient, error) { return client, nil }
}

// policyCfg builds a config whose pod-labels file exists, since startup now
// fails closed when the pod's own labels cannot be read (#35). Tests that want
// that failure use policyCfgLabels with an unreadable path.
func policyCfg(t *testing.T, timeout time.Duration) config.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "labels")
	if err := os.WriteFile(path, []byte("app=\"agent\"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return policyCfgLabels(path, timeout)
}

func policyCfgLabels(labelsPath string, timeout time.Duration) config.Config {
	return config.Config{Policy: config.PolicyConfig{
		Namespace:            "ns",
		MaxStaleness:         45 * time.Second,
		FirstSnapshotTimeout: timeout,
		PodLabelsPath:        labelsPath,
	}}
}

// #35: the pod's own labels decide which AkshPolicy selectors match it, so an
// unreadable labels file must stop startup rather than proceed with an unknown
// label set.
func TestProductionPolicyStartup_MissingPodLabelsFile_ReturnsErrorNilStore(t *testing.T) {
	upstreamSeamsOK(t, fakeAkshClient{})
	cfg := policyCfgLabels(filepath.Join(t.TempDir(), "absent"), 2*time.Second)

	store, err := productionPolicyStartup(cfg, nil, nil, nil)(context.Background())
	if err == nil {
		t.Fatal("productionPolicyStartup() error = nil, want a fail-closed error")
	}
	if store != nil {
		t.Fatalf("productionPolicyStartup() store = %v, want nil on fail-closed", store)
	}
}

func TestProductionPolicyStartup_MalformedPodLabelsFile_ReturnsErrorNilStore(t *testing.T) {
	upstreamSeamsOK(t, fakeAkshClient{})
	path := filepath.Join(t.TempDir(), "labels")
	if err := os.WriteFile(path, []byte("app=unquoted\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	store, err := productionPolicyStartup(policyCfgLabels(path, 2*time.Second), nil, nil, nil)(context.Background())
	if err == nil {
		t.Fatal("productionPolicyStartup() error = nil, want a fail-closed error")
	}
	if store != nil {
		t.Fatalf("productionPolicyStartup() store = %v, want nil on fail-closed", store)
	}
}

// The labels must actually reach the watcher, not merely be read and dropped.
func TestProductionPolicyStartup_PodLabels_PassedToWatcherOptions(t *testing.T) {
	upstreamSeamsOK(t, fakeAkshClient{})
	onw := newWatcher
	t.Cleanup(func() { newWatcher = onw })
	var got map[string]string
	newWatcher = func(opts watch.Options, _ watch.AkshPolicyClient, _ *watch.Store, _ watch.Metrics) (policyWatcher, error) {
		got = opts.PodLabels
		return &fakePolicyWatcher{}, nil
	}

	path := filepath.Join(t.TempDir(), "labels")
	if err := os.WriteFile(path, []byte("app=\"agent\"\ntier=\"web\"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := productionPolicyStartup(policyCfgLabels(path, 2*time.Second), nil, nil, nil)(context.Background()); err != nil {
		t.Fatalf("productionPolicyStartup() error = %v, want nil", err)
	}
	if got["app"] != "agent" || got["tier"] != "web" || len(got) != 2 {
		t.Fatalf("watcher PodLabels = %v, want map[app:agent tier:web]", got)
	}
}

// #83
func TestProductionPolicyStartup_FakeClient_ReturnsPopulatedStore(t *testing.T) {
	upstreamSeamsOK(t, fakeAkshClient{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store, err := productionPolicyStartup(policyCfg(t, 2*time.Second), nil, nil, nil)(ctx)
	if err != nil {
		t.Fatalf("productionPolicyStartup() error = %v, want nil", err)
	}
	if store == nil {
		t.Fatalf("productionPolicyStartup() store = nil, want populated")
	}
	if _, _, ok := store.Current(); !ok {
		t.Fatalf("store.Current() ok = false, want a served snapshot after first snapshot")
	}
}

// #84
func TestProductionPolicyStartup_HappyPath_DenyAllUntilFirstSnapshotThenServes(t *testing.T) {
	release := make(chan struct{})
	client := fakeAkshClient{listFn: func() (*v1alpha1.AkshPolicyList, error) {
		<-release
		return &v1alpha1.AkshPolicyList{}, nil
	}}
	upstreamSeamsOK(t, client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type result struct {
		store *watch.Store
		err   error
	}
	done := make(chan result, 1)
	cfg := policyCfg(t, 2*time.Second)
	go func() {
		s, e := productionPolicyStartup(cfg, nil, nil, nil)(ctx)
		done <- result{s, e}
	}()

	// Deny-all window: no store is served until the first snapshot arrives.
	select {
	case <-done:
		t.Fatalf("productionPolicyStartup returned before the first snapshot (no deny-all window)")
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("productionPolicyStartup() error = %v, want nil", r.err)
		}
		if _, _, ok := r.store.Current(); !ok {
			t.Fatalf("store serves no snapshot after first snapshot")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("productionPolicyStartup did not return after the first snapshot")
	}
}

// #85
func TestProductionPolicyStartup_InClusterConfigSeamError_ReturnsErrorNilStore(t *testing.T) {
	orig := inClusterConfig
	t.Cleanup(func() { inClusterConfig = orig })
	inClusterConfig = func() (*rest.Config, error) { return nil, errors.New("no in-cluster config") }

	store, err := productionPolicyStartup(policyCfg(t, time.Second), nil, nil, nil)(context.Background())
	assertErrorNilStore(t, store, err)
}

// #86
func TestProductionPolicyStartup_NewDynamicClientSeamError_ReturnsErrorNilStore(t *testing.T) {
	oic, odc := inClusterConfig, newDynamicClient
	t.Cleanup(func() { inClusterConfig, newDynamicClient = oic, odc })
	inClusterConfig = func() (*rest.Config, error) { return &rest.Config{}, nil }
	newDynamicClient = func(*rest.Config) (dynamic.Interface, error) { return nil, errors.New("bad dynamic client") }

	store, err := productionPolicyStartup(policyCfg(t, time.Second), nil, nil, nil)(context.Background())
	assertErrorNilStore(t, store, err)
}

// #87
func TestProductionPolicyStartup_NewAkshPolicyClientSeamError_ReturnsErrorNilStore(t *testing.T) {
	oic, odc, oac := inClusterConfig, newDynamicClient, newAkshPolicyClient
	t.Cleanup(func() { inClusterConfig, newDynamicClient, newAkshPolicyClient = oic, odc, oac })
	inClusterConfig = func() (*rest.Config, error) { return &rest.Config{}, nil }
	newDynamicClient = func(*rest.Config) (dynamic.Interface, error) { return nil, nil }
	newAkshPolicyClient = func(dynamic.Interface, string) (watch.AkshPolicyClient, error) {
		return nil, errors.New("bad policy client")
	}

	store, err := productionPolicyStartup(policyCfg(t, time.Second), nil, nil, nil)(context.Background())
	assertErrorNilStore(t, store, err)
}

// #88
func TestProductionPolicyStartup_NewWatcherSeamError_ReturnsErrorNilStore(t *testing.T) {
	upstreamSeamsOK(t, fakeAkshClient{})
	onw := newWatcher
	t.Cleanup(func() { newWatcher = onw })
	newWatcher = func(watch.Options, watch.AkshPolicyClient, *watch.Store, watch.Metrics) (policyWatcher, error) {
		return nil, errors.New("bad watcher")
	}

	store, err := productionPolicyStartup(policyCfg(t, time.Second), nil, nil, nil)(context.Background())
	assertErrorNilStore(t, store, err)
}

// #89
func TestProductionPolicyStartup_WaitFirstSnapshotTimeout_ReturnsErrorNeverStore(t *testing.T) {
	// A client whose List always errors never yields a first snapshot, so the
	// bounded WaitFirstSnapshot times out.
	client := fakeAkshClient{listFn: func() (*v1alpha1.AkshPolicyList, error) {
		return nil, errors.New("api unavailable")
	}}
	upstreamSeamsOK(t, client)

	store, err := productionPolicyStartup(policyCfg(t, 50*time.Millisecond), nil, nil, nil)(context.Background())
	assertErrorNilStore(t, store, err)
}

// #90
func TestProductionPolicyStartup_WaitFirstSnapshotTimeout_PreservesDenyAll(t *testing.T) {
	client := fakeAkshClient{listFn: func() (*v1alpha1.AkshPolicyList, error) {
		return nil, errors.New("api unavailable")
	}}
	upstreamSeamsOK(t, client)

	store, err := productionPolicyStartup(policyCfg(t, 50*time.Millisecond), nil, nil, nil)(context.Background())
	if err == nil {
		t.Fatalf("productionPolicyStartup() error = nil, want a timeout error")
	}
	if store != nil {
		t.Fatalf("productionPolicyStartup() leaked a store %v on timeout, want nil (deny-all preserved)", store)
	}
}

// #91
func TestProductionPolicyStartup_RunNonContextError_LogsErrorAndInvokesFailClosed(t *testing.T) {
	upstreamSeamsOK(t, fakeAkshClient{})
	onw := newWatcher
	t.Cleanup(func() { newWatcher = onw })
	newWatcher = func(watch.Options, watch.AkshPolicyClient, *watch.Store, watch.Metrics) (policyWatcher, error) {
		return &fakePolicyWatcher{runErr: errors.New("watcher exploded")}, nil
	}

	fired := make(chan error, 1)
	failClosed := func(e error) { fired <- e }

	store, err := productionPolicyStartup(policyCfg(t, 2*time.Second), nil, failClosed, nil)(context.Background())
	if err != nil || store == nil {
		t.Fatalf("productionPolicyStartup() = (%v, %v), want a store and nil error (WaitFirstSnapshot succeeded)", store, err)
	}
	select {
	case <-fired:
	case <-time.After(2 * time.Second):
		t.Fatalf("failClosed was not invoked for a non-context Run error")
	}
}

// #92
func TestProductionPolicyStartup_RunContextCanceledOnDrain_NoFailClosed(t *testing.T) {
	upstreamSeamsOK(t, fakeAkshClient{})
	onw := newWatcher
	t.Cleanup(func() { newWatcher = onw })
	newWatcher = func(watch.Options, watch.AkshPolicyClient, *watch.Store, watch.Metrics) (policyWatcher, error) {
		return &fakePolicyWatcher{runErr: context.Canceled}, nil
	}

	fired := make(chan error, 1)
	failClosed := func(e error) { fired <- e }

	if _, err := productionPolicyStartup(policyCfg(t, 2*time.Second), nil, failClosed, nil)(context.Background()); err != nil {
		t.Fatalf("productionPolicyStartup() error = %v, want nil", err)
	}
	select {
	case <-fired:
		t.Fatalf("failClosed invoked for a benign context.Canceled Run drain")
	case <-time.After(200 * time.Millisecond):
	}
}

// #93
func TestProductionPolicyStartup_FailClosedCallback_InvokedExactlyOnceOnRunError(t *testing.T) {
	upstreamSeamsOK(t, fakeAkshClient{})
	onw := newWatcher
	t.Cleanup(func() { newWatcher = onw })
	newWatcher = func(watch.Options, watch.AkshPolicyClient, *watch.Store, watch.Metrics) (policyWatcher, error) {
		return &fakePolicyWatcher{runErr: errors.New("fatal")}, nil
	}

	var mu sync.Mutex
	count := 0
	failClosed := func(error) { mu.Lock(); count++; mu.Unlock() }

	if _, err := productionPolicyStartup(policyCfg(t, 2*time.Second), nil, failClosed, nil)(context.Background()); err != nil {
		t.Fatalf("productionPolicyStartup() error = %v, want nil", err)
	}
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	got := count
	mu.Unlock()
	if got != 1 {
		t.Fatalf("failClosed invoked %d times, want exactly 1", got)
	}
}

// #94
func TestProductionPolicyStartup_CurriedReturn_AssignableToOrchestratorPolicyStartupSeam(t *testing.T) {
	var seam func(context.Context) (*watch.Store, error) = productionPolicyStartup(config.Config{}, nil, nil, nil)
	if seam == nil {
		t.Fatalf("curried return is nil")
	}
	// Compile-time proof of assignment to the orchestrator seam field.
	_ = runtime.Options{PolicyStartup: seam}
}

func assertErrorNilStore(t *testing.T, store *watch.Store, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("productionPolicyStartup() error = nil, want a fail-closed error")
	}
	if store != nil {
		t.Fatalf("productionPolicyStartup() store = %v, want nil on fail-closed", store)
	}
}
