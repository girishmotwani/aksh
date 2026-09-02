package watch

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	v1alpha1 "github.com/girishmotwani/aksh/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kwatch "k8s.io/apimachinery/pkg/watch"
)

// fakeClock is a deterministic, goroutine-safe clock for staleness tests. Both
// the watcher's stamp clock (w.now) and the store's age clock (store.now) can be
// pointed at the same fakeClock so the staleness boundary is crossed by
// advancing the clock rather than sleeping in real time. base carries a
// monotonic reading and every reading is base+offset, so age differences are
// exact regardless of wall-clock behaviour.
type fakeClock struct {
	base time.Time
	off  atomic.Int64 // nanoseconds since base
}

func newFakeClock() *fakeClock { return &fakeClock{base: time.Now()} }

func (c *fakeClock) now() time.Time { return c.base.Add(time.Duration(c.off.Load())) }

func (c *fakeClock) advance(d time.Duration) { c.off.Add(int64(d)) }

// listType aliases the list type for terse fake closure signatures in tests.
type listType = v1alpha1.AkshPolicyList

// fakeClient is a controllable AkshPolicyClient test double. listFn/watchFn are
// invoked with a 1-based call index so tests can vary behaviour per call (e.g.
// return a 410 watch first, then a healthy one). Optional buffered signal
// channels let tests observe when List/Watch happen.
type fakeClient struct {
	namespace string

	mu        sync.Mutex
	listOpts  []metav1.ListOptions
	watchOpts []metav1.ListOptions

	listFn  func(n int) (*v1alpha1.AkshPolicyList, error)
	watchFn func(n int) (kwatch.Interface, error)

	listSig  chan int
	watchSig chan int
}

func newFakeClient(namespace string) *fakeClient {
	return &fakeClient{
		namespace: namespace,
		listSig:   make(chan int, 256),
		watchSig:  make(chan int, 256),
	}
}

func (f *fakeClient) List(ctx context.Context, opts metav1.ListOptions) (*v1alpha1.AkshPolicyList, error) {
	f.mu.Lock()
	f.listOpts = append(f.listOpts, opts)
	n := len(f.listOpts)
	fn := f.listFn
	f.mu.Unlock()
	if f.listSig != nil {
		select {
		case f.listSig <- n:
		default:
		}
	}
	if fn != nil {
		return fn(n)
	}
	return &v1alpha1.AkshPolicyList{}, nil
}

func (f *fakeClient) Watch(ctx context.Context, opts metav1.ListOptions) (kwatch.Interface, error) {
	f.mu.Lock()
	f.watchOpts = append(f.watchOpts, opts)
	n := len(f.watchOpts)
	fn := f.watchFn
	f.mu.Unlock()
	if f.watchSig != nil {
		select {
		case f.watchSig <- n:
		default:
		}
	}
	if fn != nil {
		return fn(n)
	}
	return kwatch.NewFake(), nil
}

func (f *fakeClient) listCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.listOpts)
}

func (f *fakeClient) watchCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.watchOpts)
}

func (f *fakeClient) lastWatchOpts() (metav1.ListOptions, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.watchOpts) == 0 {
		return metav1.ListOptions{}, false
	}
	return f.watchOpts[len(f.watchOpts)-1], true
}

// listOf builds an AkshPolicyList with the given resourceVersion and policies.
func listOf(resourceVersion string, policies ...v1alpha1.AkshPolicy) *v1alpha1.AkshPolicyList {
	l := &v1alpha1.AkshPolicyList{Items: policies}
	l.ResourceVersion = resourceVersion
	return l
}

// denyPolicy builds a policy whose rule has an unsupported effect so that
// policy.Compile fails, exercising the retain-last-good / deny-all paths.
func denyPolicy(name string) v1alpha1.AkshPolicy {
	p := v1alpha1.AkshPolicy{}
	p.Name = name
	p.Namespace = "default"
	p.Spec.Egress.Rules = []v1alpha1.EgressRule{
		{Name: "r-" + name, To: v1alpha1.HostMatch{Host: "blocked.example.com"}, Effect: "Deny"},
	}
	return p
}

// goneStatus is a *metav1.Status representing HTTP 410 Gone for watch errors.
func goneStatus() *metav1.Status {
	return &metav1.Status{
		TypeMeta: metav1.TypeMeta{Kind: "Status"},
		Status:   metav1.StatusFailure,
		Code:     410,
		Reason:   metav1.StatusReasonGone,
		Message:  "too old resource version",
	}
}

// placeholderObject is a runtime.Object used as the payload of non-error watch
// events; the watcher relists to build the complete set and never decodes it.
func placeholderObject() *metav1.Status { return &metav1.Status{} }

// fakeWatch is a controllable kwatch.Interface that records Stop and lets tests
// feed events, including 410 Gone errors.
type fakeWatch struct {
	ch      chan kwatch.Event
	once    sync.Once
	stopped atomicBool
}

func newFakeWatch() *fakeWatch { return &fakeWatch{ch: make(chan kwatch.Event, 32)} }

func (f *fakeWatch) ResultChan() <-chan kwatch.Event { return f.ch }

func (f *fakeWatch) Stop() {
	f.once.Do(func() {
		f.stopped.set(true)
		close(f.ch)
	})
}

func (f *fakeWatch) isStopped() bool { return f.stopped.get() }

func (f *fakeWatch) sendModify() {
	f.ch <- kwatch.Event{Type: kwatch.Modified, Object: placeholderObject()}
}

func (f *fakeWatch) sendGone() { f.ch <- kwatch.Event{Type: kwatch.Error, Object: goneStatus()} }

// atomicBool is a tiny mutex-guarded bool (the race detector is unavailable, so
// tests rely on the mutex for a consistent value across goroutines).
type atomicBool struct {
	mu sync.Mutex
	v  bool
}

func (b *atomicBool) set(v bool) { b.mu.Lock(); b.v = v; b.mu.Unlock() }
func (b *atomicBool) get() bool  { b.mu.Lock(); defer b.mu.Unlock(); return b.v }

// countingMetrics counts the watcher's policy metric calls. Both counters are
// tracked separately so a test can assert that a stale-deny transition does not
// also register as a forbidden list, and vice versa.
type countingMetrics struct {
	mu        sync.Mutex
	n         int
	forbidden int
}

func (c *countingMetrics) PolicyStaleDeny()     { c.mu.Lock(); c.n++; c.mu.Unlock() }
func (c *countingMetrics) PolicyListForbidden() { c.mu.Lock(); c.forbidden++; c.mu.Unlock() }
func (c *countingMetrics) count() int           { c.mu.Lock(); defer c.mu.Unlock(); return c.n }
func (c *countingMetrics) forbiddenCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.forbidden
}

// mustWatcher builds a Watcher and fails the test on validation error.
func mustWatcher(t *testing.T, opts Options, client AkshPolicyClient, store *Store) *Watcher {
	t.Helper()
	w, err := NewWatcher(opts, client, store)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	return w
}

// mustWaitReady blocks until the first snapshot is published or fails the test.
func mustWaitReady(t *testing.T, w *Watcher) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := w.WaitFirstSnapshot(ctx); err != nil {
		t.Fatalf("WaitFirstSnapshot: %v", err)
	}
}
