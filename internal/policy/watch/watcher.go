package watch

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	v1alpha1 "github.com/girishmotwani/aksh/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kwatch "k8s.io/apimachinery/pkg/watch"
)

// Validation errors returned by NewWatcher. They are sentinels so callers and
// tests can classify the failure without string matching.
var (
	ErrEmptyNamespace      = errors.New("watch: namespace must not be empty")
	ErrNilClient           = errors.New("watch: AkshPolicyClient must not be nil")
	ErrNilStore            = errors.New("watch: Store must not be nil")
	ErrInvalidMaxStaleness = errors.New("watch: MaxStaleness must be > 0")
)

// Options configures a Watcher.
type Options struct {
	// Namespace is the pod's own namespace. The watcher lists and watches only
	// this namespace; cluster-wide access is never requested.
	Namespace string
	// PodLabels holds this pod's own labels, used to evaluate each policy's
	// spec.selector. It must be sourced from the pod's downward-API labels
	// before the Watcher is constructed. An empty map is a meaningful value --
	// it means the pod carries no labels, so only selector-less policies apply.
	// It does not mean "unknown"; see filterByPodLabels.
	PodLabels map[string]string
	// MaxStaleness is the request-time deny-all threshold (fail-closed at the
	// boundary). Must be > 0.
	MaxStaleness time.Duration
	// ResyncPeriod is the interval between unconditional full relists. It is
	// what keeps a snapshot fresh when no policy edits occur: an unedited CRD
	// produces no watch events, so without a periodic relist the snapshot ages
	// past MaxStaleness and the request path denies all traffic. It must be
	// shorter than MaxStaleness; a value at or beyond it is clamped. Zero (the
	// default) derives the interval from MaxStaleness.
	ResyncPeriod time.Duration
}

// AkshPolicyClient is the narrow, namespaced client surface the watcher needs.
// A real client-go typed/dynamic client or a test fake can satisfy it.
type AkshPolicyClient interface {
	List(ctx context.Context, opts metav1.ListOptions) (*v1alpha1.AkshPolicyList, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (kwatch.Interface, error)
}

// Metrics is the focused metrics seam the watcher needs. audit.MetricsRecorder
// satisfies it structurally, so production injects the real recorder and the
// counters below are live; a test can supply a fake without pulling in the full
// recorder contract.
//
// The method names deliberately match audit.MetricsRecorder. An earlier
// watch-local interface used a different name, which meant the real recorder
// could not satisfy it and the counter was silently a no-op in production.
type Metrics interface {
	// PolicyStaleDeny counts fresh->stale snapshot transitions.
	PolicyStaleDeny()
	// PolicyListForbidden counts policy List calls refused with 403/401.
	PolicyListForbidden()
}

// noopMetrics is used when no recorder is injected.
type noopMetrics struct{}

func (noopMetrics) PolicyStaleDeny()     {}
func (noopMetrics) PolicyListForbidden() {}

// Watcher keeps a Store current from namespaced AkshPolicy CRD changes.
type Watcher struct {
	opts   Options
	client AkshPolicyClient
	store  *Store

	// now is the injectable time source used when publishing snapshots. It lets
	// tests simulate age across reconnect outages without a real clock.
	now func() time.Time
	log *slog.Logger

	metrics Metrics

	// lastListErr retains the most recent List failure so a first-snapshot
	// timeout can report the underlying cause instead of a bare context error.
	lastListErr atomic.Pointer[error]
	// listFailures counts consecutive List failures, driving both the log rate
	// limiter and the "attempts" field operators use to judge persistence.
	listFailures atomic.Uint64

	// reconnectBackoff is the base backoff between failed reconnect attempts.
	reconnectBackoff time.Duration

	// ready is closed once, on the first successful compile+swap.
	ready     chan struct{}
	readyOnce sync.Once

	// mu serializes compile+swap so Swap is never called with a partial set.
	mu        sync.Mutex
	firstDone bool

	// relistMu serializes whole relists (List + compile + swap) so a periodic
	// resync racing an event-driven relist cannot publish an older list after
	// a newer one.
	relistMu sync.Mutex

	// lastStale tracks the observed staleness state so the deny metric fires
	// exactly once per fresh->stale transition.
	lastStale bool

	// fatal marks an unrecoverable watcher state. Liveness is !fatal: watch
	// outages and stale snapshots are request-time decisions, not liveness loss.
	fatal atomic.Bool
}

// NewWatcher validates its inputs and returns a ready-to-Run Watcher with no
// metrics recorder attached. It never mutates store on failure.
func NewWatcher(opts Options, client AkshPolicyClient, store *Store) (*Watcher, error) {
	return NewWatcherWithMetrics(opts, client, store, nil)
}

// NewWatcherWithMetrics is NewWatcher with an explicit metrics recorder, so the
// policy counters are live in production. A nil recorder selects the no-op.
func NewWatcherWithMetrics(opts Options, client AkshPolicyClient, store *Store, metrics Metrics) (*Watcher, error) {
	if opts.Namespace == "" {
		return nil, ErrEmptyNamespace
	}
	if client == nil {
		return nil, ErrNilClient
	}
	if store == nil {
		return nil, ErrNilStore
	}
	if opts.MaxStaleness <= 0 {
		return nil, ErrInvalidMaxStaleness
	}
	if metrics == nil {
		metrics = noopMetrics{}
	}
	return &Watcher{
		opts:             opts,
		client:           client,
		store:            store,
		now:              time.Now,
		log:              slog.Default(),
		metrics:          metrics,
		reconnectBackoff: 50 * time.Millisecond,
		ready:            make(chan struct{}),
	}, nil
}

// Live reports whether the watcher is in a runnable state. A stale snapshot or a
// watch outage does not clear liveness; only a fatal invariant violation does.
func (w *Watcher) Live() bool { return !w.fatal.Load() }

// WaitFirstSnapshot blocks until the first successful compile+swap, returning nil
// once ready. If the context ends first, the returned error wraps the context
// error so errors.Is still classifies it, and names the most recent List failure
// when there is one -- otherwise the caller reports only "context deadline
// exceeded", which points an operator at a timeout when the real cause is
// usually a missing AkshPolicy read permission.
func (w *Watcher) WaitFirstSnapshot(ctx context.Context) error {
	select {
	case <-w.ready:
		return nil
	case <-ctx.Done():
		if last := w.lastListFailure(); last != nil {
			return fmt.Errorf("%w (no policy snapshot; last list error: %v)", ctx.Err(), last)
		}
		return ctx.Err()
	}
}

// Run is implemented in the watch loop (see run.go).
func (w *Watcher) Run(ctx context.Context) error {
	return w.run(ctx)
}
