package watch

import (
	"context"
	"time"

	v1alpha1 "github.com/girishmotwani/aksh/api/v1alpha1"
	"github.com/girishmotwani/aksh/internal/policy"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	kwatch "k8s.io/apimachinery/pkg/watch"
)

// maxReconnectBackoff caps the exponential backoff between failed reconnect
// attempts, bounding the reconnect loop.
const maxReconnectBackoff = 30 * time.Second

// run performs the initial list+compile+swap, starts the staleness monitor and
// the periodic resync, then establishes a namespaced watch and consumes events,
// reconnecting with a full relist on watch breaks/410 until the context is
// canceled.
func (w *Watcher) run(ctx context.Context) error {
	rv, err := w.initialList(ctx)
	if err != nil {
		return err
	}
	go w.staleMonitor(ctx)
	go w.resyncLoop(ctx)
	return w.watchLoop(ctx, rv)
}

// initialList relists until the first List call succeeds (a compile failure is
// not a List failure; it retains last-good and still yields a resourceVersion).
// It returns the resourceVersion to resume the watch from.
func (w *Watcher) initialList(ctx context.Context) (string, error) {
	for {
		rv, err := w.relistAndSwap(ctx)
		if err == nil {
			return rv, nil
		}
		w.noteListFailure(phaseInitial, err)
		if !w.sleep(ctx, w.reconnectBackoff) {
			return "", ctx.Err()
		}
	}
}

// watchLoop establishes a watch from rv and consumes it. On any watch break
// (410 Gone, other error, or a closed channel) it reconnects with a bounded
// backoff and a full relist, then resumes the watch from the relisted rv.
func (w *Watcher) watchLoop(ctx context.Context, rv string) error {
	for {
		if ctx.Err() != nil {
			return nil
		}
		wi, err := w.client.Watch(ctx, metav1.ListOptions{ResourceVersion: rv})
		if err != nil {
			if !w.sleep(ctx, w.reconnectBackoff) {
				return nil
			}
			rv = w.reconnect(ctx)
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		latestRV, reconnect := w.consume(ctx, wi)
		if ctx.Err() != nil {
			return nil
		}
		if latestRV != "" {
			rv = latestRV
		}
		if reconnect {
			rv = w.reconnect(ctx)
			if ctx.Err() != nil {
				return nil
			}
		}
	}
}

// consume reads events until the watch breaks or the context is canceled. A
// non-error event (Add/Modify/Delete/Bookmark) triggers a full relist so the
// complete accumulated set is recompiled and swapped atomically. It returns the
// latest observed resourceVersion and whether the caller must reconnect.
func (w *Watcher) consume(ctx context.Context, wi kwatch.Interface) (string, bool) {
	defer wi.Stop()
	ch := wi.ResultChan()
	rv := ""
	for {
		select {
		case <-ctx.Done():
			return rv, false
		case ev, ok := <-ch:
			if !ok {
				return rv, true // channel closed → reconnect
			}
			if ev.Type == kwatch.Error {
				// 410 Gone or any other watch error → full relist + reconnect.
				return rv, true
			}
			newRV, err := w.relistAndSwap(ctx)
			if err != nil {
				return rv, true // list error → reconnect
			}
			rv = newRV
		}
	}
}

// reconnect performs a bounded-backoff full relist and returns the resulting
// resourceVersion, retaining the last good snapshot across List failures. It
// returns an empty string only if the context is canceled.
func (w *Watcher) reconnect(ctx context.Context) string {
	backoff := w.reconnectBackoff
	for {
		rv, err := w.relistAndSwap(ctx)
		if err == nil {
			return rv
		}
		w.noteListFailure(phaseReconnect, err)
		if !w.sleep(ctx, backoff) {
			return ""
		}
		if backoff < maxReconnectBackoff {
			backoff *= 2
			if backoff > maxReconnectBackoff {
				backoff = maxReconnectBackoff
			}
		}
	}
}

// defaultResyncDivisor derives the resync period from MaxStaleness when no
// explicit ResyncPeriod is configured. Three relists per staleness window mean
// a single failed relist cannot on its own push the snapshot past the
// deny-all boundary.
const defaultResyncDivisor = 3

// resyncInterval returns the effective periodic relist interval. An explicit
// ResyncPeriod is honoured unless it is at or beyond MaxStaleness, which would
// guarantee the snapshot crosses the deny-all boundary between relists; such a
// value is clamped to the derived interval and reported. Zero (the default)
// derives the interval from MaxStaleness.
func (w *Watcher) resyncInterval() time.Duration {
	derived := w.opts.MaxStaleness / defaultResyncDivisor
	if derived <= 0 {
		derived = w.opts.MaxStaleness
	}
	if w.opts.ResyncPeriod <= 0 {
		return derived
	}
	if w.opts.ResyncPeriod >= w.opts.MaxStaleness {
		w.log.Warn("policy resync period is not shorter than max staleness; clamping",
			"namespace", w.opts.Namespace,
			"resync_period", w.opts.ResyncPeriod.String(),
			"max_staleness", w.opts.MaxStaleness.String(),
			"effective_resync_period", derived.String())
		return derived
	}
	return w.opts.ResyncPeriod
}

// resyncLoop performs a full relist on a fixed interval so snapshot freshness
// never depends on policy edits arriving. An unedited AkshPolicy produces no
// watch events, so without this the snapshot ages past MaxStaleness and the
// request path denies every request (fail-closed, but unusable). A relist
// failure is left to the next tick: the last-good snapshot is retained and
// keeps ageing, so the fail-closed boundary is preserved.
func (w *Watcher) resyncLoop(ctx context.Context) {
	t := time.NewTicker(w.resyncInterval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := w.relistAndSwap(ctx); err != nil {
				w.log.Warn("periodic policy resync failed; retaining last good snapshot",
					"namespace", w.opts.Namespace, "error", err.Error())
			}
		}
	}
}

// staleMonitor periodically observes staleness so the deny-boundary metric is
// emitted even when no watch events arrive. It exits when the context ends.
func (w *Watcher) staleMonitor(ctx context.Context) {
	interval := w.opts.MaxStaleness / 4
	if interval > time.Second {
		interval = time.Second
	}
	if interval < 10*time.Millisecond {
		interval = 10 * time.Millisecond
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.observeStaleness()
		}
	}
}

// observeStaleness emits the stale-deny metric exactly once each time the store
// transitions from fresh to stale (age >= MaxStaleness, a negative age from a
// clock anomaly, or no snapshot).
func (w *Watcher) observeStaleness() {
	_, age, ok := w.store.Current()
	stale := !ok || age < 0 || age >= w.opts.MaxStaleness

	w.mu.Lock()
	prev := w.lastStale
	w.lastStale = stale
	w.mu.Unlock()

	if stale && !prev {
		w.metrics.PolicyStaleDeny()
	}
}

// relistAndSwap performs a full List and compiles the complete set. On a List
// (network) error it returns the error for the caller to back off. A compile
// failure retains the last-good snapshot and is not an error here. Whole
// relists are serialized so concurrent callers cannot publish out of order.
func (w *Watcher) relistAndSwap(ctx context.Context) (string, error) {
	w.relistMu.Lock()
	defer w.relistMu.Unlock()

	list, err := w.client.List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", err
	}
	w.noteListSuccess()
	w.compileAndSwap(list.Items)
	return list.ResourceVersion, nil
}

// compileAndSwap filters by pod labels, compiles the complete policy set, and on
// success atomically publishes it. The whole operation is serialized so Swap is
// never called with a partially accumulated set. On compile failure the previous
// snapshot is retained (fail-closed relies on staleness, not clearing).
func (w *Watcher) compileAndSwap(items []v1alpha1.AkshPolicy) {
	filtered := w.filterByPodLabels(items)

	w.mu.Lock()
	defer w.mu.Unlock()

	snap, err := policy.Compile(filtered)
	if err != nil {
		w.log.Warn("policy compile failed; retaining last good snapshot",
			"namespace", w.opts.Namespace, "error", err.Error())
		return
	}
	first := !w.firstDone
	w.store.Swap(snap, w.now())
	if first {
		w.log.Info("policy snapshot published",
			"namespace", w.opts.Namespace,
			"version", snap.Version(),
			"rules", len(snap.Rules()),
			"first", true)
	}
	w.readyOnce.Do(func() {
		w.firstDone = true
		close(w.ready)
	})
}

// filterByPodLabels returns the subset of policies that apply to this pod: those
// with no selector (or an empty selector, which matches everything) plus those
// whose selector matches the pod's own labels (S2/OQ-S2-01: a sidecar only needs
// to know whether a policy selects itself).
//
// There is deliberately no "empty PodLabels means everything applies" shortcut.
// An unlabelled pod must match only the selector-less policies, and the caller
// is required to source the pod's labels before constructing the Watcher --
// productionPolicyStartup fails closed if it cannot. Short-circuiting here would
// silently widen every pod's egress to the union of all policies in the
// namespace on a deny-by-default product (#35).
func (w *Watcher) filterByPodLabels(items []v1alpha1.AkshPolicy) []v1alpha1.AkshPolicy {
	set := labels.Set(w.opts.PodLabels)
	out := make([]v1alpha1.AkshPolicy, 0, len(items))
	for i := range items {
		sel := items[i].Spec.Selector
		if sel == nil {
			out = append(out, items[i])
			continue
		}
		s, err := metav1.LabelSelectorAsSelector(sel)
		if err != nil {
			continue
		}
		if s.Matches(set) {
			out = append(out, items[i])
		}
	}
	return out
}

// sleep blocks for d or until ctx is canceled. It returns true if d elapsed and
// false if the context was canceled. A non-positive d yields without waiting.
func (w *Watcher) sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		select {
		case <-ctx.Done():
			return false
		default:
			return true
		}
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
