package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"

	"github.com/girishmotwani/aksh/internal/config"
	"github.com/girishmotwani/aksh/internal/policy/watch"
)

// policyWatcher is the narrow watcher surface productionPolicyStartup drives. The
// real *watch.Watcher satisfies it; the newWatcher seam lets the lifecycle
// error-branch tests (#91-#93) inject a fake whose Run returns an arbitrary
// error the real watcher never would.
type policyWatcher interface {
	Run(context.Context) error
	WaitFirstSnapshot(context.Context) error
}

// Package-level function-variable seams (design Testing Strategy, Plan iter1
// finding #1). Each makes one fail-closed construction branch reachable under
// CGO_ENABLED=0 by overriding the var in a test. Production binds the real
// client-go / watch constructors.
var (
	// inClusterConfig builds the in-cluster REST config (#85/#95).
	inClusterConfig = watch.InClusterRESTConfig
	// newDynamicClient builds the client-go dynamic client (#86).
	newDynamicClient = func(cfg *rest.Config) (dynamic.Interface, error) {
		return dynamic.NewForConfig(cfg)
	}
	// newAkshPolicyClient builds the namespaced AkshPolicy client (#87).
	newAkshPolicyClient = func(dc dynamic.Interface, namespace string) (watch.AkshPolicyClient, error) {
		return watch.NewDynamicAkshPolicyClient(dc, namespace)
	}
	// newWatcher builds the policy Watcher over the store (#88).
	newWatcher = func(opts watch.Options, client watch.AkshPolicyClient, store *watch.Store) (policyWatcher, error) {
		return watch.NewWatcher(opts, client, store)
	}
)

// productionPolicyStartup is the curried policy first-snapshot gate (replaces the
// TD S6-2 placeholder). The returned func drives the real assembly: in-cluster
// REST config -> dynamic client -> namespaced AkshPolicy client -> Watcher ->
// Run(goroutine) -> WaitFirstSnapshot -> populated *watch.Store. The store denies
// all until the first snapshot (deny-all-by-default), and every construction
// failure returns (nil, err) fail-closed so no partial store leaks to the
// orchestrator (#83-#90). A non-context.Canceled error from the Run goroutine is
// logged at ERROR and reported to failClosed exactly once (#91/#93); a
// context.Canceled on drain is benign (#92). The curried return is assignable to
// runtime.Options.PolicyStartup (#94).
func productionPolicyStartup(cfg config.Config, log *slog.Logger, failClosed func(error)) func(context.Context) (*watch.Store, error) {
	if log == nil {
		log = slog.Default()
	}
	return func(ctx context.Context) (*watch.Store, error) {
		restCfg, err := inClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("aksh-proxy: policy startup: in-cluster config: %w", err)
		}
		dc, err := newDynamicClient(restCfg)
		if err != nil {
			return nil, fmt.Errorf("aksh-proxy: policy startup: dynamic client: %w", err)
		}
		client, err := newAkshPolicyClient(dc, cfg.Policy.Namespace)
		if err != nil {
			return nil, fmt.Errorf("aksh-proxy: policy startup: policy client: %w", err)
		}

		store := &watch.Store{}
		// Sourced before the watcher is built: the pod's own labels decide which
		// AkshPolicy selectors match it. A read failure fails closed here rather
		// than proceeding with an unknown label set (#35).
		podLabels, err := watch.LoadPodLabels(cfg.Policy.PodLabelsPath)
		if err != nil {
			return nil, fmt.Errorf("aksh-proxy: policy startup: pod labels: %w", err)
		}
		w, err := newWatcher(watch.Options{
			Namespace:    cfg.Policy.Namespace,
			PodLabels:    podLabels,
			MaxStaleness: cfg.Policy.EffectiveMaxStaleness(),
			ResyncPeriod: cfg.Policy.Resync,
		}, client, store)
		if err != nil {
			return nil, fmt.Errorf("aksh-proxy: policy startup: watcher: %w", err)
		}

		// Run drives the watch for the daemon lifetime. runCtx is cancelled only
		// if the first snapshot never arrives (so the goroutine never leaks); on
		// success the watcher keeps serving updates until the daemon ctx ends.
		runCtx, cancelRun := context.WithCancel(ctx)
		firstSnapshotOK := false
		defer func() {
			if !firstSnapshotOK {
				cancelRun()
			}
		}()
		go func() {
			if runErr := w.Run(runCtx); runErr != nil && !errors.Is(runErr, context.Canceled) {
				// Fatal, non-drain watcher error: log and fail closed exactly
				// once (the watcher never re-reports a single fatal error).
				log.Error("aksh-proxy: policy watcher terminated", "error", runErr)
				if failClosed != nil {
					failClosed(runErr)
				}
			}
		}()

		waitCtx, cancelWait := context.WithTimeout(ctx, cfg.Policy.EffectiveFirstSnapshotTimeout())
		defer cancelWait()
		if err := w.WaitFirstSnapshot(waitCtx); err != nil {
			// Timeout / cancellation before the first snapshot: the deferred
			// cancelRun stops the watcher goroutine and we never return a store
			// (deny-all preserved, #89/#90).
			return nil, fmt.Errorf("aksh-proxy: policy startup: first snapshot: %w", err)
		}
		firstSnapshotOK = true
		return store, nil
	}
}
