package main

import (
	"context"
	"testing"

	"github.com/girishmotwani/aksh/internal/config"
	"github.com/girishmotwani/aksh/internal/dataplane/capture"
	"github.com/girishmotwani/aksh/internal/runtime"
)

// TestRun_EnvironmentPreflightFailure_AbortsBeforeLoadAndAttach proves the
// P1-P8 environment gates run BEFORE the eager LoadAndAttach and that a failure
// there is fatal and fail-closed: no kernel object is created (loadAndAttach is
// never called) and run() returns a non-zero exit code.
func TestRun_EnvironmentPreflightFailure_AbortsBeforeLoadAndAttach(t *testing.T) {
	rec := &recorder{}
	fl := &fakeListener{}

	code := run(context.Background(), deps{
		loadConfig: func() (config.Config, error) { return runValidConfig(), nil },
		envPreflight: func(context.Context, *capture.Options) error {
			rec.add("env-preflight")
			return &capture.PreflightError{Code: capture.E_CGROUP_SCOPE, Gate: "V2"}
		},
		loadAndAttach: func(context.Context, *capture.Options) (captureHandle, error) {
			rec.add("load")
			return &fakeHandle{attachInfo: healthyAttach()}, nil
		},
		factory: fakeFactory(fl),
	})

	if code == 0 {
		t.Fatalf("run() = 0, want non-zero on environment preflight failure")
	}
	if rec.index("env-preflight") < 0 {
		t.Fatalf("environment preflight never ran: %v", rec.snapshot())
	}
	if rec.index("load") != -1 {
		t.Fatalf("loadAndAttach ran despite environment preflight failure: %v", rec.snapshot())
	}
	if fl.binds() != 0 {
		t.Fatalf("listener bound %d times, want 0 (aborted before any bind)", fl.binds())
	}
}

// TestRun_EnvironmentPreflight_RunsBeforeLoadAndAttach proves the ordering on
// the success path: the environment gates run first, then the eager attach.
func TestRun_EnvironmentPreflight_RunsBeforeLoadAndAttach(t *testing.T) {
	rec := &recorder{}
	fh := &fakeHandle{attachInfo: healthyAttach()}
	fl := &fakeListener{}

	code := run(context.Background(), deps{
		loadConfig: func() (config.Config, error) { return runValidConfig(), nil },
		envPreflight: func(context.Context, *capture.Options) error {
			rec.add("env-preflight")
			return nil
		},
		loadAndAttach: func(context.Context, *capture.Options) (captureHandle, error) {
			rec.add("load")
			return fh, nil
		},
		factory: fakeFactory(fl),
		newOrchestrator: func(runtime.Options) (orchestratorRunner, error) {
			return &fakeRunner{}, nil
		},
	})
	if code != 0 {
		t.Fatalf("run() = %d, want 0", code)
	}
	ei, li := rec.index("env-preflight"), rec.index("load")
	if ei < 0 || li < 0 || ei >= li {
		t.Fatalf("order = %v, want env-preflight before load", rec.snapshot())
	}
}
