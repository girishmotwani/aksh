package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/girishmotwani/aksh/internal/config"
	"github.com/girishmotwani/aksh/internal/dataplane/capture"
)

// fakeCgroupResolver is a podCgroupResolver double for the startup wiring tests.
// It records the candidate it received and returns a scripted result.
type fakeCgroupResolver struct {
	resolved       string
	err            error
	gotPath        string
	discovered     string
	discoverErr    error
	discoverCalled bool
}

func (f *fakeCgroupResolver) ResolvePodCgroup(podPath string) (string, error) {
	f.gotPath = podPath
	return f.resolved, f.err
}

func (f *fakeCgroupResolver) DiscoverPodCgroup() (string, error) {
	f.discoverCalled = true
	return f.discovered, f.discoverErr
}

// 140
func TestRun_CgroupCandidateDerivationFails_ReturnsNonZeroBeforeValidateLoadOrBind(t *testing.T) {
	fl := &fakeListener{}
	loadCalled := false
	code := run(context.Background(), deps{
		loadConfig: func() (config.Config, error) { return validConfig(), nil },
		factory:    fakeFactory(fl),
		deriveCgroupCandidate: func(string, string) (string, error) {
			return "", errors.New("cannot read proc cgroup")
		},
		loadAndAttach: func(context.Context, *capture.Options) (captureHandle, error) {
			loadCalled = true
			return noopCaptureHandle{}, nil
		},
	})
	if code == 0 {
		t.Fatal("run() = 0, want non-zero on cgroup candidate derivation failure")
	}
	if fl.binds() != 0 {
		t.Fatalf("listener bound %d times, want 0 (aborted before bind)", fl.binds())
	}
	if loadCalled {
		t.Fatal("loadAndAttach was called; derivation failure must abort before Load")
	}
}

// 141
func TestRun_PodCgroupResolverConstructionFails_ReturnsNonZeroBeforeValidateLoadOrBind(t *testing.T) {
	fl := &fakeListener{}
	loadCalled := false
	code := run(context.Background(), deps{
		loadConfig:            func() (config.Config, error) { return validConfig(), nil },
		factory:               fakeFactory(fl),
		deriveCgroupCandidate: func(string, string) (string, error) { return "/host/kubepods/pod", nil },
		newPodCgroupResolver: func(config.Config) (podCgroupResolver, error) {
			return nil, errors.New("resolver construction failed")
		},
		loadAndAttach: func(context.Context, *capture.Options) (captureHandle, error) {
			loadCalled = true
			return noopCaptureHandle{}, nil
		},
	})
	if code == 0 {
		t.Fatal("run() = 0, want non-zero on resolver construction failure")
	}
	if fl.binds() != 0 {
		t.Fatalf("listener bound %d times, want 0 (aborted before bind)", fl.binds())
	}
	if loadCalled {
		t.Fatal("loadAndAttach was called; resolver construction failure must abort before Load")
	}
}

// 142
func TestRun_PodCgroupResolverResolveFails_ReturnsNonZeroBeforeValidateLoadOrBind(t *testing.T) {
	fl := &fakeListener{}
	loadCalled := false
	code := run(context.Background(), deps{
		loadConfig:            func() (config.Config, error) { return validConfig(), nil },
		factory:               fakeFactory(fl),
		deriveCgroupCandidate: func(string, string) (string, error) { return "/host/kubepods/pod", nil },
		newPodCgroupResolver: func(config.Config) (podCgroupResolver, error) {
			return &fakeCgroupResolver{err: errors.New("scope validation failed")}, nil
		},
		loadAndAttach: func(context.Context, *capture.Options) (captureHandle, error) {
			loadCalled = true
			return noopCaptureHandle{}, nil
		},
	})
	if code == 0 {
		t.Fatal("run() = 0, want non-zero on resolver resolve failure")
	}
	if fl.binds() != 0 {
		t.Fatalf("listener bound %d times, want 0 (aborted before bind)", fl.binds())
	}
	if loadCalled {
		t.Fatal("loadAndAttach was called; resolve failure must abort before Load")
	}
}

// 143
func TestRun_PodCgroupResolved_PopulatesCapturePodPathBeforeConfigValidate(t *testing.T) {
	fl := &fakeListener{}
	// The loaded config has an EMPTY PodPath, so Validate can only pass if the
	// resolved path is set into cfg.Capture.PodPath BEFORE Validate runs.
	cfg := validConfig()
	cfg.Capture.PodPath = ""

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, deps{
			loadConfig:            func() (config.Config, error) { return cfg, nil },
			factory:               fakeFactory(fl),
			deriveCgroupCandidate: func(string, string) (string, error) { return "/host/kubepods/pod", nil },
			newPodCgroupResolver: func(config.Config) (podCgroupResolver, error) {
				return &fakeCgroupResolver{resolved: "/proc/1/root/sys/fs/cgroup"}, nil
			},
		})
	}()

	waitFor(t, func() bool { return fl.binds() > 0 }, "listener never bound; PodPath was not populated before Validate")
	cancel()
	if code := waitExit(t, done); code != 0 {
		t.Fatalf("run() = %d, want 0 after clean drain", code)
	}
}

// 144
func TestRun_PodCgroupResolved_LoadAndAttachReceivesResolvedPodPath(t *testing.T) {
	fl := &fakeListener{}
	gotPodPath := ""
	resolver := &fakeCgroupResolver{resolved: "/resolved/pod/path"}
	code := run(context.Background(), deps{
		loadConfig:            func() (config.Config, error) { return validConfig(), nil },
		factory:               fakeFactory(fl),
		deriveCgroupCandidate: func(string, string) (string, error) { return "/host/kubepods/pod", nil },
		newPodCgroupResolver: func(config.Config) (podCgroupResolver, error) {
			return resolver, nil
		},
		loadAndAttach: func(_ context.Context, opts *capture.Options) (captureHandle, error) {
			gotPodPath = opts.PodPath
			return nil, errors.New("stop after capturing opts")
		},
	})
	if code == 0 {
		t.Fatal("run() = 0, want non-zero (loadAndAttach returned an error)")
	}
	// The derived candidate must reach the resolver unchanged: a regression that
	// passed the wrong path into ResolvePodCgroup would otherwise go uncaught.
	if resolver.gotPath != "/host/kubepods/pod" {
		t.Fatalf("resolver received candidate %q, want %q", resolver.gotPath, "/host/kubepods/pod")
	}
	if gotPodPath != "/resolved/pod/path" {
		t.Fatalf("loadAndAttach opts.PodPath = %q, want %q (resolved path must reach capture options)", gotPodPath, "/resolved/pod/path")
	}
}

// 145
func TestMainRun_ProductionWiring_PassesCaptureConfigToPodCgroupResolver(t *testing.T) {
	cfg := validConfig()
	cfg.Capture.HostCgroupMount = "/host/sys/fs/cgroup"
	cfg.Capture.LocalCgroupMount = "/sys/fs/cgroup"
	cfg.Capture.ProcCgroupPath = "/proc/self/cgroup"

	res, err := newProdPodCgroupResolver(cfg)
	if err != nil {
		t.Fatalf("newProdPodCgroupResolver() error = %v, want nil", err)
	}
	if res == nil {
		t.Fatal("newProdPodCgroupResolver() = nil, want a resolver")
	}
	if _, ok := res.(*capture.PodCgroupResolver); !ok {
		t.Fatalf("newProdPodCgroupResolver() = %T, want *capture.PodCgroupResolver", res)
	}

	// Behavioral proof that the config values were threaded into the resolver:
	// ResolvePodCgroup gets PAST the FSMagic-nil guard (so the production
	// FSMagicProber was wired, otherwise it returns ErrMissingConfig) and then
	// fails at os.Stat of the configured HostCgroupMount (so that field was
	// threaded, not dropped). A non-nil, non-FSMagic error referencing the
	// configured mount proves both.
	_, rerr := res.ResolvePodCgroup("/host/sys/fs/cgroup/kubepods/pod/container")
	if rerr == nil {
		t.Fatal("ResolvePodCgroup() = nil error, want failure at the configured host mount")
	}
	if errors.Is(rerr, capture.ErrMissingConfig) {
		t.Fatalf("ResolvePodCgroup() error = %v; the production FSMagic prober was not wired", rerr)
	}
	if !strings.Contains(rerr.Error(), "/host/sys/fs/cgroup") {
		t.Fatalf("ResolvePodCgroup() error = %v, want it to reference the configured HostCgroupMount", rerr)
	}
}

// 146
// On a node with a private cgroup namespace (the kubelet default on cgroup v2,
// e.g. AKS) /proc/self/cgroup reads "0::/", so the Case-A candidate derivation
// fails closed with errV2PathHasNoPodParent. run() must then fall back to the
// resolver's Case-B inode discovery (DiscoverPodCgroup) rather than aborting,
// so the proxy can capture on cgroup-namespaced nodes.
func TestRun_NamespacedCgroupDeriveFails_FallsBackToDiscoverPodCgroup(t *testing.T) {
	fl := &fakeListener{}
	gotPodPath := ""
	resolver := &fakeCgroupResolver{discovered: "/host/sys/fs/cgroup/kubepods.slice/pod.slice"}
	code := run(context.Background(), deps{
		loadConfig: func() (config.Config, error) { return validConfig(), nil },
		factory:    fakeFactory(fl),
		deriveCgroupCandidate: func(string, string) (string, error) {
			return "", errV2PathHasNoPodParent
		},
		newPodCgroupResolver: func(config.Config) (podCgroupResolver, error) { return resolver, nil },
		loadAndAttach: func(_ context.Context, opts *capture.Options) (captureHandle, error) {
			gotPodPath = opts.PodPath
			return nil, errors.New("stop after capturing opts")
		},
	})
	if code == 0 {
		t.Fatal("run() = 0, want non-zero (loadAndAttach returned an error after a successful discover)")
	}
	if !resolver.discoverCalled {
		t.Fatal("DiscoverPodCgroup was not called; the namespaced-cgroup path must fall back to Case-B discovery")
	}
	if gotPodPath != "/host/sys/fs/cgroup/kubepods.slice/pod.slice" {
		t.Fatalf("loadAndAttach opts.PodPath = %q, want the discovered Case-B path", gotPodPath)
	}
}

// 147
// A Case-B discovery that itself fails (opaque namespace, ambiguous inode, walk
// bound) is still a fail-closed condition: run() must abort before Load or bind.
func TestRun_NamespacedCgroupDiscoverFails_ReturnsNonZeroBeforeLoadOrBind(t *testing.T) {
	fl := &fakeListener{}
	loadCalled := false
	code := run(context.Background(), deps{
		loadConfig: func() (config.Config, error) { return validConfig(), nil },
		factory:    fakeFactory(fl),
		deriveCgroupCandidate: func(string, string) (string, error) {
			return "", errV2PathHasNoPodParent
		},
		newPodCgroupResolver: func(config.Config) (podCgroupResolver, error) {
			return &fakeCgroupResolver{discoverErr: errors.New("cgroup namespace is opaque")}, nil
		},
		loadAndAttach: func(context.Context, *capture.Options) (captureHandle, error) {
			loadCalled = true
			return noopCaptureHandle{}, nil
		},
	})
	if code == 0 {
		t.Fatal("run() = 0, want non-zero when Case-B discovery fails")
	}
	if fl.binds() != 0 {
		t.Fatalf("listener bound %d times, want 0 (aborted before bind)", fl.binds())
	}
	if loadCalled {
		t.Fatal("loadAndAttach was called; a failed Case-B discovery must abort before Load")
	}
}
