package main

import (
	"context"

	"github.com/cilium/ebpf"

	"github.com/girishmotwani/aksh/internal/dataplane/capture"
	"github.com/girishmotwani/aksh/internal/runtime"
)

// captureHandle is the injectable eBPF Handle surface run() consumes. The real
// *capture.Handle satisfies it; the lifecycle tests (#102-#109) inject a fake so
// no kernel is required. It mirrors the Handle methods run() actually uses:
// PairMap for the resolver, AttachInfo/AttachLost for the validate-only
// preflight, OnAttachLoss for the fail-closed serve-cancel trigger, and Close
// for reverse-order drain teardown.
type captureHandle interface {
	PairMap() *ebpf.Map
	AttachInfo() capture.AttachInfo
	Close() error
	OnAttachLoss(func(error))
	AttachLoss() <-chan error
	AttachLost() bool
}

// orchestratorRunner is the minimal orchestrator surface run() drives. The real
// *runtime.Orchestrator satisfies it (Run + the ProbeSource Ready/Live it
// exposes to the control plane); tests inject a fake to observe the eager
// LoadAndAttach-before-runtime.New ordering (#102).
type orchestratorRunner interface {
	Run(context.Context) error
	Ready() runtime.ProbeStatus
	Live() runtime.ProbeStatus
}

var _ runtime.ProbeSource = orchestratorRunner(nil)

// podCgroupResolver is the injectable pod-cgroup resolution surface run()
// consumes between config load and Validate (design step: cgroup-in-Go before
// validate). The real *capture.PodCgroupResolver satisfies it via its
// ResolvePodCgroup method; tests inject a fake, and the benign default echoes
// the pod path already present in the config.
type podCgroupResolver interface {
	ResolvePodCgroup(podPath string) (string, error)
	DiscoverPodCgroup() (string, error)
}

var _ podCgroupResolver = (*capture.PodCgroupResolver)(nil)

// passthroughResolver is the benign default resolver: it echoes the pod path it
// was constructed with (cfg.Capture.PodPath) so the skeleton lifecycle tests
// stay hermetic without a live cgroup hierarchy.
type passthroughResolver struct{ path string }

func (p passthroughResolver) ResolvePodCgroup(_ string) (string, error) { return p.path, nil }

func (p passthroughResolver) DiscoverPodCgroup() (string, error) { return p.path, nil }

var _ podCgroupResolver = passthroughResolver{}

// controlPlane is the minimal control-plane surface run() wires into the
// orchestrator start/shutdown seams. The real *runtime.ControlPlaneServer
// satisfies it; the benign default and test fakes bind no socket.
type controlPlane interface {
	Start(context.Context) error
	Shutdown(context.Context) error
}

// Compile-time proof that the production types satisfy the seams.
var (
	_ captureHandle      = (*capture.Handle)(nil)
	_ orchestratorRunner = (*runtime.Orchestrator)(nil)
	_ controlPlane       = (*runtime.ControlPlaneServer)(nil)
)

// noopCaptureHandle is the benign default eager-attach result for tests that do
// not inject a Handle. It owns no kernel object; every method is inert.
type noopCaptureHandle struct{}

func (noopCaptureHandle) PairMap() *ebpf.Map             { return nil }
func (noopCaptureHandle) AttachInfo() capture.AttachInfo { return capture.AttachInfo{} }
func (noopCaptureHandle) Close() error                   { return nil }
func (noopCaptureHandle) OnAttachLoss(func(error))       {}
func (noopCaptureHandle) AttachLoss() <-chan error       { return nil }
func (noopCaptureHandle) AttachLost() bool               { return false }

// noopControlPlane is the benign default control plane for tests: it binds no
// socket and every lifecycle call succeeds.
type noopControlPlane struct{}

func (noopControlPlane) Start(context.Context) error    { return nil }
func (noopControlPlane) Shutdown(context.Context) error { return nil }

var (
	_ captureHandle = noopCaptureHandle{}
	_ controlPlane  = noopControlPlane{}
)
