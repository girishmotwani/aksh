package runtime

import (
	"context"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/config"
	"github.com/girishmotwani/aksh/internal/policy/watch"
)

func podIdentityConfig() config.PodConfig {
	return config.PodConfig{
		Namespace:      "aksh-e2e",
		Name:           "aksh-e2e-abc123",
		UID:            "uid-1",
		ServiceAccount: "aksh-proxy",
	}
}

// TestRun_PipelineReceivesPodAuditIdentity proves assembly.go threads the S5
// Downward API pod attribution and service account from config.Config into the
// pipeline's audit identity (issue #62). Without this the pod block in every
// audit record is empty, defeating replica attribution (ADR-S0-06).
func TestRun_PipelineReceivesPodAuditIdentity(t *testing.T) {
	log := &orderLog{}
	gl := &gateListener{}
	opts := baseOptions(log, gl)
	opts.Config.Pod = podIdentityConfig()
	opts.PolicyStartup = func(context.Context) (*watch.Store, error) { return &watch.Store{}, nil }

	o, _ := New(opts)
	cancel, errc := runInBackground(o)
	defer cancel()
	waitFor(t, func() bool { return log.has("serve") }, 2*time.Second, "serve")
	cancel()
	<-errc

	if o.pipeline == nil {
		t.Fatal("pipeline was not composed/retained")
	}
	got := o.pipeline.AuditIdentity()
	if got.PodNamespace != "aksh-e2e" {
		t.Errorf("PodNamespace = %q, want %q", got.PodNamespace, "aksh-e2e")
	}
	if got.PodName != "aksh-e2e-abc123" {
		t.Errorf("PodName = %q, want %q", got.PodName, "aksh-e2e-abc123")
	}
	if got.PodUID != "uid-1" {
		t.Errorf("PodUID = %q, want %q", got.PodUID, "uid-1")
	}
	if got.ServiceAccount != "aksh-proxy" {
		t.Errorf("ServiceAccount = %q, want %q", got.ServiceAccount, "aksh-proxy")
	}
}
