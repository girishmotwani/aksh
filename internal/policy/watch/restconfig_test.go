package watch

import (
	"errors"
	"testing"

	"k8s.io/client-go/rest"
)

// #95
func TestInClusterRESTConfig_InClusterFailure_ReturnsBoundedClosedError(t *testing.T) {
	orig := inClusterConfig
	t.Cleanup(func() { inClusterConfig = orig })

	sentinel := errors.New("no service account token")
	inClusterConfig = func() (*rest.Config, error) { return nil, sentinel }

	cfg, err := InClusterRESTConfig()
	if err == nil {
		t.Fatalf("InClusterRESTConfig() error = nil, want a bounded closed error")
	}
	if !errors.Is(err, ErrInClusterConfig) {
		t.Fatalf("InClusterRESTConfig() error = %v, want wrapping ErrInClusterConfig", err)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("InClusterRESTConfig() error = %v, want preserving the underlying cause", err)
	}
	if cfg != nil {
		t.Fatalf("InClusterRESTConfig() config = %v, want nil on failure", cfg)
	}
}

// #96
func TestInClusterRESTConfig_Success_ReturnsNonNilRestConfig(t *testing.T) {
	orig := inClusterConfig
	t.Cleanup(func() { inClusterConfig = orig })

	want := &rest.Config{Host: "https://10.0.0.1:6443"}
	inClusterConfig = func() (*rest.Config, error) { return want, nil }

	cfg, err := InClusterRESTConfig()
	if err != nil {
		t.Fatalf("InClusterRESTConfig() error = %v, want nil", err)
	}
	if cfg == nil {
		t.Fatalf("InClusterRESTConfig() config = nil, want non-nil")
	}
	if cfg.Host != want.Host {
		t.Fatalf("InClusterRESTConfig() host = %q, want %q", cfg.Host, want.Host)
	}
}
