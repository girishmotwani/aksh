//go:build !linux

package capture_test

import (
	"errors"
	"testing"

	"github.com/girishmotwani/aksh/internal/dataplane/capture"
)

// #5 — on a non-Linux GOOS the handle_other.go stub keeps LoadAndAttach and the
// Handle type compilable under CGO_ENABLED=0 cross-compilation while refusing at
// runtime with ErrUnsupportedPlatform.
func TestLoadAndAttach_OnUnsupportedPlatform_ReturnsErrUnsupportedPlatform(t *testing.T) {
	opts := capture.DefaultOptions()
	h, err := capture.LoadAndAttach(&opts)
	if !errors.Is(err, capture.ErrUnsupportedPlatform) {
		t.Fatalf("LoadAndAttach() error = %v, want ErrUnsupportedPlatform", err)
	}
	if h != nil {
		t.Fatalf("LoadAndAttach() handle = %v, want nil", h)
	}
}

// AttachLost (S5 predicate) — non-Linux stub always reports false: no attach is
// ever established off-Linux.
func TestAttachLost_OnUnsupportedPlatform_ReturnsFalse(t *testing.T) {
	var h capture.Handle
	if h.AttachLost() {
		t.Fatalf("AttachLost() on non-Linux stub = true, want false")
	}
}
