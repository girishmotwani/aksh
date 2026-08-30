//go:build linux

package capture_test

import (
	"path/filepath"
	"testing"

	"github.com/girishmotwani/aksh/internal/dataplane/capture"
)

// TestNewFSMagicProber_ReadsFilesystemMagic verifies the production prober
// returns a filesystem magic for a real path and an error for a missing one.
func TestNewFSMagicProber_ReadsFilesystemMagic(t *testing.T) {
	p := capture.NewFSMagicProber()

	dir := t.TempDir()
	magic, err := p.FSMagic(dir)
	if err != nil {
		t.Fatalf("FSMagic(%q) error = %v, want nil", dir, err)
	}
	if magic == 0 {
		t.Fatalf("FSMagic(%q) = 0, want a non-zero statfs f_type", dir)
	}

	missing := filepath.Join(dir, "does-not-exist")
	if _, err := p.FSMagic(missing); err == nil {
		t.Fatalf("FSMagic(%q) error = nil, want a statfs error for a missing path", missing)
	}
}
