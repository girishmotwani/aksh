package bpf

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
)

// bpfPackagePath resolves a path relative to internal/dataplane/bpf,
// working whether `go test` is invoked with this directory as the working
// directory (the common case) or from the repo root. os.IsNotExist is used
// (rather than treating any Stat error as "not found") so permission or
// other transient errors surface distinctly instead of being silently
// swallowed into the fallback branch.
func bpfPackagePath(parts ...string) string {
	base := filepath.Join("internal", "dataplane", "bpf")
	if _, err := os.Stat(base); err == nil || !os.IsNotExist(err) {
		if len(parts) == 0 {
			return base
		}
		return filepath.Join(append([]string{base}, parts...)...)
	}

	if len(parts) == 0 {
		return "."
	}
	return filepath.Join(parts...)
}

func loadEmbeddedCollectionSpecPortable() (*ebpf.CollectionSpec, error) {
	objectPath := bpfPackagePath("akshbpf_bpfel.o")
	raw, err := os.ReadFile(objectPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", objectPath, err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("LoadCollectionSpecFromReader(%s): %w", objectPath, err)
	}

	return spec, nil
}
