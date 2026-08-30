// Package capture (white-box). This file directly exercises
// canonicalizeHostMount, the unexported helper extracted from
// ResolvePodCgroup in review iteration 2 (dev_review_iter1.md, High,
// cgroup.go:116). The failure branch cannot be reached deterministically
// through the exported ResolvePodCgroup API: os.Stat(hostMount) already
// requires the path to resolve, and on every platform this package targets,
// anything that makes filepath.EvalSymlinks fail on a path also makes
// os.Stat on that same path fail first. The helper is therefore tested at
// its own granularity, following the existing internal-test precedent in
// byteorder_test.go.
package capture

import (
	"path/filepath"
	"testing"
)

// TestCanonicalizeHostMount_EvalSymlinksFails_ReturnsError proves the fix is
// fail-closed: canonicalizeHostMount must surface a filepath.EvalSymlinks
// error rather than silently returning the uncanonicalised path. Before the
// fix, the equivalent inline code (`if real, err := ...; err == nil`)
// swallowed this exact error and let ResolvePodCgroup's V2/V3 containment
// checks run on the raw, uncanonicalised hostMount.
func TestCanonicalizeHostMount_EvalSymlinksFails_ReturnsError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	got, err := canonicalizeHostMount(missing)
	if err == nil {
		t.Fatalf("canonicalizeHostMount(%q) = (%q, nil), want a fail-closed error", missing, got)
	}
	if got != "" {
		t.Fatalf("canonicalizeHostMount(%q) path = %q, want empty on error", missing, got)
	}
}

// TestCanonicalizeHostMount_ValidPath_ResolvesRealPath confirms the fix does
// not regress the success path: a path with no symlinks in it canonicalises
// to the same value filepath.EvalSymlinks would produce directly.
func TestCanonicalizeHostMount_ValidPath_ResolvesRealPath(t *testing.T) {
	dir := t.TempDir()
	got, err := canonicalizeHostMount(dir)
	if err != nil {
		t.Fatalf("canonicalizeHostMount(%q) error = %v, want nil", dir, err)
	}
	want, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("filepath.EvalSymlinks(%q) error = %v", dir, err)
	}
	if got != want {
		t.Fatalf("canonicalizeHostMount(%q) = %q, want %q", dir, got, want)
	}
}
