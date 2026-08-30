package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// writeProcCgroup writes content to a temp proc cgroup file and returns its path.
func writeProcCgroup(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "cgroup")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write proc cgroup file: %v", err)
	}
	return path
}

// 130
func TestDerivePodCgroupCandidate_ValidV2Line_ReturnsCleanHostPodPath(t *testing.T) {
	proc := writeProcCgroup(t, "0::/kubepods/pod123/abc\n")
	got, err := derivePodCgroupCandidate("/host", proc)
	if err != nil {
		t.Fatalf("derivePodCgroupCandidate() error = %v, want nil", err)
	}
	if want := "/host/kubepods/pod123"; got != want {
		t.Fatalf("derivePodCgroupCandidate() = %q, want %q", got, want)
	}
}

// FilesystemRootHostMount is a regression guard for the "/" host mount: an
// earlier cleanHost+separator prefix test produced "//" and would wrongly reject
// every path. Derivation must accept a root host mount and return a clean path.
func TestDerivePodCgroupCandidate_FilesystemRootHostMount_ReturnsCleanPath(t *testing.T) {
	proc := writeProcCgroup(t, "0::/kubepods/pod123/abc\n")
	got, err := derivePodCgroupCandidate("/", proc)
	if err != nil {
		t.Fatalf("derivePodCgroupCandidate() error = %v, want nil for root host mount", err)
	}
	if want := "/kubepods/pod123"; got != want {
		t.Fatalf("derivePodCgroupCandidate() = %q, want %q", got, want)
	}
}

// 131
func TestDerivePodCgroupCandidate_HostMountZeroValue_ReturnsHostMountRequiredError(t *testing.T) {
	proc := writeProcCgroup(t, "0::/kubepods/pod123/abc\n")
	if _, err := derivePodCgroupCandidate("   ", proc); !errors.Is(err, errHostMountRequired) {
		t.Fatalf("derivePodCgroupCandidate() error = %v, want errHostMountRequired", err)
	}
}

// 132
func TestDerivePodCgroupCandidate_ProcCgroupPathZeroValue_ReturnsProcCgroupPathRequiredError(t *testing.T) {
	if _, err := derivePodCgroupCandidate("/host", "  "); !errors.Is(err, errProcCgroupPathRequired) {
		t.Fatalf("derivePodCgroupCandidate() error = %v, want errProcCgroupPathRequired", err)
	}
}

// 133
func TestDerivePodCgroupCandidate_ProcCgroupFileUnreadable_ReturnsError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if _, err := derivePodCgroupCandidate("/host", missing); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("derivePodCgroupCandidate() error = %v, want a read error wrapping fs.ErrNotExist", err)
	}
}

// HostMountNotAbsolute guards the defensive rejection of a relative host cgroup
// mount, which would otherwise yield a relative pod candidate.
func TestDerivePodCgroupCandidate_RelativeHostMount_ReturnsError(t *testing.T) {
	proc := writeProcCgroup(t, "0::/kubepods/pod123/abc\n")
	if _, err := derivePodCgroupCandidate("host/sys/fs/cgroup", proc); !errors.Is(err, errHostMountNotAbsolute) {
		t.Fatalf("derivePodCgroupCandidate() error = %v, want errHostMountNotAbsolute", err)
	}
}

// 134
func TestDerivePodCgroupCandidate_NoV2HierarchyLine_ReturnsError(t *testing.T) {
	proc := writeProcCgroup(t, "1:name=systemd:/kubepods/pod123/abc\n2:cpu:/kubepods\n")
	if _, err := derivePodCgroupCandidate("/host", proc); !errors.Is(err, errNoV2Hierarchy) {
		t.Fatalf("derivePodCgroupCandidate() error = %v, want errNoV2Hierarchy", err)
	}
}

// 135
func TestDerivePodCgroupCandidate_V2RelativePathZeroValue_ReturnsError(t *testing.T) {
	proc := writeProcCgroup(t, "0::\n")
	if _, err := derivePodCgroupCandidate("/host", proc); !errors.Is(err, errV2PathEmpty) {
		t.Fatalf("derivePodCgroupCandidate() error = %v, want errV2PathEmpty", err)
	}
}

// NoPodParent guards the rejection of a v2 path with no pod parent segment: a
// single top-level component would otherwise collapse the candidate onto the
// host cgroup2 root rather than a pod cgroup.
func TestDerivePodCgroupCandidate_V2PathWithNoPodParent_ReturnsError(t *testing.T) {
	proc := writeProcCgroup(t, "0::/kubepods\n")
	if _, err := derivePodCgroupCandidate("/host", proc); !errors.Is(err, errV2PathHasNoPodParent) {
		t.Fatalf("derivePodCgroupCandidate() error = %v, want errV2PathHasNoPodParent", err)
	}
}

// 136
// Test 136 (binding): a relative v2 path is rejected. With the absolute-path
// guard in place, a relative path is caught by errV2PathNotAbsolute. Assert the
// specific guard so the test does not silently pass on an unrelated error, and
// see TestDerivePodCgroupCandidate_AbsolutePathWithDotDot_IsCleanedAndContained
// for the containment behaviour.
func TestDerivePodCgroupCandidate_PathEscapeRelativePath_ReturnsError(t *testing.T) {
	proc := writeProcCgroup(t, "0::../../../../etc/evil/container\n")
	if _, err := derivePodCgroupCandidate("/host", proc); !errors.Is(err, errV2PathNotAbsolute) {
		t.Fatalf("derivePodCgroupCandidate() error = %v, want errV2PathNotAbsolute", err)
	}
}

// AbsolutePathWithDotDot documents that an absolute v2 path cannot escape the
// host mount: path.Dir cleans away any ".." so the joined candidate is always
// contained. The path here resolves to /host/etc/evil (contained), so derivation
// succeeds; the authoritative escape/symlink defense is enforced later by
// capture.PodCgroupResolver.ResolvePodCgroup.
func TestDerivePodCgroupCandidate_AbsolutePathWithDotDot_IsCleanedAndContained(t *testing.T) {
	proc := writeProcCgroup(t, "0::/../../etc/evil/container\n")
	got, err := derivePodCgroupCandidate("/host", proc)
	if err != nil {
		t.Fatalf("derivePodCgroupCandidate() error = %v, want nil (dot-dot cleaned, path contained)", err)
	}
	if want := "/host/etc/evil"; got != want {
		t.Fatalf("derivePodCgroupCandidate() = %q, want %q", got, want)
	}
}

// 137
func TestDerivePodCgroupCandidate_SystemdPodSlicePath_ReturnsPodDirectoryCandidate(t *testing.T) {
	proc := writeProcCgroup(t, "0::/kubepods.slice/kubepods-podXXX.slice/cri-containerd-abc.scope\n")
	got, err := derivePodCgroupCandidate("/host", proc)
	if err != nil {
		t.Fatalf("derivePodCgroupCandidate() error = %v, want nil", err)
	}
	if want := "/host/kubepods.slice/kubepods-podXXX.slice"; got != want {
		t.Fatalf("derivePodCgroupCandidate() = %q, want %q", got, want)
	}
}

// 138
func TestDerivePodCgroupCandidate_MultipleHierarchyLines_UsesHierarchyZeroLine(t *testing.T) {
	proc := writeProcCgroup(t, "1:name=systemd:/other/pod/xyz\n0::/kubepods/pod123/abc\n2:cpu:/still/other\n")
	got, err := derivePodCgroupCandidate("/host", proc)
	if err != nil {
		t.Fatalf("derivePodCgroupCandidate() error = %v, want nil", err)
	}
	if want := "/host/kubepods/pod123"; got != want {
		t.Fatalf("derivePodCgroupCandidate() = %q, want %q", got, want)
	}
}

// 139
func TestDerivePodCgroupCandidate_DuplicateSlashes_ReturnsCleanPath(t *testing.T) {
	proc := writeProcCgroup(t, "0::/kubepods//pod123///abc\n")
	got, err := derivePodCgroupCandidate("/host", proc)
	if err != nil {
		t.Fatalf("derivePodCgroupCandidate() error = %v, want nil", err)
	}
	if want := "/host/kubepods/pod123"; got != want {
		t.Fatalf("derivePodCgroupCandidate() = %q, want %q", got, want)
	}
}
