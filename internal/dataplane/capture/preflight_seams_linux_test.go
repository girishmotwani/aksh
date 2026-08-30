//go:build linux

package capture

import (
	"os"
	"path/filepath"
	"testing"
)

// writeStatus writes a minimal /proc/self/status-shaped file carrying the given
// CapEff hex string, so the capability prober can be tested without depending on
// the real capabilities of the test process.
func writeStatus(t *testing.T, capEffHex string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "status")
	body := "Name:\taksh\nCapInh:\t0000000000000000\nCapPrm:\t" + capEffHex +
		"\nCapEff:\t" + capEffHex + "\nCapBnd:\t" + capEffHex + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write status: %v", err)
	}
	return path
}

func TestProcCapabilityProber_KnownCapabilityPresent_ReturnsTrue(t *testing.T) {
	// CAP_BPF is bit 39; set only that bit.
	capEff := uint64(1) << 39
	p := procCapabilityProber{statusPath: writeStatus(t, hexCaps(capEff))}
	got, err := p.HasCapability("CAP_BPF")
	if err != nil {
		t.Fatalf("HasCapability(CAP_BPF) error = %v, want nil", err)
	}
	if !got {
		t.Fatalf("HasCapability(CAP_BPF) = false, want true when bit 39 is set")
	}
}

func TestProcCapabilityProber_KnownCapabilityAbsent_ReturnsFalse(t *testing.T) {
	p := procCapabilityProber{statusPath: writeStatus(t, hexCaps(0))}
	got, err := p.HasCapability("CAP_NET_ADMIN")
	if err != nil {
		t.Fatalf("HasCapability(CAP_NET_ADMIN) error = %v, want nil", err)
	}
	if got {
		t.Fatalf("HasCapability(CAP_NET_ADMIN) = true, want false when no bits are set")
	}
}

func TestProcCapabilityProber_UnknownCapability_ReturnsError(t *testing.T) {
	p := procCapabilityProber{statusPath: writeStatus(t, hexCaps(^uint64(0)))}
	if _, err := p.HasCapability("CAP_NOT_A_REAL_CAP"); err == nil {
		t.Fatalf("HasCapability(unknown) error = nil, want an error rather than a silent false")
	}
}

// hexCaps renders a 64-bit capability mask as the 16-digit lowercase hex string
// the kernel writes in /proc/self/status.
func hexCaps(mask uint64) string {
	const digits = "0123456789abcdef"
	var out [16]byte
	for i := 15; i >= 0; i-- {
		out[i] = digits[mask&0xf]
		mask >>= 4
	}
	return string(out[:])
}

func TestNewProductionPreflightSeams_PopulatesOnlyEnvironmentSeams(t *testing.T) {
	opts := DefaultOptions()
	opts.PodPath = "/host/sys/fs/cgroup/kubepods.slice/pod"
	opts.Metrics = nil // not read by the seam builder

	seams, err := NewProductionPreflightSeams(&opts)
	if err != nil {
		t.Fatalf("NewProductionPreflightSeams() error = %v, want nil", err)
	}
	if seams.Cgo == nil || seams.Uname == nil || seams.FSMagic == nil ||
		seams.BPFFS == nil || seams.Capabilities == nil || seams.Memlock == nil ||
		seams.Cgroup == nil {
		t.Fatalf("environment seams P1-P8 must all be populated: %+v", seams)
	}
	if seams.Loader != nil || seams.Config != nil || seams.Attacher != nil ||
		seams.PinRoot != nil || seams.Redirect != nil || seams.PrivDrop != nil ||
		seams.UIDExclusion != nil {
		t.Fatalf("kernel-object seams P9-P15 must be left nil, LoadAndAttach owns them: %+v", seams)
	}
}
