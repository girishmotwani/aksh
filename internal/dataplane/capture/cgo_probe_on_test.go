//go:build linux && cgo

package capture

import "testing"

// TestProductionCgoProbe_CgoEnabled_ReturnsTrue proves the P1 probe reflects the
// actual build: when the binary is linked with cgo it must report true so that
// gate P1 rejects the environment rather than silently passing.
func TestProductionCgoProbe_CgoEnabled_ReturnsTrue(t *testing.T) {
	if !(productionCgoProbe{}).CgoEnabled() {
		t.Fatal("CgoEnabled() = false, want true in a cgo build")
	}
}
