//go:build linux && !cgo

package capture

import "testing"

// TestProductionCgoProbe_CgoDisabled_ReturnsFalse proves the P1 probe reflects
// the actual build: with CGO_ENABLED=0 it must report false, which is the state
// gate P1 requires (syscall.AllThreadsSyscall needs a pure-Go binary). This is
// the gate that would have caught issue #66.
func TestProductionCgoProbe_CgoDisabled_ReturnsFalse(t *testing.T) {
	if (productionCgoProbe{}).CgoEnabled() {
		t.Fatal("CgoEnabled() = true, want false in a CGO_ENABLED=0 build")
	}
}
