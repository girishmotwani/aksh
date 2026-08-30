package main

import (
	"context"
	"errors"
	"testing"
)

// #97
func TestProductionPreflight_HealthyEstablishedAttach_ReturnsNil(t *testing.T) {
	h := &fakeHandle{attachInfo: healthyAttach()}
	if err := productionPreflight(h)(context.Background()); err != nil {
		t.Fatalf("productionPreflight() error = %v, want nil for a healthy established attach", err)
	}
}

// #98
func TestProductionPreflight_NilHandle_ReturnsError(t *testing.T) {
	if err := productionPreflight(nil)(context.Background()); !errors.Is(err, ErrPreflightNoHandle) {
		t.Fatalf("productionPreflight(nil) error = %v, want ErrPreflightNoHandle", err)
	}
}

// #99
func TestProductionPreflight_InvalidAttachInfo_ReturnsError(t *testing.T) {
	h := &fakeHandle{} // zero AttachInfo
	if err := productionPreflight(h)(context.Background()); !errors.Is(err, ErrPreflightInvalidAttach) {
		t.Fatalf("productionPreflight() error = %v, want ErrPreflightInvalidAttach", err)
	}
}

// #100
func TestProductionPreflight_AttachAlreadyLost_ReturnsError(t *testing.T) {
	h := &fakeHandle{attachInfo: healthyAttach(), attachLost: true}
	if err := productionPreflight(h)(context.Background()); !errors.Is(err, ErrPreflightAttachLost) {
		t.Fatalf("productionPreflight() error = %v, want ErrPreflightAttachLost", err)
	}
}

// #101
func TestProductionPreflight_Invoked_DoesNotCallLoadAndAttach(t *testing.T) {
	h := &fakeHandle{attachInfo: healthyAttach()}
	if err := productionPreflight(h)(context.Background()); err != nil {
		t.Fatalf("productionPreflight() error = %v, want nil", err)
	}
	// Validate-only: it reads AttachInfo/AttachLost but never re-attaches — a
	// re-attach would build a resolver from PairMap() and tear the Handle down.
	if got := h.pairMaps(); got != 0 {
		t.Fatalf("productionPreflight consumed PairMap() %d times, want 0 (no re-attach path)", got)
	}
	if got := h.closes(); got != 0 {
		t.Fatalf("productionPreflight closed the Handle %d times, want 0 (validate-only)", got)
	}
}
