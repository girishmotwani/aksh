package main

import (
	"context"
	"errors"

	"github.com/girishmotwani/aksh/internal/dataplane/capture"
)

// errPreflight sentinels for the validate-only capture preflight (replaces the
// TD S6-1 placeholder). They are closed errors so callers/tests classify the
// failure without string matching.
var (
	// ErrPreflightNoHandle is returned when the eager LoadAndAttach never
	// produced a Handle (attach never established).
	ErrPreflightNoHandle = errors.New("aksh-proxy: capture preflight: no attach handle")
	// ErrPreflightInvalidAttach is returned when the Handle's AttachInfo is
	// zero/invalid (no attached programs or no cgroup).
	ErrPreflightInvalidAttach = errors.New("aksh-proxy: capture preflight: invalid attach info")
	// ErrPreflightAttachLost is returned when the Handle's attach has already
	// been lost.
	ErrPreflightAttachLost = errors.New("aksh-proxy: capture preflight: attach already lost")
)

// productionPreflight is the VALIDATE-ONLY capture preflight seam (DD-7/F1). It
// is curried over the Handle produced by the eager LoadAndAttach in run(), so
// the orchestrator Preflight gate confirms the already-established attach is
// healthy WITHOUT performing any LoadAndAttach (#101). The returned func returns
// nil for a healthy established attach (#97) and a closed error for a nil Handle
// (#98), invalid AttachInfo (#99), or an already-lost attach (#100).
func productionPreflight(h captureHandle) func(context.Context) error {
	return func(context.Context) error {
		if isNilCaptureHandle(h) {
			return ErrPreflightNoHandle
		}
		if !validAttachInfo(h.AttachInfo()) {
			return ErrPreflightInvalidAttach
		}
		if h.AttachLost() {
			return ErrPreflightAttachLost
		}
		return nil
	}
}

// validAttachInfo reports whether an attach snapshot describes a live attach:
// at least one attached program id and a non-zero cgroup id.
func validAttachInfo(ai capture.AttachInfo) bool {
	return len(ai.ProgIDs) > 0 && ai.CgroupID != 0
}

// isNilCaptureHandle reports whether the seam holds no Handle. It treats both an
// untyped nil interface and a typed nil *capture.Handle as "no handle" so a
// missing attach fails closed rather than panicking on method dispatch.
func isNilCaptureHandle(h captureHandle) bool {
	if h == nil {
		return true
	}
	if hp, ok := h.(*capture.Handle); ok && hp == nil {
		return true
	}
	return false
}
