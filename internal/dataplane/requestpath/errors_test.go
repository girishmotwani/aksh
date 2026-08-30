package requestpath_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/girishmotwani/aksh/internal/dataplane/requestpath"
)

func TestSentinelErrors_WrapAndCompareWithErrorsIs(t *testing.T) {
	sentinels := []error{
		requestpath.ErrHeadTooLarge,
		requestpath.ErrPipelined,
		requestpath.ErrUnsupportedProto,
		requestpath.ErrAmbiguousFraming,
		requestpath.ErrBadTarget,
		requestpath.ErrUnhonourableExpect,
		requestpath.ErrDeniedTrailer,
		requestpath.ErrNoHandoverTLS,
	}

	for _, sentinel := range sentinels {
		t.Run(sentinel.Error(), func(t *testing.T) {
			wrapped := fmt.Errorf("wrapped: %w", sentinel)
			if !errors.Is(wrapped, sentinel) {
				t.Fatalf("errors.Is(%v, %v) = false, want true", wrapped, sentinel)
			}
		})
	}
}
