//go:build !linux

package capture_test

import (
	"errors"
	"testing"

	"github.com/girishmotwani/aksh/internal/dataplane/capture"
)

// TestNonLinuxStubs covers unit test spec section 8 (#95-#100).
//
// The spec prescribes no build tag for this file, but the stub symbols it
// exercises only exist behind //go:build !linux. Without the tag `go vet` — which
// test-compiles _test.go files — fails under GOOS=linux. The tag is added here
// and recorded in the Findings document; it can be dropped once the Linux
// implementations of spec sections 9-11 land and both builds export the symbols.
func TestNonLinuxStubs(t *testing.T) {
	t.Run("LoadAndAttach_OnUnsupportedPlatform_ReturnsErrUnsupportedPlatform", func(t *testing.T) {
		opts := capture.DefaultOptions()
		info, err := capture.LoadAndAttach(&opts)
		if !errors.Is(err, capture.ErrUnsupportedPlatform) {
			t.Fatalf("LoadAndAttach() error = %v, want ErrUnsupportedPlatform", err)
		}
		if info != nil {
			t.Fatalf("LoadAndAttach() info = %+v, want nil", info)
		}
	})

	t.Run("NewBPFDestinationResolverStub_OnUnsupportedPlatform_ReturnsErrUnsupportedPlatform", func(t *testing.T) {
		resolver, err := capture.NewBPFDestinationResolver(nil, capture.DefaultOptions())
		if !errors.Is(err, capture.ErrUnsupportedPlatform) {
			t.Fatalf("NewBPFDestinationResolver() error = %v, want ErrUnsupportedPlatform", err)
		}
		if resolver != nil {
			t.Fatalf("NewBPFDestinationResolver() resolver = %+v, want nil", resolver)
		}
	})

	t.Run("DropPrivileges_OnUnsupportedPlatform_ReturnsErrUnsupportedPlatform", func(t *testing.T) {
		err := capture.DropPrivileges(capture.PrivDropConfig{ProxyUID: 1774, ProxyGID: 1774})
		if !errors.Is(err, capture.ErrUnsupportedPlatform) {
			t.Fatalf("DropPrivileges() error = %v, want ErrUnsupportedPlatform", err)
		}
	})

	t.Run("LoadAndAttach_OnUnsupportedPlatform_DoesNotPanic", func(t *testing.T) {
		opts := capture.DefaultOptions()
		for i := 0; i < 3; i++ {
			if _, err := capture.LoadAndAttach(&opts); !errors.Is(err, capture.ErrUnsupportedPlatform) {
				t.Fatalf("call %d: LoadAndAttach() error = %v, want ErrUnsupportedPlatform", i, err)
			}
		}
		if _, err := capture.LoadAndAttach(nil); !errors.Is(err, capture.ErrUnsupportedPlatform) {
			t.Fatalf("LoadAndAttach(nil) error = %v, want ErrUnsupportedPlatform", err)
		}
	})

	t.Run("NewBPFDestinationResolverStub_OnUnsupportedPlatform_DoesNotPanic", func(t *testing.T) {
		// The spec types this argument as *ebpf.Map. It is declared as `any`
		// here so that the platform-neutral slice adds no module dependency;
		// the stub never dereferences it either way.
		for i := 0; i < 3; i++ {
			if _, err := capture.NewBPFDestinationResolver(nil, capture.Options{}); !errors.Is(err, capture.ErrUnsupportedPlatform) {
				t.Fatalf("call %d: NewBPFDestinationResolver() error = %v, want ErrUnsupportedPlatform", i, err)
			}
		}
	})

	t.Run("DropPrivileges_OnUnsupportedPlatform_DoesNotPanic", func(t *testing.T) {
		if err := capture.DropPrivileges(capture.PrivDropConfig{}); !errors.Is(err, capture.ErrUnsupportedPlatform) {
			t.Fatalf("DropPrivileges() error = %v, want ErrUnsupportedPlatform", err)
		}
	})
}
