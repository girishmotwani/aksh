//go:build linux

package capture

import (
	"testing"

	"github.com/girishmotwani/aksh/internal/dataplane"
)

// Compile-time proof that the Linux BPFDestinationResolver satisfies the frozen
// dataplane.DestinationResolver interface (unit test #123). This assertion has
// no kernel dependency, so it lives in a platform-neutral test file (no
// ebpf_integration tag) rather than in resolver_integration_test.go.
var _ dataplane.DestinationResolver = (*BPFDestinationResolver)(nil)

func TestBPFDestinationResolverContract(t *testing.T) {
	t.Run("Resolve_FrozenInterfaceSignature_MatchesDestinationResolver", func(t *testing.T) {
		// The package-level var above is the real compile-time check; naming it
		// here as a subtest keeps the binding test name observable in test output.
		var _ dataplane.DestinationResolver = (*BPFDestinationResolver)(nil)
	})
}
