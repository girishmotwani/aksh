package runtime

import (
	"context"
	"fmt"
	"strings"

	"github.com/girishmotwani/aksh/internal/token"
)

// providerDispatchAcquirer routes a resolved credential to the acquirer that
// serves its provider. It sits ABOVE the per-provider guarded runtimeTokenAcquirers,
// so each provider owns an isolated breaker and negative cache: the dispatch
// itself adds only provider selection and a fail-closed default, while the
// guard it routes to enforces that provider's breaker/negative-cache/metrics.
// This isolation means an Entra outage or a permanent static misconfiguration
// cannot open or reset the other provider's breaker or poison its cache.
//
// token.Resolve lowercases the provider and maps an empty provider to "entra",
// so by the time a request reaches the dispatch through the cache the provider
// string is already canonical. The empty case is handled defensively for direct
// callers regardless.
type providerDispatchAcquirer struct {
	// Entra serves the "entra" (and legacy empty) provider, normally a guarded
	// acquirer with Entra's own breaker/negative cache. Required.
	Entra token.TokenAcquirer
	// Static serves the "static" provider, normally a guarded acquirer with its
	// own isolated breaker/negative cache. Nil when no static token file is
	// configured; a static-provider request then fails closed as permanent so a
	// policy that selects an unconfigured provider cannot silently forward no
	// credential.
	Static token.TokenAcquirer
}

const (
	providerEntra  = "entra"
	providerStatic = "static"
)

// Acquire dispatches by provider. Unknown providers and an unconfigured static
// provider both fail closed with a permanent classification so the negative
// cache suppresses repeated misrouting rather than retrying it.
func (d providerDispatchAcquirer) Acquire(ctx context.Context, rc token.ResolvedCredential) (token.Token, error) {
	switch strings.ToLower(strings.TrimSpace(rc.Provider)) {
	case "", providerEntra:
		if d.Entra == nil {
			return token.Token{}, &token.AcquireError{
				Class:   token.AcquireErrorPermanent,
				Message: "runtime: entra credential provider is not configured",
			}
		}
		return d.Entra.Acquire(ctx, rc)
	case providerStatic:
		if d.Static == nil {
			return token.Token{}, &token.AcquireError{
				Class:   token.AcquireErrorPermanent,
				Message: "runtime: static credential provider is not configured",
			}
		}
		return d.Static.Acquire(ctx, rc)
	default:
		return token.Token{}, &token.AcquireError{
			Class:   token.AcquireErrorPermanent,
			Message: fmt.Sprintf("runtime: unknown credential provider %q", rc.Provider),
		}
	}
}

// Compile-time assertion that the dispatch satisfies the acquirer seam wrapped
// by the guarded adapter and the token cache.
var _ token.TokenAcquirer = providerDispatchAcquirer{}
