package runtime

import (
	"context"
	"errors"

	"github.com/girishmotwani/aksh/internal/token"
)

// AcquireFailureRecorder records classified token-acquisition failures with
// bounded provider and class labels only. It follows the abstract
// audit.MetricsRecorder pattern: the concrete Prometheus backend arrives in a
// later phase, and no token material ever crosses this seam.
type AcquireFailureRecorder interface {
	// RecordAcquireFailure records one aksh_token_acquire_fail_total event for
	// the given provider and error class.
	RecordAcquireFailure(provider, class string)
}

// runtimeTokenAcquirer gates the base token.TokenAcquirer (the Entra WIF
// acquirer) behind an explicitly composed token.Breaker and token.NegativeCache
// so that a request denies before any exchange when the provider is unhealthy
// or a permanent failure was already observed. It implements token.TokenAcquirer
// and is handed to token.NewTokenCache, which continues to own cache hits,
// refresh-ahead, and single-flight.
type runtimeTokenAcquirer struct {
	Base     token.TokenAcquirer
	Breaker  *token.Breaker
	Negative *token.NegativeCache
	Metrics  AcquireFailureRecorder
}

// newGuardedAcquirer wraps a base acquirer with a fresh, independent breaker and
// negative cache so each credential provider is isolated: one provider's outage
// or permanent misconfiguration cannot open the other's breaker or poison its
// negative cache. Callers build one per provider and route between them with a
// providerDispatchAcquirer.
func newGuardedAcquirer(base token.TokenAcquirer) runtimeTokenAcquirer {
	return runtimeTokenAcquirer{
		Base:     base,
		Breaker:  token.NewBreaker(breakerThreshold, breakerProbeIntervalSec),
		Negative: token.NewNegativeCache(negativeCacheEntries, negativeCacheTTL),
	}
}

// Acquire applies the fail-closed gate sequence: negative-cache lookup, then
// breaker admission, then the base exchange. On a fresh classified failure it
// records the breaker outcome, populates the negative cache for permanent
// errors, and emits the bounded failure metric; on success it records breaker
// success. The gates never call the base acquirer once they deny.
func (a runtimeTokenAcquirer) Acquire(ctx context.Context, rc token.ResolvedCredential) (token.Token, error) {
	if a.Base == nil || a.Breaker == nil || a.Negative == nil {
		return token.Token{}, &token.AcquireError{
			Class:   token.AcquireErrorTransient,
			Message: "runtime: token acquirer missing a required dependency",
		}
	}

	id := token.CredID(rc)

	if cached := a.Negative.Get(id); cached != nil {
		return token.Token{}, cached
	}
	if !a.Breaker.AllowRequest() {
		return token.Token{}, &token.AcquireError{
			Class:   token.AcquireErrorTransient,
			Message: "runtime: token acquisition breaker open",
		}
	}

	tok, err := a.Base.Acquire(ctx, rc)
	if err != nil {
		class := token.AcquireErrorTransient
		var ae *token.AcquireError
		if errors.As(err, &ae) {
			class = ae.Class
		}
		a.Breaker.RecordFailure(class)
		if class == token.AcquireErrorPermanent && ae != nil {
			a.Negative.Put(id, ae)
		}
		if a.Metrics != nil {
			a.Metrics.RecordAcquireFailure(rc.Provider, class.String())
		}
		return token.Token{}, err
	}

	a.Breaker.RecordSuccess()
	return tok, nil
}

// Compile-time assertion that the guarded adapter satisfies the acquirer seam
// consumed by token.NewTokenCache.
var _ token.TokenAcquirer = runtimeTokenAcquirer{}
