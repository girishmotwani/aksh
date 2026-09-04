package runtime

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/dataplane/listener"
	"github.com/girishmotwani/aksh/internal/dataplane/requestpath"
	"github.com/girishmotwani/aksh/internal/dataplane/tlsterm"
	"github.com/girishmotwani/aksh/internal/dataplane/upstream"
	"github.com/girishmotwani/aksh/internal/pipeline"
	"github.com/girishmotwani/aksh/internal/pki"
	"github.com/girishmotwani/aksh/internal/policy"
	"github.com/girishmotwani/aksh/internal/policy/watch"
	"github.com/girishmotwani/aksh/internal/token"
	"github.com/girishmotwani/aksh/internal/token/entra"
	"github.com/girishmotwani/aksh/internal/token/static"
)

const (
	rejectionAuditConcurrency = 64
	rejectionAuditTimeout     = 250 * time.Millisecond
	breakerThreshold          = 5
	breakerProbeIntervalSec   = 30
	negativeCacheEntries      = 256
	negativeCacheTTL          = 30 * time.Second
	tokenCacheEntries         = 256
)

// assemble composes the data-plane handler chain in the design's fixed order:
// leaf source (only after the CA is ready), TLS terminator, guarded token
// cache, policy pipeline (MatchStage backed by the watch.Store, AcquireStage
// backed by the guarded cache), upstream dialer, the bounded rejection
// recorder, and the request-path handler. It returns the TLS-terminating
// connection handler that fronts the request path.
func (o *Orchestrator) assemble(ca pki.CAProvider, store *watch.Store, sink audit.AuditSink) (listener.ConnHandler, error) {
	leaf, err := tlsterm.NewCachedLeafSource(ca, leafOptions())
	if err != nil {
		return nil, fmt.Errorf("runtime: leaf source: %w", err)
	}
	o.leafSource = leaf
	o.rec("leafsource")

	term, err := tlsterm.NewTerminator(leaf, leafOptions(), o.dataMetrics)
	if err != nil {
		return nil, fmt.Errorf("runtime: terminator: %w", err)
	}

	acquirer, err := entra.NewAcquirer(entra.Options{
		TenantID:    o.cfg.Token.Entra.TenantID,
		ClientID:    o.cfg.Token.Entra.ClientID,
		Authority:   o.cfg.Token.Entra.Authority,
		SATokenPath: o.cfg.Token.SATokenPath,
	})
	if err != nil {
		return nil, fmt.Errorf("runtime: entra acquirer: %w", err)
	}

	// Provider dispatch sits ABOVE per-provider guarded acquirers so each
	// provider owns an isolated breaker and negative cache: an Entra outage
	// tripping its breaker never denies static reads, and a permanent static
	// misconfiguration never poisons Entra's negative cache (and vice versa).
	// The static acquirer is built only when a token path is set, so a policy
	// selecting an unconfigured provider fails closed at the dispatch.
	dispatch := providerDispatchAcquirer{Entra: newGuardedAcquirer(acquirer)}
	if path := o.cfg.Token.Static.Path; path != "" {
		staticAcq, err := static.NewAcquirer(static.Options{TokenPath: path})
		if err != nil {
			return nil, fmt.Errorf("runtime: static acquirer: %w", err)
		}
		dispatch.Static = newGuardedAcquirer(staticAcq)
	}
	o.tokenCache = token.NewTokenCache(dispatch, token.CacheOptions{MaxEntries: tokenCacheEntries})

	// MatchStage reads the watch.Store (Current/Fresh) with the configured
	// staleness bound; AcquireStage pulls from the token cache fronting the
	// provider dispatch, never directly from an acquirer.
	o.matchStage = &pipeline.MatchStage{
		Store:        store,
		Matcher:      policy.NewMatcher(),
		MaxStaleness: o.cfg.Policy.MaxStaleness,
	}
	o.acquireStage = &pipeline.AcquireStage{Cache: o.tokenCache}
	pl := pipeline.NewPipeline([]pipeline.Stage{
		&pipeline.SanitiseStage{},
		&pipeline.IdentityStage{},
		o.matchStage,
		o.acquireStage,
		&pipeline.InjectStage{},
	}, sink, pipeline.WithAuditIdentity(pipeline.AuditIdentity{
		// Resolved once from the S5 Downward API via config; per-process
		// constants, so the pipeline holds them rather than re-reading per
		// request (ADR-S0-06 replica attribution).
		PodNamespace:   o.cfg.Pod.Namespace,
		PodName:        o.cfg.Pod.Name,
		PodUID:         o.cfg.Pod.UID,
		ServiceAccount: o.cfg.Pod.ServiceAccount,
	}))
	o.pipeline = pl

	dialer, err := upstream.NewDirectDialer(upstreamOptions(o.rootCAs), listener.NewSelfDialRegistry(), o.dataMetrics)
	if err != nil {
		return nil, fmt.Errorf("runtime: dialer: %w", err)
	}

	// Bounded, detached rejection recorder (design startup step 8): the sink,
	// typed metrics recorder, bounded concurrency, and bounded timeout are all
	// supplied here so a refusal never blocks the accept loop. The S6 audit
	// path consumes the typed recorder directly (F9 migration).
	o.rejectionRecorder = audit.NewRejectionRecorder(sink, o.dataMetrics, rejectionAuditConcurrency, rejectionAuditTimeout, nil)

	handler, err := requestpath.NewHandler(pl, dialer, sink, o.dataMetrics, requestpath.DefaultOptions())
	if err != nil {
		return nil, fmt.Errorf("runtime: request handler: %w", err)
	}

	// Insert TLS termination in front of the request path. The struct literal
	// is used deliberately (not NewTLSTerminatingConnHandler, which rejects a
	// bare *requestpath.Handler as Next): here the request path is the intended
	// post-termination delegate, exactly as the design reference wiring shows.
	//
	// Log is wired so a refused plaintext connection produces a WARN line
	// naming its destination (issue #83); without it, the most common capture
	// misconfiguration left no trace in the proxy's own signals.
	return tlsTerminatingConnHandler{Terminator: term, Next: handler, Log: o.log}, nil
}

// leafOptions returns the leaf-certificate minting/caching parameters used by
// the CachedLeafSource and Terminator.
//
// NextProtos advertises only http/1.1 because the request path parses the
// downstream stream with http.ReadRequest, which reads HTTP/1.x wire framing.
// Offering h2 would let an agent negotiate a protocol the relay cannot read.
func leafOptions() tlsterm.LeafOptions {
	return tlsterm.LeafOptions{
		CacheEntries: 1024,
		CacheTTL:     5 * time.Minute,
		LeafLifetime: 10 * time.Minute,
		Backdate:     time.Minute,
		MintRate:     50,
		MintBurst:    100,
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}
}

// upstreamOptions returns the direct-dialer parameters, pinned to the reserved
// proxy UID so upstream connections are attributed to the dropped identity.
//
// NextProtos advertises only http/1.1 for the same reason as leafOptions: the
// relay reads upstream responses with http.ReadResponse. Advertising h2 let
// HTTP/2-capable origins negotiate it, after which every response failed to
// parse and was recorded as deny/fault reason=response_failed.
func upstreamOptions(rootCAs *x509.CertPool) upstream.UpstreamOptions {
	return upstream.UpstreamOptions{
		DialTimeout:        15 * time.Second,
		HandshakeTimeout:   15 * time.Second,
		MaxConcurrentDials: 256,
		ProxyUID:           proxyUID,
		NextProtos:         []string{"http/1.1"},
		RootCAs:            rootCAs,
	}
}

// defaultAuditSinkFactory returns a benign discard sink. Production main.go
// injects the real stdout/file sink from config; the default keeps the
// skeleton lifecycle self-contained.
func defaultAuditSinkFactory() (audit.AuditSink, error) {
	return audit.NewStreamSink(io.Discard), nil
}

// nopCAProvider is the benign default CA provider. It satisfies pki.CAProvider
// for construction only; Signer is never called on the skeleton serve path
// (no real TLS handshake occurs). Production main.go injects the real
// pki.PodCAProvider.
type nopCAProvider struct{}

func (nopCAProvider) Signer() (*x509.Certificate, crypto.Signer) { return nil, nil }
func (nopCAProvider) Generation() uint64                         { return 0 }
func (nopCAProvider) PublicPEM() []byte                          { return nil }

// noopStartupMetrics discards startup-gate metrics when none is injected.
type noopStartupMetrics struct{}

func (noopStartupMetrics) RecordStartupFailure(string)                           {}
func (noopStartupMetrics) RecordStartupGateResult(string, string, time.Duration) {}

var _ pki.CAProvider = nopCAProvider{}
