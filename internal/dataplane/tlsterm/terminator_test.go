package tlsterm_test

import (
	"crypto/tls"
	"errors"
	"reflect"
	"testing"

	"github.com/girishmotwani/aksh/internal/dataplane/tlsterm"
)

func newTestTerminator(t *testing.T, metrics *fakeMetrics) (*tlsterm.Terminator, *fakeCA) {
	t.Helper()
	ca := newFakeCA(t)
	var src *tlsterm.CachedLeafSource
	var err error
	if metrics != nil {
		src, err = tlsterm.NewCachedLeafSourceWithMetrics(ca, validLeafOptions(), metrics)
	} else {
		src, err = tlsterm.NewCachedLeafSource(ca, validLeafOptions())
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var term *tlsterm.Terminator
	if metrics != nil {
		term, err = tlsterm.NewTerminator(src, validLeafOptions(), metrics)
	} else {
		term, err = tlsterm.NewTerminator(src, validLeafOptions(), nil)
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return term, ca
}

func TestTerminatorGetConfigForClient(t *testing.T) {
	t.Run("GetConfigForClient_FrozenBehaviourSignature_MatchesTLSConfigGetConfigForClient", func(t *testing.T) {
		term, _ := newTestTerminator(t, nil)
		var fn func(*tls.ClientHelloInfo) (*tls.Config, error) = term.GetConfigForClient
		_ = fn
	})

	t.Run("GetConfigForClient_NilClientHelloInfo_ReturnsErrMissingClientHello", func(t *testing.T) {
		term, _ := newTestTerminator(t, nil)
		_, err := term.GetConfigForClient(nil)
		if !errors.Is(err, tlsterm.ErrMissingClientHello) {
			t.Fatalf("error = %v, want ErrMissingClientHello", err)
		}
	})

	t.Run("GetConfigForClient_EmptyServerName_ReturnsErrNoSNI", func(t *testing.T) {
		term, _ := newTestTerminator(t, nil)
		_, err := term.GetConfigForClient(&tls.ClientHelloInfo{ServerName: ""})
		if !errors.Is(err, tlsterm.ErrNoSNI) {
			t.Fatalf("error = %v, want ErrNoSNI", err)
		}
	})

	t.Run("GetConfigForClient_ValidSNI_ReturnsConfigWithLeafFromCertificateFor", func(t *testing.T) {
		term, ca := newTestTerminator(t, nil)
		cfg, err := term.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "svc.ns"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg == nil {
			t.Fatal("cfg = nil, want non-nil")
		}
		if len(cfg.Certificates) == 0 && cfg.GetCertificate == nil {
			t.Fatal("cfg has neither Certificates nor GetCertificate populated")
		}
		if got := ca.mintCount.Load(); got != 1 {
			t.Fatalf("mint count = %d, want 1", got)
		}
	})

	t.Run("GetConfigForClient_LeafSourceReturnsError_ReturnsWrappedErrorNoConfig", func(t *testing.T) {
		term, ca := newTestTerminator(t, nil)
		ca.setMintErr(errors.New("ca unavailable"))
		cfg, err := term.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "svc.ns"})
		if err == nil {
			t.Fatal("error = nil, want non-nil")
		}
		if cfg != nil {
			t.Fatalf("cfg = %v, want nil on leaf-source error", cfg)
		}
	})

	t.Run("GetConfigForClient_MinVersionFloorEnforced_RejectsBelowConfiguredMinVersion", func(t *testing.T) {
		term, _ := newTestTerminator(t, nil)
		cfg, err := term.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "svc.ns"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.MinVersion < tls.VersionTLS12 {
			t.Fatalf("MinVersion = %d, want >= tls.VersionTLS12", cfg.MinVersion)
		}
	})

	t.Run("GetConfigForClient_NextProtosSubsetOfConfigured_ALPNRestrictedToAllowedSet", func(t *testing.T) {
		term, _ := newTestTerminator(t, nil)
		cfg, err := term.GetConfigForClient(&tls.ClientHelloInfo{
			ServerName:      "svc.ns",
			SupportedProtos: []string{"h2", "http/1.1", "spdy/3"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := validLeafOptions().NextProtos
		if !reflect.DeepEqual(cfg.NextProtos, want) {
			t.Fatalf("NextProtos = %v, want exactly %v (in order)", cfg.NextProtos, want)
		}
	})

	t.Run("GetConfigForClient_CAUnavailableDuringMint_ReturnsErrorMappedToHandshakeReject", func(t *testing.T) {
		metrics := &fakeMetrics{}
		term, ca := newTestTerminator(t, metrics)
		ca.setMintErr(errors.New("ca down"))
		_, err := term.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "svc.ns"})
		if err == nil {
			t.Fatal("error = nil, want non-nil")
		}
		metrics.mu.Lock()
		defer metrics.mu.Unlock()
		found := false
		for _, d := range metrics.decision {
			if d == "deny/handshake_failed" {
				found = true
			}
		}
		if !found {
			t.Fatalf("decisions = %v, want to include \"deny/handshake_failed\"", metrics.decision)
		}
	})

	t.Run("GetConfigForClient_ConcurrentClientHellos_EachGetsIndependentConfig", func(t *testing.T) {
		term, _ := newTestTerminator(t, nil)
		const n = 10
		errs := make([]error, n)
		cfgs := make([]*tls.Config, n)
		done := make(chan int, n)
		for i := 0; i < n; i++ {
			go func(idx int) {
				name := "svc.ns"
				if idx%2 == 0 {
					name = "other.ns"
				}
				cfgs[idx], errs[idx] = term.GetConfigForClient(&tls.ClientHelloInfo{ServerName: name})
				done <- idx
			}(i)
		}
		for i := 0; i < n; i++ {
			<-done
		}
		for i, err := range errs {
			if err != nil {
				t.Fatalf("goroutine %d: unexpected error: %v", i, err)
			}
			if cfgs[i] == nil {
				t.Fatalf("goroutine %d: cfg = nil", i)
			}
		}
		// Each call must produce its own *tls.Config instance and its own
		// backing NextProtos slice: a shared pointer or shared slice backing
		// array would let one connection's config mutate/rescope another's.
		for i := 0; i < n; i++ {
			for j := i + 1; j < n; j++ {
				if cfgs[i] == cfgs[j] {
					t.Fatalf("goroutine %d and %d received the identical *tls.Config pointer", i, j)
				}
				if len(cfgs[i].NextProtos) > 0 && len(cfgs[j].NextProtos) > 0 &&
					&cfgs[i].NextProtos[0] == &cfgs[j].NextProtos[0] {
					t.Fatalf("goroutine %d and %d share the same NextProtos backing array", i, j)
				}
			}
		}
	})

	t.Run("GetConfigForClient_BeforeUse_ServerNameCanonicalised", func(t *testing.T) {
		term, ca := newTestTerminator(t, nil)
		if _, err := term.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "SVC.ns"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := term.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "svc.ns"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := ca.mintCount.Load(); got != 1 {
			t.Fatalf("mint count = %d, want 1 (SNI must be canonicalised before cache lookup)", got)
		}
	})

	t.Run("GetConfigForClient_OnRejection_RecordDecisionCalled", func(t *testing.T) {
		metrics := &fakeMetrics{}
		term, _ := newTestTerminator(t, metrics)
		if _, err := term.GetConfigForClient(&tls.ClientHelloInfo{ServerName: ""}); err == nil {
			t.Fatal("expected error for empty ServerName")
		}
		metrics.mu.Lock()
		defer metrics.mu.Unlock()
		if len(metrics.decision) != 1 {
			t.Fatalf("decision calls = %d, want exactly 1", len(metrics.decision))
		}
	})

	t.Run("GetConfigForClient_OnConfigBuild_LatencyRecorded", func(t *testing.T) {
		metrics := &fakeMetrics{}
		term, _ := newTestTerminator(t, metrics)
		if _, err := term.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "svc.ns"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		metrics.mu.Lock()
		defer metrics.mu.Unlock()
		found := false
		for _, stage := range metrics.latency {
			if stage == "tls_config_build" {
				found = true
			}
		}
		if !found {
			t.Fatalf("latency stages = %v, want to include \"tls_config_build\"", metrics.latency)
		}
	})
}

func TestTerminatorPostHandshakeAssert(t *testing.T) {
	t.Run("PostHandshakeAssert_NegotiatedServerNameMismatchesCandidateSNI_RejectsWithHandshakeAlert", func(t *testing.T) {
		term, _ := newTestTerminator(t, nil)
		state := tls.ConnectionState{ServerName: "attacker.ns"}
		err := term.PostHandshakeAssert(state, "svc.ns")
		if !errors.Is(err, tlsterm.ErrHandshakeAssertFailed) {
			t.Fatalf("error = %v, want ErrHandshakeAssertFailed", err)
		}
	})

	t.Run("PostHandshakeAssert_DidResumeTrueForNewConnection_RejectsAsAnomalous", func(t *testing.T) {
		term, _ := newTestTerminator(t, nil)
		state := tls.ConnectionState{ServerName: "svc.ns", DidResume: true}
		err := term.PostHandshakeAssert(state, "svc.ns")
		if !errors.Is(err, tlsterm.ErrHandshakeAssertFailed) {
			t.Fatalf("error = %v, want ErrHandshakeAssertFailed", err)
		}
	})

	t.Run("PostHandshakeAssert_NormalHandshakeNoResumption_Succeeds", func(t *testing.T) {
		term, _ := newTestTerminator(t, nil)
		state := tls.ConnectionState{ServerName: "svc.ns", DidResume: false}
		if err := term.PostHandshakeAssert(state, "svc.ns"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestTerminatorRecordHandshakeFailure(t *testing.T) {
	t.Run("GetConfigForClient_DownstreamHandshakeFailsAfterConfigReturned_RecordsHandshakeRejection", func(t *testing.T) {
		metrics := &fakeMetrics{}
		term, _ := newTestTerminator(t, metrics)
		if _, err := term.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "svc.ns"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Simulate the downstream client aborting after a valid *tls.Config
		// was returned: the caller (listener) observes a handshake failure
		// and reports it via RecordHandshakeFailure, which must record
		// RejectHandshake (T4) rather than silently dropping it.
		term.RecordHandshakeFailure("svc.ns")
		metrics.mu.Lock()
		defer metrics.mu.Unlock()
		found := false
		for _, d := range metrics.decision {
			if d == "deny/handshake_failed" {
				found = true
			}
		}
		if !found {
			t.Fatalf("decisions = %v, want to include \"deny/handshake_failed\" after RecordHandshakeFailure", metrics.decision)
		}
	})
}
