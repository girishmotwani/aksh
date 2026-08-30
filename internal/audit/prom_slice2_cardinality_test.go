package audit_test

import (
	"fmt"
	"testing"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/token"
)

// #72 — the `credential` derived label is the bounded S3 §2.3 hash, capped by
// the 256-entry token cache (S3 §8). This asserts that the number of distinct
// aksh_token_cache_evictions_total series cannot exceed the cache cap even under
// a flood of eviction events: the label's domain is the cache key domain, not
// the (unbounded) count of eviction calls.
func TestTokenCacheEviction_CredentialLabel_BoundedByHashCap(t *testing.T) {
	const cacheCap = 256

	rec, reg := newRecorder(t)

	// The live cache holds at most cacheCap credentials, so the credential
	// label domain is a set of at most cacheCap S3 hashes. Derive that bounded
	// set via the real token.CredID hash used by the cache.
	creds := make([]audit.CredentialID, 0, cacheCap)
	for i := 0; i < cacheCap; i++ {
		rc := token.ResolvedCredential{
			Identity: fmt.Sprintf("identity-%d", i),
			Provider: "entra",
			Resource: "https://graph.microsoft.com",
		}
		creds = append(creds, audit.CredentialID(token.CredID(rc)))
	}

	// Flood far more eviction events than the cap, cycling over the bounded
	// credential set (as a churning cache would).
	for round := 0; round < 8; round++ {
		for _, c := range creds {
			rec.TokenCacheEviction(audit.ProviderEntra, c)
		}
	}

	fam := family(t, reg, "aksh_token_cache_evictions_total")
	if fam == nil {
		t.Fatal("aksh_token_cache_evictions_total not present")
	}
	if n := len(fam.GetMetric()); n > cacheCap {
		t.Fatalf("distinct credential series = %d, exceeds cache cap %d", n, cacheCap)
	}
	if n := len(fam.GetMetric()); n != cacheCap {
		t.Fatalf("distinct credential series = %d, want %d (one per bounded hash)", n, cacheCap)
	}
}
