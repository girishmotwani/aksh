package token_test

import (
	"testing"

	"github.com/girishmotwani/aksh/internal/token"
)

// TestCredID_SameResolvedCredential_ReturnsDeterministicHash verifies that
// repeated CredID calls over the same identity, provider, and resource return
// the same string.
func TestCredID_SameResolvedCredential_ReturnsDeterministicHash(t *testing.T) {
	rc := token.ResolvedCredential{
		Identity: "abc123",
		Provider: "entra",
		Resource: "https://graph.microsoft.com",
	}

	id1 := token.CredID(rc)
	id2 := token.CredID(rc)
	if id1 != id2 {
		t.Fatalf("CredID not deterministic: %q != %q", id1, id2)
	}
	if id1 == "" {
		t.Fatal("CredID returned empty string")
	}
}

// TestCredID_IdentityProviderResourceDistinct_ProduceDifferentHashes verifies
// that changing identity, provider, or resource independently produces
// distinct credential IDs.
func TestCredID_IdentityProviderResourceDistinct_ProduceDifferentHashes(t *testing.T) {
	base := token.ResolvedCredential{
		Identity: "id-1",
		Provider: "entra",
		Resource: "https://graph.microsoft.com",
	}

	diffIdentity := base
	diffIdentity.Identity = "id-2"

	diffProvider := base
	diffProvider.Provider = "aws"

	diffResource := base
	diffResource.Resource = "https://vault.example.com"

	baseID := token.CredID(base)
	cases := map[string]token.ResolvedCredential{
		"identity": diffIdentity,
		"provider": diffProvider,
		"resource": diffResource,
	}
	seen := map[string]string{baseID: "base"}
	for name, rc := range cases {
		got := token.CredID(rc)
		if got == baseID {
			t.Fatalf("changing %s did not change CredID: %q", name, got)
		}
		if prev, ok := seen[got]; ok {
			t.Fatalf("CredID collision between %s and %s: %q", name, prev, got)
		}
		seen[got] = name
	}
}

// TestCredID_FieldOrder_IsIdentityProviderResource verifies that the hash input
// order is fixed as identity|provider|resource; a swapped-field fixture does
// not match the golden ID.
func TestCredID_FieldOrder_IsIdentityProviderResource(t *testing.T) {
	canonical := token.ResolvedCredential{
		Identity: "alpha",
		Provider: "beta",
		Resource: "gamma",
	}
	// Swap identity and provider values. With a fixed field order and
	// length-prefixed hashing, this must produce a different ID.
	swapped := token.ResolvedCredential{
		Identity: "beta",
		Provider: "alpha",
		Resource: "gamma",
	}

	golden := token.CredID(canonical)
	if got := token.CredID(swapped); got == golden {
		t.Fatalf("swapped-field fixture matched golden ID %q; field order not enforced", golden)
	}

	// WireScopes must not participate in the identity: CredID is
	// hash(identity|provider|resource) only.
	withScopes := canonical
	withScopes.WireScopes = []string{"https://graph.microsoft.com/.default"}
	if got := token.CredID(withScopes); got != golden {
		t.Fatalf("CredID changed when WireScopes added: %q != %q", got, golden)
	}
}
