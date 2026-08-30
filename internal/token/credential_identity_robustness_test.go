package token_test

import (
	"testing"

	"github.com/girishmotwani/aksh/internal/token"
)

// TestCredentialIdentity_ScopeOrderIndependent proves the "sort order" clause
// of S3 §2.3: OAuth scopes are a set, so the derived identity must not depend
// on the order the scopes are listed in the policy. Two rules that differ only
// in scope ordering must resolve to the same cache/pool/audit identity —
// otherwise the same logical credential would fragment across cache entries.
func TestCredentialIdentity_ScopeOrderIndependent(t *testing.T) {
	base := token.CredentialSelector{
		Provider: "entra",
		Resource: "https://graph.microsoft.com",
		Scopes: []string{
			"https://graph.microsoft.com/.default",
			"https://graph.microsoft.com/User.Read",
			"https://graph.microsoft.com/Mail.Read",
		},
	}
	shuffled := token.CredentialSelector{
		Provider: "entra",
		Resource: "https://graph.microsoft.com",
		Scopes: []string{
			"https://graph.microsoft.com/Mail.Read",
			"https://graph.microsoft.com/.default",
			"https://graph.microsoft.com/User.Read",
		},
	}
	rcBase, err := token.Resolve(base)
	if err != nil {
		t.Fatal(err)
	}
	rcShuffled, err := token.Resolve(shuffled)
	if err != nil {
		t.Fatal(err)
	}
	if rcBase.Identity != rcShuffled.Identity {
		t.Fatalf("scope order changed the identity: %q != %q", rcBase.Identity, rcShuffled.Identity)
	}
}

// TestCredentialIdentity_DuplicateScopesCollapse proves that a repeated scope
// does not change the identity — the set semantics de-duplicate before
// hashing, so a policy that lists the same scope twice cannot fork the cache.
func TestCredentialIdentity_DuplicateScopesCollapse(t *testing.T) {
	single := token.CredentialSelector{
		Provider: "entra",
		Resource: "https://graph.microsoft.com",
		Scopes:   []string{"https://graph.microsoft.com/.default"},
	}
	doubled := token.CredentialSelector{
		Provider: "entra",
		Resource: "https://graph.microsoft.com",
		Scopes: []string{
			"https://graph.microsoft.com/.default",
			"https://graph.microsoft.com/.default",
		},
	}
	rc1, err := token.Resolve(single)
	if err != nil {
		t.Fatal(err)
	}
	rc2, err := token.Resolve(doubled)
	if err != nil {
		t.Fatal(err)
	}
	if rc1.Identity != rc2.Identity {
		t.Fatalf("duplicate scope changed the identity: %q != %q", rc1.Identity, rc2.Identity)
	}
	if rc1.Identity == "none" {
		t.Fatal("selector with a scope resolved to the none sentinel")
	}
}

// TestCredentialIdentity_LengthPrefixingPreventsAmbiguity proves the
// "length prefixing" clause of S3 §2.3: without length-prefixing the tuple
// before hashing, two different credentials whose concatenated fields spell
// the same string would collide. Provider "ab" + resource "c" and provider
// "a" + resource "bc" both concatenate to "abc"; length-prefixing must keep
// their identities distinct. A collision here would let one credential's
// cached token be served for a different credential — a confused-deputy defect.
func TestCredentialIdentity_LengthPrefixingPreventsAmbiguity(t *testing.T) {
	a, err := token.Resolve(token.CredentialSelector{Provider: "ab", Resource: "c"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := token.Resolve(token.CredentialSelector{Provider: "a", Resource: "bc"})
	if err != nil {
		t.Fatal(err)
	}
	if a.Identity == b.Identity {
		t.Fatalf("provider/resource boundary is ambiguous: {ab,c} and {a,bc} share identity %q", a.Identity)
	}
	if a.Identity == "none" || b.Identity == "none" {
		t.Fatalf("non-empty selectors resolved to the none sentinel: a=%q b=%q", a.Identity, b.Identity)
	}

	// Resource↔scope boundary: with the resource fixed, one scope "readwrite"
	// must not collide with two scopes "read"+"write". Length-prefixing the
	// scope COUNT and each scope keeps them distinct even though a naive
	// concatenation would spell the same bytes.
	one, err := token.Resolve(token.CredentialSelector{
		Provider: "entra", Resource: "https://api.example.com",
		Scopes: []string{"https://api.example.com/readwrite"},
	})
	if err != nil {
		t.Fatal(err)
	}
	two, err := token.Resolve(token.CredentialSelector{
		Provider: "entra", Resource: "https://api.example.com",
		Scopes: []string{"https://api.example.com/read", "https://api.example.com/write"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if one.Identity == two.Identity {
		t.Fatalf("resource/scope boundary is ambiguous: [readwrite] and [read,write] share identity %q", one.Identity)
	}
}
