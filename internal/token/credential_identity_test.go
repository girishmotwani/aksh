package token_test

import (
	"testing"

	"github.com/girishmotwani/aksh/internal/token"
)

// TestCredentialIdentity_DeterministicHash verifies that the same
// CredentialSelector fields produce the same hex SHA-256 identity via Resolve.
func TestCredentialIdentity_DeterministicHash(t *testing.T) {
	sel := token.CredentialSelector{
		Provider: "entra",
		Resource: "https://graph.microsoft.com",
		Scopes:   []string{"https://graph.microsoft.com/.default"},
	}

	rc1, err := token.Resolve(sel)
	if err != nil {
		t.Fatal(err)
	}
	rc2, _ := token.Resolve(sel)
	if rc1.Identity != rc2.Identity {
		t.Fatalf("Resolve().Identity not deterministic: %q != %q", rc1.Identity, rc2.Identity)
	}
	if len(rc1.Identity) != 64 {
		t.Fatalf("Identity length = %d, want 64 (hex SHA-256)", len(rc1.Identity))
	}
}

// TestCredentialIdentity_DifferentScopesProduceDifferentKeys verifies
// that changing scopes changes the derived key.
func TestCredentialIdentity_DifferentScopesProduceDifferentKeys(t *testing.T) {
	sel1 := token.CredentialSelector{
		Provider: "entra",
		Resource: "https://graph.microsoft.com",
		Scopes:   []string{"https://graph.microsoft.com/.default"},
	}
	sel2 := token.CredentialSelector{
		Provider: "entra",
		Resource: "https://graph.microsoft.com",
		Scopes:   []string{"https://graph.microsoft.com/User.Read"},
	}

	rc1, _ := token.Resolve(sel1)
	rc2, _ := token.Resolve(sel2)
	if rc1.Identity == rc2.Identity {
		t.Fatal("different scopes produced the same identity")
	}
}

// TestCredentialIdentity_NoneForEmptySelector verifies that a rule
// with no credential produces the literal "none".
func TestCredentialIdentity_NoneForEmptySelector(t *testing.T) {
	sel := token.CredentialSelector{}
	rc, _ := token.Resolve(sel)
	if rc.Identity != "none" {
		t.Fatalf("empty selector Identity = %q, want %q", rc.Identity, "none")
	}
}

// TestCredentialIdentity_NoDelimiterCollision verifies that selectors
// whose field values contain the "|" or "," characters previously used
// as join delimiters do not collide with a differently-split selector
// that would otherwise concatenate to the same string.
func TestCredentialIdentity_NoDelimiterCollision(t *testing.T) {
	pairs := [][2]token.CredentialSelector{
		{
			{Provider: "a|b", Resource: "c", Scopes: []string{"s"}},
			{Provider: "a", Resource: "b|c", Scopes: []string{"s"}},
		},
		{
			{Provider: "p", Resource: "r", Scopes: []string{"admin", "read,write"}},
			{Provider: "p", Resource: "r", Scopes: []string{"admin,read", "write"}},
		},
		{
			{Provider: "p", Resource: "r", Scopes: []string{"x", "y"}},
			{Provider: "p", Resource: "r", Scopes: []string{"x,y"}},
		},
	}

	for i, pair := range pairs {
		id1 := pair[0].Identity()
		id2 := pair[1].Identity()
		if id1 == id2 {
			t.Errorf("pair %d: distinct selectors collided to the same identity %q", i, id1)
		}
	}
}
