package token_test

import (
	"testing"

	"github.com/girishmotwani/aksh/internal/token"
)

func TestResolve_ProviderDefaultsToEntra(t *testing.T) {
	sel := token.CredentialSelector{Resource: "https://graph.microsoft.com", Scopes: []string{".default"}}
	rc, err := token.Resolve(sel)
	if err != nil {
		t.Fatal(err)
	}
	if rc.Provider != "entra" {
		t.Errorf("provider = %q, want entra", rc.Provider)
	}
}

func TestResolve_ProviderLowercased(t *testing.T) {
	sel := token.CredentialSelector{Provider: "ENTRA", Resource: "https://graph.microsoft.com", Scopes: []string{".default"}}
	rc, err := token.Resolve(sel)
	if err != nil {
		t.Fatal(err)
	}
	if rc.Provider != "entra" {
		t.Errorf("provider = %q, want entra", rc.Provider)
	}
}

func TestResolve_ResourceURI_Normalized(t *testing.T) {
	sel := token.CredentialSelector{Provider: "entra", Resource: "HTTPS://Graph.Microsoft.COM/", Scopes: []string{".default"}}
	rc, err := token.Resolve(sel)
	if err != nil {
		t.Fatal(err)
	}
	if rc.Resource != "https://graph.microsoft.com" {
		t.Errorf("resource = %q, want normalized", rc.Resource)
	}
}

func TestResolve_ResourceOpaqueGUID_Lowercased(t *testing.T) {
	sel := token.CredentialSelector{Provider: "entra", Resource: "6DFE22A0-AB34-4F26-B5B3-C3F2A1E5D8B9", Scopes: []string{".default"}}
	rc, err := token.Resolve(sel)
	if err != nil {
		t.Fatal(err)
	}
	if rc.Resource != "6dfe22a0-ab34-4f26-b5b3-c3f2a1e5d8b9" {
		t.Errorf("resource = %q, want lowercased", rc.Resource)
	}
}

func TestResolve_ScopesSortedAndDeduplicated(t *testing.T) {
	sel := token.CredentialSelector{Provider: "entra", Resource: "https://graph.microsoft.com", Scopes: []string{"b", "a", "b"}}
	rc, err := token.Resolve(sel)
	if err != nil {
		t.Fatal(err)
	}
	if len(rc.WireScopes) != 2 {
		t.Fatalf("wire scopes len = %d, want 2", len(rc.WireScopes))
	}
	if rc.WireScopes[0] >= rc.WireScopes[1] {
		t.Errorf("wire scopes not sorted: %v", rc.WireScopes)
	}
}

func TestResolve_WireScopeComposition_Relative(t *testing.T) {
	sel := token.CredentialSelector{Provider: "entra", Resource: "https://graph.microsoft.com", Scopes: []string{".default"}}
	rc, err := token.Resolve(sel)
	if err != nil {
		t.Fatal(err)
	}
	if len(rc.WireScopes) != 1 || rc.WireScopes[0] != "https://graph.microsoft.com/.default" {
		t.Errorf("wire scopes = %v, want [https://graph.microsoft.com/.default]", rc.WireScopes)
	}
}

func TestResolve_WireScopeComposition_Absolute(t *testing.T) {
	sel := token.CredentialSelector{Provider: "entra", Resource: "https://graph.microsoft.com", Scopes: []string{"https://other.com/scope"}}
	rc, err := token.Resolve(sel)
	if err != nil {
		t.Fatal(err)
	}
	if len(rc.WireScopes) != 1 || rc.WireScopes[0] != "https://other.com/scope" {
		t.Errorf("wire scopes = %v, want [https://other.com/scope]", rc.WireScopes)
	}
}

func TestResolve_WireScopeComposition_NoDoubleSlash(t *testing.T) {
	sel := token.CredentialSelector{Provider: "entra", Resource: "https://graph.microsoft.com/", Scopes: []string{"/v1"}}
	rc, err := token.Resolve(sel)
	if err != nil {
		t.Fatal(err)
	}
	if len(rc.WireScopes) != 1 || rc.WireScopes[0] != "https://graph.microsoft.com/v1" {
		t.Errorf("wire scopes = %v, want [https://graph.microsoft.com/v1]", rc.WireScopes)
	}
}

func TestResolve_Identity_GoldenVector(t *testing.T) {
	sel := token.CredentialSelector{Provider: "entra", Resource: "https://graph.microsoft.com", Scopes: []string{".default"}}
	rc, err := token.Resolve(sel)
	if err != nil {
		t.Fatal(err)
	}
	if len(rc.Identity) != 64 {
		t.Errorf("identity length = %d, want 64", len(rc.Identity))
	}
	rc2, _ := token.Resolve(sel)
	if rc.Identity != rc2.Identity {
		t.Error("identity not deterministic")
	}
}

func TestResolve_Identity_None_ForEmptySelector(t *testing.T) {
	sel := token.CredentialSelector{}
	rc, err := token.Resolve(sel)
	if err != nil {
		t.Fatal(err)
	}
	if rc.Identity != "none" {
		t.Errorf("identity = %q, want none", rc.Identity)
	}
}

func TestResolve_Identity_SameScopeDifferentOrder(t *testing.T) {
	sel1 := token.CredentialSelector{Provider: "entra", Resource: "https://r.com", Scopes: []string{"a", "b"}}
	sel2 := token.CredentialSelector{Provider: "entra", Resource: "https://r.com", Scopes: []string{"b", "a"}}
	rc1, _ := token.Resolve(sel1)
	rc2, _ := token.Resolve(sel2)
	if rc1.Identity != rc2.Identity {
		t.Error("same scopes in different order should produce same identity")
	}
}

func TestResolve_Identity_DifferentResource(t *testing.T) {
	sel1 := token.CredentialSelector{Provider: "entra", Resource: "https://a.com", Scopes: []string{".default"}}
	sel2 := token.CredentialSelector{Provider: "entra", Resource: "https://b.com", Scopes: []string{".default"}}
	rc1, _ := token.Resolve(sel1)
	rc2, _ := token.Resolve(sel2)
	if rc1.Identity == rc2.Identity {
		t.Error("different resources should produce different identity")
	}
}

func TestResolve_Identity_DifferentResource_EmptyScopes(t *testing.T) {
	sel1 := token.CredentialSelector{Provider: "entra", Resource: "https://graph.microsoft.com"}
	sel2 := token.CredentialSelector{Provider: "entra", Resource: "https://management.azure.com"}
	rc1, _ := token.Resolve(sel1)
	rc2, _ := token.Resolve(sel2)
	if rc1.Identity == rc2.Identity {
		t.Error("different resources with empty scopes must produce different identity")
	}
}

func TestResolve_ScopeContainingSpace_Rejected(t *testing.T) {
	sel := token.CredentialSelector{Provider: "entra", Resource: "https://r.com", Scopes: []string{"has space"}}
	_, err := token.Resolve(sel)
	if err == nil {
		t.Error("scope with space should be rejected")
	}
}

func TestResolve_ScopeContainingControlChar_Rejected(t *testing.T) {
	sel := token.CredentialSelector{Provider: "entra", Resource: "https://r.com", Scopes: []string{"bad\x01scope"}}
	_, err := token.Resolve(sel)
	if err == nil {
		t.Error("scope with control character should be rejected")
	}
}
