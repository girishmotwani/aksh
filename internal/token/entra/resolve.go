package entra

import (
	"fmt"
	"strings"

	v1alpha1 "github.com/girishmotwani/aksh/api/v1alpha1"
	"github.com/girishmotwani/aksh/internal/token"
)

// Resolve is the CRD-facing adapter that converts a v1alpha1.CredentialSelector
// into token.CredentialSelector, applies Entra-specific provider validation, and
// delegates canonicalization to the provider-neutral token.Resolve. It never
// duplicates token.Resolve's normalization.
//
// A nil selector is a validation error (never a panic). The provider must be
// empty (defaulted to entra downstream) or the literal "entra"; any other
// non-empty value is rejected so this Entra adapter cannot silently resolve a
// foreign provider's credential.
func Resolve(sel *v1alpha1.CredentialSelector) (token.ResolvedCredential, error) {
	if sel == nil {
		return token.ResolvedCredential{}, fmt.Errorf("entra: credential selector must not be nil")
	}

	provider := strings.ToLower(strings.TrimSpace(sel.Provider))
	if provider != "" && provider != providerEntra {
		return token.ResolvedCredential{}, fmt.Errorf("entra: unsupported provider %q, only %q or empty is accepted", sel.Provider, providerEntra)
	}

	return token.Resolve(token.CredentialSelector{
		Provider: sel.Provider,
		Resource: sel.Resource,
		Scopes:   sel.Scopes,
	})
}
