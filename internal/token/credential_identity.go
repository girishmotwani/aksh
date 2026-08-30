package token

import (
	"crypto/sha256"
	"fmt"
)

const credIDVersion = "aksh-credid-v1"

// CredID derives a provider-neutral credential identity used as the token
// pool key and audit correlation id. It hashes the fixed tuple
// identity|provider|resource from a ResolvedCredential.
//
// The field order is fixed as identity|provider|resource and the derivation
// uses length-prefixed writes (matching resolvedIdentity in resolve.go) so
// separator-like bytes in any field cannot make two distinct tuples collide.
// WireScopes deliberately do not participate: Identity already folds in the
// scope set, so CredID stays stable across audit and pool consumers.
func CredID(rc ResolvedCredential) string {
	h := sha256.New()
	writeLP(h, credIDVersion)
	writeLP(h, rc.Identity)
	writeLP(h, rc.Provider)
	writeLP(h, rc.Resource)
	return fmt.Sprintf("%x", h.Sum(nil))
}
