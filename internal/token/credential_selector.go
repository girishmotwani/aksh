package token

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
)

// CredentialSelector is the public, CRD-facing description of which
// credential a policy rule wants. Provider-neutral by construction (S0).
type CredentialSelector struct {
	Provider string
	Resource string
	Scopes   []string
}

// IsEmpty returns true when no credential is requested — the rule
// allows the destination without injecting an Authorization header.
func (cs CredentialSelector) IsEmpty() bool {
	return cs.Provider == "" && cs.Resource == "" && len(cs.Scopes) == 0
}

// Identity returns the canonical key used by S1's upstream pool, S3's
// token cache, and S6's audit record. Returns "none" for an empty
// selector; otherwise a hex SHA-256 over Provider, Resource, and the
// sorted Scopes. Each field is length-prefixed before hashing (rather
// than joined with a delimiter such as "|" or ",") so that no field's
// content — e.g. a scope string containing a comma, or a resource URI
// containing a pipe — can imitate a separator and collide two distinct
// selectors onto the same identity.
func (cs CredentialSelector) Identity() string {
	if cs.IsEmpty() {
		return "none"
	}

	sorted := make([]string, len(cs.Scopes))
	copy(sorted, cs.Scopes)
	sort.Strings(sorted)

	h := sha256.New()
	writeField := func(s string) {
		var lenBuf [8]byte
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(s)))
		h.Write(lenBuf[:])
		h.Write([]byte(s))
	}

	writeField(cs.Provider)
	writeField(cs.Resource)

	var countBuf [8]byte
	binary.BigEndian.PutUint64(countBuf[:], uint64(len(sorted)))
	h.Write(countBuf[:])
	for _, s := range sorted {
		writeField(s)
	}

	return fmt.Sprintf("%x", h.Sum(nil))
}
