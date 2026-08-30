package token

import (
	"encoding/json"
	"fmt"
)

const redacted = "[REDACTED]"

// Secret stores a secret string while redacting common render paths.
type Secret struct {
	v string
}

// NewSecret creates a new secret wrapper.
func NewSecret(v string) Secret {
	return Secret{v: v}
}

// Reveal crosses the redaction boundary and returns the raw secret. Keeping
// plaintext access behind one conspicuous method makes escape sites auditable.
func (s Secret) Reveal() string {
	return s.v
}

// Format redacts the secret under any fmt verb, including verbs that bypass
// String and would otherwise fall back to reflective formatting.
func (s Secret) Format(f fmt.State, verb rune) {
	_, _ = f.Write([]byte(redacted))
}

// String returns a redacted representation.
func (s Secret) String() string {
	return redacted
}

// MarshalJSON redacts the secret when marshaled.
func (s Secret) MarshalJSON() ([]byte, error) {
	return json.Marshal(redacted)
}

// MarshalText redacts the secret when marshaled as text.
func (s Secret) MarshalText() ([]byte, error) {
	return []byte(redacted), nil
}
