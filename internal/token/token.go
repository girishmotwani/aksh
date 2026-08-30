package token

import (
	"fmt"
	"time"
)

// redactedSentinel is returned by every redaction hook below in place
// of the secret value.
const redactedSentinel = "[REDACTED]"

// Token holds a brokered credential and its expiry. The secret value
// is stored in an unexported field and is accessible only through
// the Value() method. Token implements the full redaction method set —
// Format, String, GoString, MarshalText, and MarshalJSON — so the
// secret cannot leak via fmt, encoding/json, or encoding.TextMarshaler
// consumers regardless of field visibility (S3 §6 rule 4). This does
// NOT protect a Token embedded in an unexported field of another type
// that is itself printed via reflection-based tooling (e.g. spew) —
// callers must not hold Token in a struct that isn't similarly redacted.
type Token struct {
	value     string
	expiresAt time.Time
}

// NewToken creates a Token with the given secret value and expiry.
func NewToken(value string, expiresAt time.Time) Token {
	return Token{value: value, expiresAt: expiresAt}
}

// Reveal returns the raw token string. This is the ONLY accessor —
// grep for Reveal( to audit all plaintext access sites.
func (t Token) Reveal() string {
	return t.value
}

// ExpiresAt returns the token's expiry time.
func (t Token) ExpiresAt() time.Time {
	return t.expiresAt
}

// Format implements fmt.Formatter to redact the secret under every verb.
// Without this, %#v would print the raw unexported field value.
func (t Token) Format(f fmt.State, verb rune) {
	fmt.Fprint(f, t.String())
}

// String implements fmt.Stringer, redacting the secret.
func (t Token) String() string {
	return "Token{" + redactedSentinel + ", expires=" + t.expiresAt.Format(time.RFC3339) + "}"
}

// GoString implements fmt.GoStringer so %#v also redacts the secret.
func (t Token) GoString() string {
	return t.String()
}

// MarshalText implements encoding.TextMarshaler, redacting the secret.
// This covers any consumer that serializes Token via TextMarshaler
// (e.g. YAML encoders, some logging libraries) independent of json.Marshal.
func (t Token) MarshalText() ([]byte, error) {
	return []byte(redactedSentinel), nil
}

// MarshalJSON implements json.Marshaler, redacting the secret. Without
// this, a future exported field or json tag on Token would serialize
// the raw value; this makes redaction a property of the type rather
// than an accident of field visibility.
func (t Token) MarshalJSON() ([]byte, error) {
	return []byte(`"` + redactedSentinel + `"`), nil
}
