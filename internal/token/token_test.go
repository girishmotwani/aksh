package token_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/token"
)

// TestToken_RedactsOnFormat verifies that fmt verbs %v, %+v, and %#v
// never leak the secret value. S0/S3 §6: an unexported field reached
// through fmt cannot call String() and prints the raw value.
func TestToken_RedactsOnFormat(t *testing.T) {
	secret := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.secret-payload"
	tok := token.NewToken(secret, time.Now().Add(time.Hour))

	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		out := fmt.Sprintf(verb, tok)
		if strings.Contains(out, secret) {
			t.Errorf("fmt.Sprintf(%q, token) leaked the secret: %s", verb, out)
		}
	}
}

// TestToken_RedactsOnJSONMarshal verifies that json.Marshal never
// leaks the secret, even if Token is later embedded with an exported
// field or json tag — MarshalJSON makes redaction a type property
// rather than an accident of field visibility.
func TestToken_RedactsOnJSONMarshal(t *testing.T) {
	secret := "super-secret-value"
	tok := token.NewToken(secret, time.Now().Add(time.Hour))

	out, err := json.Marshal(tok)
	if err != nil {
		t.Fatalf("json.Marshal(token) error: %v", err)
	}
	if strings.Contains(string(out), secret) {
		t.Errorf("json.Marshal(token) leaked the secret: %s", out)
	}
}

// TestToken_RedactsOnTextMarshal verifies encoding.TextMarshaler
// consumers (e.g. YAML encoders) also see the redacted sentinel.
func TestToken_RedactsOnTextMarshal(t *testing.T) {
	secret := "another-secret-value"
	tok := token.NewToken(secret, time.Now().Add(time.Hour))

	out, err := tok.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText() error: %v", err)
	}
	if strings.Contains(string(out), secret) {
		t.Errorf("MarshalText() leaked the secret: %s", out)
	}
}

// TestToken_ExpiryAccessible verifies that the expiry is readable
// without exposing the secret.
func TestToken_ExpiryAccessible(t *testing.T) {
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	tok := token.NewToken("secret", exp)

	got := tok.ExpiresAt()
	if !got.Equal(exp) {
		t.Fatalf("ExpiresAt() = %v, want %v", got, exp)
	}
}

// TestToken_RevealAccessibleViaMethod verifies that the secret is
// retrievable through a deliberate accessor (needed by the injection stage).
func TestToken_RevealAccessibleViaMethod(t *testing.T) {
	secret := "test-token-value"
	tok := token.NewToken(secret, time.Now().Add(time.Hour))

	if got := tok.Reveal(); got != secret {
		t.Fatalf("Reveal() = %q, want %q", got, secret)
	}
}
