package token_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/token"
)

const testSecret = "super-secret-token-ABC123-xyz"

func newTestToken() token.Token {
	return token.NewToken(testSecret, time.Now().Add(time.Hour))
}

func TestToken_Redaction_V(t *testing.T) {
	tok := newTestToken()
	out := fmt.Sprintf("%v", tok)
	if strings.Contains(out, testSecret) {
		t.Errorf("%%v leaked secret: %s", out)
	}
}

func TestToken_Redaction_PlusV(t *testing.T) {
	tok := newTestToken()
	out := fmt.Sprintf("%+v", tok)
	if strings.Contains(out, testSecret) {
		t.Errorf("%%+v leaked secret: %s", out)
	}
}

func TestToken_Redaction_HashV(t *testing.T) {
	tok := newTestToken()
	out := fmt.Sprintf("%#v", tok)
	if strings.Contains(out, testSecret) {
		t.Errorf("%%#v leaked secret: %s", out)
	}
}

func TestToken_Redaction_S(t *testing.T) {
	tok := newTestToken()
	out := fmt.Sprintf("%s", tok)
	if strings.Contains(out, testSecret) {
		t.Errorf("%%s leaked secret: %s", out)
	}
}

func TestToken_Redaction_D(t *testing.T) {
	tok := newTestToken()
	out := fmt.Sprintf("%d", tok)
	if strings.Contains(out, testSecret) {
		t.Errorf("%%d leaked secret: %s", out)
	}
}

func TestToken_Redaction_X(t *testing.T) {
	tok := newTestToken()
	out := fmt.Sprintf("%x", tok)
	if strings.Contains(out, testSecret) {
		t.Errorf("%%x leaked secret: %s", out)
	}
}

func TestToken_Redaction_JSON(t *testing.T) {
	tok := newTestToken()
	b, err := json.Marshal(tok)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), testSecret) {
		t.Errorf("json.Marshal leaked secret: %s", string(b))
	}
}

func TestToken_Reveal(t *testing.T) {
	tok := newTestToken()
	if tok.Reveal() != testSecret {
		t.Errorf("Reveal() = %q, want %q", tok.Reveal(), testSecret)
	}
}

func TestSecret_Redaction_V(t *testing.T) {
	s := token.NewSecret(testSecret)
	out := fmt.Sprintf("%v", s)
	if strings.Contains(out, testSecret) {
		t.Errorf("secret %%v leaked: %s", out)
	}
}

func TestSecret_Redaction_JSON(t *testing.T) {
	s := token.NewSecret(testSecret)
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), testSecret) {
		t.Errorf("secret json.Marshal leaked: %s", string(b))
	}
}
