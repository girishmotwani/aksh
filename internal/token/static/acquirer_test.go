package static_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/token"
	"github.com/girishmotwani/aksh/internal/token/static"
)

const staticProvider = "static"

func writeTokenFile(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	return path
}

func staticRC(t *testing.T) token.ResolvedCredential {
	t.Helper()
	rc, err := token.Resolve(token.CredentialSelector{Provider: staticProvider, Resource: "openai-api-key"})
	if err != nil {
		t.Fatalf("resolve static selector: %v", err)
	}
	if rc.Provider != staticProvider {
		t.Fatalf("resolved provider = %q, want %q", rc.Provider, staticProvider)
	}
	return rc
}

func TestNewAcquirer_RejectsEmptyPath(t *testing.T) {
	if _, err := static.NewAcquirer(static.Options{}); err == nil {
		t.Fatalf("empty TokenPath must be rejected")
	}
}

func TestNewAcquirer_RejectsTooShortTTL(t *testing.T) {
	if _, err := static.NewAcquirer(static.Options{TokenPath: "/x", TTL: 5 * time.Second}); err == nil {
		t.Fatalf("TTL below the skew margin must be rejected at construction")
	}
}

func TestAcquire_ReadsBearerAndTrimsOneNewline(t *testing.T) {
	const secret = "sk-abc123"
	path := writeTokenFile(t, secret+"\n")
	a, err := static.NewAcquirer(static.Options{TokenPath: path})
	if err != nil {
		t.Fatalf("NewAcquirer: %v", err)
	}

	before := time.Now()
	tok, err := a.Acquire(context.Background(), staticRC(t))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if tok.Reveal() != secret {
		t.Fatalf("token value mismatch after trimming a single newline")
	}
	// The synthetic expiry must be far enough in the future to survive the
	// cache's 60s skew margin.
	if !tok.ExpiresAt().After(before.Add(90 * time.Second)) {
		t.Fatalf("synthetic expiry %v too close to now", tok.ExpiresAt())
	}
}

func TestAcquire_TrimsCRLF(t *testing.T) {
	const secret = "sk-crlf"
	path := writeTokenFile(t, secret+"\r\n")
	a, _ := static.NewAcquirer(static.Options{TokenPath: path})
	tok, err := a.Acquire(context.Background(), staticRC(t))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if tok.Reveal() != secret {
		t.Fatalf("CRLF terminator not trimmed to exactly one line ending")
	}
}

func TestAcquire_RejectsWhitespaceOrControlCharacters(t *testing.T) {
	for _, contents := range []string{"sk-x\n\n", "sk x", "sk-x\tpart", "sk-x\x00part"} {
		path := writeTokenFile(t, contents)
		a, _ := static.NewAcquirer(static.Options{TokenPath: path})
		_, err := a.Acquire(context.Background(), staticRC(t))
		assertClass(t, err, token.AcquireErrorPermanent)
	}
}

func TestAcquire_MissingFileIsLocal(t *testing.T) {
	a, _ := static.NewAcquirer(static.Options{TokenPath: filepath.Join(t.TempDir(), "absent")})
	_, err := a.Acquire(context.Background(), staticRC(t))
	assertClass(t, err, token.AcquireErrorLocal)
}

func TestAcquire_EmptyMaterialIsPermanent(t *testing.T) {
	path := writeTokenFile(t, "\n")
	a, _ := static.NewAcquirer(static.Options{TokenPath: path})
	_, err := a.Acquire(context.Background(), staticRC(t))
	assertClass(t, err, token.AcquireErrorPermanent)
}

func TestAcquire_OversizedMaterialIsPermanent(t *testing.T) {
	path := writeTokenFile(t, strings.Repeat("A", 9*1024))
	a, _ := static.NewAcquirer(static.Options{TokenPath: path})
	_, err := a.Acquire(context.Background(), staticRC(t))
	assertClass(t, err, token.AcquireErrorPermanent)
}

func TestAcquire_WrongProviderIsPermanent(t *testing.T) {
	path := writeTokenFile(t, "sk-abc")
	a, _ := static.NewAcquirer(static.Options{TokenPath: path})
	rc, err := token.Resolve(token.CredentialSelector{Provider: "entra", Resource: "https://vault.example.com"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	_, err = a.Acquire(context.Background(), rc)
	assertClass(t, err, token.AcquireErrorPermanent)
}

func TestAcquire_RereadsFileEachCall(t *testing.T) {
	path := writeTokenFile(t, "sk-first")
	a, _ := static.NewAcquirer(static.Options{TokenPath: path})
	first, err := a.Acquire(context.Background(), staticRC(t))
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	if err := os.WriteFile(path, []byte("sk-second"), 0o600); err != nil {
		t.Fatalf("rotate token: %v", err)
	}
	second, err := a.Acquire(context.Background(), staticRC(t))
	if err != nil {
		t.Fatalf("second Acquire: %v", err)
	}
	if first.Reveal() == second.Reveal() {
		t.Fatalf("Acquire must re-read the file so rotation takes effect")
	}
}

func TestError_NeverLeaksSecret(t *testing.T) {
	// A permanent error message must not contain the secret. Use empty material
	// which is the only permanent path whose input is under our control.
	path := writeTokenFile(t, "")
	a, _ := static.NewAcquirer(static.Options{TokenPath: path})
	_, err := a.Acquire(context.Background(), staticRC(t))
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "\x00") {
		t.Fatalf("unexpected content in error")
	}
}

func TestToken_DoesNotSerializeSecret(t *testing.T) {
	const secret = "sk-serialize"
	path := writeTokenFile(t, secret)
	a, _ := static.NewAcquirer(static.Options{TokenPath: path})
	tok, err := a.Acquire(context.Background(), staticRC(t))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	blob, err := json.Marshal(tok)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(blob), secret) {
		t.Fatalf("secret leaked through JSON serialization")
	}
	if strings.Contains(fmt.Sprintf("%v %+v %#v", tok, tok, tok), secret) {
		t.Fatalf("secret leaked through fmt formatting")
	}
}

func TestLocalSelfTest_PassesForValidMaterial(t *testing.T) {
	path := writeTokenFile(t, "sk-ok\n")
	if err := static.LocalSelfTest(static.Options{TokenPath: path}); err != nil {
		t.Fatalf("LocalSelfTest rejected valid material: %v", err)
	}
}

func TestLocalSelfTest_FailsClosedForMissingFile(t *testing.T) {
	if err := static.LocalSelfTest(static.Options{TokenPath: filepath.Join(t.TempDir(), "absent")}); err == nil {
		t.Fatalf("LocalSelfTest must fail closed for a missing token file")
	}
}

func TestLocalSelfTest_FailsClosedForEmptyPath(t *testing.T) {
	if err := static.LocalSelfTest(static.Options{}); err == nil {
		t.Fatalf("LocalSelfTest must reject an empty token path")
	}
}

// TestStaticAcquirer_SatisfiesTokenAcquirer is a compile-time-style assertion
// that *static.Acquirer is a token.TokenAcquirer.
func TestStaticAcquirer_SatisfiesTokenAcquirer(t *testing.T) {
	a, _ := static.NewAcquirer(static.Options{TokenPath: writeTokenFile(t, "sk")})
	var _ token.TokenAcquirer = a
}

func assertClass(t *testing.T, err error, want token.AcquireErrorClass) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error of class %s, got nil", want)
	}
	var ae *token.AcquireError
	if !errors.As(err, &ae) {
		t.Fatalf("error %v is not *token.AcquireError", err)
	}
	if ae.Class != want {
		t.Fatalf("error class = %s, want %s", ae.Class, want)
	}
}
