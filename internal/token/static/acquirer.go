// Package static implements a file-backed static bearer credential acquirer.
//
// Unlike the Entra WIF acquirer, which performs a live token exchange, this
// provider reads a pre-provisioned bearer credential (for example an OpenAI API
// key) from a file mounted only into the Aksh sidecar. The agent container
// never holds the secret: kagent uses a dummy key, Aksh strips the caller's
// Authorization, and a matched policy credential selector (provider "static")
// injects the real key as Authorization: Bearer <key>.
//
// There is no refresh protocol: the file is re-read on every acquisition so a
// rotated Secret takes effect once the kubelet rewrites the projected file and
// the existing cache entry expires. The secret value is never logged or
// serialized — it lives only inside a token.Token, which redacts itself.
package static

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/girishmotwani/aksh/internal/token"
)

// providerStatic is the only credential provider this acquirer serves.
const providerStatic = "static"

// maxTokenBytes bounds how much of the token file is read. A bearer credential
// is small; anything larger is treated as invalid material rather than loaded
// into memory. The reader consumes one byte past the cap so an oversized file
// is detected without an unbounded read.
const maxTokenBytes = 8 * 1024

// defaultTokenTTL is the bounded synthetic expiry stamped on a static token.
//
// A static credential has no issuer-advertised lifetime, so Aksh assigns one
// that is comfortably larger than the cache's clock-skew margin
// (token.tokenSkewMargin, 60s) — otherwise the cache would reject every freshly
// read token as "expires within skew margin". The TTL also bounds how long a
// rotated secret can take to propagate: once it elapses the cache re-reads the
// file. Five minutes matches the Entra acquirer's default TTL.
const defaultTokenTTL = 5 * time.Minute

// minUsableTTL is the smallest synthetic lifetime that survives the token
// cache's clock-skew margin. A token minted with a shorter TTL would be
// discarded immediately, so the constructor rejects such configuration rather
// than silently serving unusable tokens.
const minUsableTTL = 90 * time.Second

// Options configures the static bearer acquirer.
type Options struct {
	// TokenPath is the absolute path of the file holding the bearer credential.
	TokenPath string
	// TTL overrides the synthetic token lifetime. Non-positive selects
	// defaultTokenTTL. Values below minUsableTTL are rejected at construction so
	// a configured acquirer can never mint tokens the cache would discard.
	TTL time.Duration
}

// Acquirer reads a static bearer credential from a file and returns it as a
// token.Token with a bounded synthetic expiry. It implements token.TokenAcquirer.
type Acquirer struct {
	tokenPath string
	ttl       time.Duration
}

// NewAcquirer validates the options and constructs an Acquirer. The token path
// must be non-empty; the file itself is not required to exist at construction
// (LocalSelfTest performs the fail-closed startup read). A configured but
// too-short TTL is rejected so misconfiguration fails closed instead of minting
// tokens the cache will not accept.
func NewAcquirer(opts Options) (*Acquirer, error) {
	if strings.TrimSpace(opts.TokenPath) == "" {
		return nil, fmt.Errorf("static: TokenPath must not be empty")
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = defaultTokenTTL
	}
	if ttl < minUsableTTL {
		return nil, fmt.Errorf("static: TTL must be at least %s", minUsableTTL)
	}
	return &Acquirer{tokenPath: strings.TrimSpace(opts.TokenPath), ttl: ttl}, nil
}

// Acquire reads the configured file and returns its contents as a bearer token.
// It re-reads on every call so a rotated Secret takes effect without a restart.
//
// Failures are classified into *token.AcquireError: a missing or unreadable
// file is Local (Aksh's own mount/config problem), while empty or oversized
// material is Permanent (the secret content is wrong and will not fix itself on
// retry). The negative cache therefore suppresses repeated reads of a
// structurally invalid secret while still retrying a transiently absent mount.
func (a *Acquirer) Acquire(_ context.Context, rc token.ResolvedCredential) (token.Token, error) {
	if rc.Provider != providerStatic {
		return token.Token{}, &token.AcquireError{
			Class:   token.AcquireErrorPermanent,
			Message: fmt.Sprintf("static: acquirer cannot serve provider %q, only %q", rc.Provider, providerStatic),
		}
	}

	value, err := readToken(a.tokenPath)
	if err != nil {
		return token.Token{}, err
	}
	return token.NewToken(value, time.Now().Add(a.ttl)), nil
}

// readToken reads and validates the bearer credential at path. The returned
// string is the secret and must never be logged; every error is classified and
// carries only the bounded path, never file contents.
func readToken(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", &token.AcquireError{
			Class:   token.AcquireErrorLocal,
			Message: fmt.Sprintf("static: open token file %s", path),
			Cause:   err,
		}
	}
	defer f.Close()

	raw, err := io.ReadAll(io.LimitReader(f, maxTokenBytes+1))
	if err != nil {
		return "", &token.AcquireError{
			Class:   token.AcquireErrorLocal,
			Message: fmt.Sprintf("static: read token file %s", path),
			Cause:   err,
		}
	}
	if len(raw) > maxTokenBytes {
		return "", &token.AcquireError{
			Class:   token.AcquireErrorPermanent,
			Message: fmt.Sprintf("static: token file %s exceeds %d bytes", path, maxTokenBytes),
		}
	}

	value := trimOneTrailingNewline(string(raw))
	if value == "" {
		return "", &token.AcquireError{
			Class:   token.AcquireErrorPermanent,
			Message: fmt.Sprintf("static: token file %s is empty", path),
		}
	}
	for _, r := range value {
		if r <= 0x20 || r == 0x7f {
			return "", &token.AcquireError{
				Class:   token.AcquireErrorPermanent,
				Message: fmt.Sprintf("static: token file %s contains whitespace or control characters", path),
			}
		}
	}
	return value, nil
}

// trimOneTrailingNewline removes at most one trailing line terminator ("\n" or
// "\r\n") added by common file-writing tools. Remaining whitespace/control
// characters are rejected before the value can become an HTTP header.
func trimOneTrailingNewline(s string) string {
	if strings.HasSuffix(s, "\n") {
		s = s[:len(s)-1]
		if strings.HasSuffix(s, "\r") {
			s = s[:len(s)-1]
		}
	}
	return s
}
