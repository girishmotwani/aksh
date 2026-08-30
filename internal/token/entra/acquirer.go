// Package entra implements the Microsoft Entra Workload Identity Federation
// token acquirer plus CRD-facing resolution and local-only readiness checks.
package entra

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/girishmotwani/aksh/internal/token"
)

// providerEntra is the only credential provider this acquirer serves.
const providerEntra = "entra"

// Options configures the Entra WIF acquirer.
type Options struct {
	TenantID    string
	ClientID    string
	Authority   string // HTTPS token endpoint base
	SATokenPath string
	HTTPClient  *http.Client
	Timeout     time.Duration
}

// Acquirer performs the Entra WIF client-credentials + client_assertion
// (JWT-bearer) exchange, trading the pod's projected ServiceAccount token for
// an access token carrying the workload identity.
type Acquirer struct {
	tenantID    string
	clientID    string
	authority   string
	saTokenPath string
	hc          *http.Client
}

// NewAcquirer validates the options and constructs an Acquirer. Every field is
// validated before any HTTP client path is built so misconfiguration fails
// closed instead of falling back to ambient credentials.
func NewAcquirer(opts Options) (*Acquirer, error) {
	if strings.TrimSpace(opts.TenantID) == "" {
		return nil, fmt.Errorf("entra: TenantID must not be empty")
	}
	if strings.TrimSpace(opts.ClientID) == "" {
		return nil, fmt.Errorf("entra: ClientID must not be empty")
	}
	if strings.TrimSpace(opts.SATokenPath) == "" {
		return nil, fmt.Errorf("entra: SATokenPath must not be empty")
	}
	if err := validateAuthority(opts.Authority); err != nil {
		return nil, err
	}

	hc := opts.HTTPClient
	if hc == nil {
		timeout := opts.Timeout
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		hc = &http.Client{Timeout: timeout}
	}

	return &Acquirer{
		tenantID:    opts.TenantID,
		clientID:    opts.ClientID,
		authority:   opts.Authority,
		saTokenPath: opts.SATokenPath,
		hc:          hc,
	}, nil
}

// tokenResponse is the subset of the OAuth2 token response Aksh consumes.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// defaultTokenTTL guards against an absent or non-positive expires_in.
const defaultTokenTTL = 5 * time.Minute

// Acquire performs the Entra WIF client-credentials + client_assertion exchange
// for the given resolved credential. It implements token.TokenAcquirer.
//
// The projected SA token is re-read on every call so short-lived rotations take
// effect without restarting the process. Failures are classified into
// *token.AcquireError so the runtime can retry transient failures and negative
// cache permanent ones.
func (a *Acquirer) Acquire(ctx context.Context, rc token.ResolvedCredential) (token.Token, error) {
	if rc.Provider != providerEntra {
		// Reject before touching the SA token: this acquirer only serves the
		// entra provider and must never exchange another provider's credential.
		return token.Token{}, &token.AcquireError{
			Class:   token.AcquireErrorPermanent,
			Message: fmt.Sprintf("entra: acquirer cannot serve provider %q, only %q", rc.Provider, providerEntra),
		}
	}

	assertion, err := os.ReadFile(a.saTokenPath)
	if err != nil {
		return token.Token{}, a.fail(&token.AcquireError{
			Class:   token.AcquireErrorLocal,
			Message: fmt.Sprintf("entra: read projected SA token %s", a.saTokenPath),
			Cause:   err,
		})
	}

	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {a.clientID},
		"scope":                 {strings.Join(rc.WireScopes, " ")},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {strings.TrimSpace(string(assertion))},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.authority, strings.NewReader(form.Encode()))
	if err != nil {
		return token.Token{}, a.fail(&token.AcquireError{
			Class:   token.AcquireErrorLocal,
			Message: "entra: build token request",
			Cause:   err,
		})
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.hc.Do(req)
	if err != nil {
		// Context cancellation and transport timeouts are retryable; preserve
		// the cause so callers can inspect context.DeadlineExceeded.
		return token.Token{}, a.fail(&token.AcquireError{
			Class:   token.AcquireErrorTransient,
			Message: "entra: token endpoint request failed",
			Cause:   err,
		})
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if readErr != nil {
		// A truncated read leaves body incomplete; classifying it as a
		// permanent empty-token failure would be wrong. Retry is safe.
		return token.Token{}, a.fail(&token.AcquireError{
			Class:   token.AcquireErrorTransient,
			Message: "entra: read token endpoint response body",
			Cause:   readErr,
		})
	}

	if resp.StatusCode != http.StatusOK {
		return token.Token{}, a.fail(classifyHTTPFailure(resp.StatusCode, body))
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return token.Token{}, a.fail(&token.AcquireError{
			Class:   token.AcquireErrorTransient,
			Message: "entra: decode token response",
			Cause:   err,
		})
	}
	if tr.AccessToken == "" {
		return token.Token{}, a.fail(&token.AcquireError{
			Class:   token.AcquireErrorPermanent,
			Message: "entra: token response had empty access_token",
		})
	}

	ttl := time.Duration(tr.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = defaultTokenTTL
	}
	return token.NewToken(tr.AccessToken, time.Now().Add(ttl)), nil
}

// classifyHTTPFailure maps a non-200 token endpoint response to a classified
// acquire error. 429/5xx are transient; well-formed OAuth client errors such as
// invalid_scope/invalid_client are permanent.
func classifyHTTPFailure(status int, body []byte) *token.AcquireError {
	if status == http.StatusTooManyRequests || status == http.StatusRequestTimeout || status >= 500 {
		return &token.AcquireError{
			Class:   token.AcquireErrorTransient,
			Message: fmt.Sprintf("entra: token endpoint status %d", status),
		}
	}

	oauthErr := ""
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err == nil {
		oauthErr = tr.Error
	}
	msg := fmt.Sprintf("entra: token endpoint status %d", status)
	if oauthErr != "" {
		msg = fmt.Sprintf("%s (%s)", msg, oauthErr)
	}
	return &token.AcquireError{
		Class:   token.AcquireErrorPermanent,
		Message: msg,
	}
}

// fail emits bounded failure logging — provider and error class only, never SA
// assertions, client assertions, or access tokens — and returns the error.
func (a *Acquirer) fail(err *token.AcquireError) *token.AcquireError {
	class := err.Class.String()
	if cause := err.Unwrap(); cause != nil && errors.Is(cause, context.Canceled) {
		// Do not log routine cancellations at the same level, but still avoid
		// any token material.
		log.Printf("entra: acquire cancelled provider=%s class=%s", providerEntra, class)
		return err
	}
	log.Printf("entra: acquire failed provider=%s class=%s", providerEntra, class)
	return err
}

// decodeJWTUnverified is retained for future claim-based diagnostics; it never
// logs token material and does not verify signatures.
func decodeJWTUnverified(jwt string) map[string]any {
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil
	}
	return claims
}

// validateAuthority rejects http:// and schemeless authorities; only absolute
// HTTPS URLs with a host are accepted.
func validateAuthority(authority string) error {
	if strings.TrimSpace(authority) == "" {
		return fmt.Errorf("entra: Authority must be a non-empty HTTPS URL")
	}
	parsed, err := url.Parse(authority)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return fmt.Errorf("entra: Authority %q must be an absolute HTTPS URL", authority)
	}
	if strings.ToLower(parsed.Scheme) != "https" {
		return fmt.Errorf("entra: Authority %q must use https (only HTTPS authorities are accepted)", authority)
	}
	return nil
}
