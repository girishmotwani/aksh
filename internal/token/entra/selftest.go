package entra

import (
	"fmt"
	"os"
	"strings"
)

// LocalSelfTest validates Entra WIF readiness using only local inputs — it
// performs zero network calls. It checks that the options are well-formed and
// that the projected ServiceAccount token file is readable and shaped like a
// JWT, so a misconfigured pod fails closed at startup instead of on first
// request.
//
// Any HTTPClient in opts is intentionally never used; passing a panic-on-use
// client proves this method makes no exchange.
func LocalSelfTest(opts Options) error {
	if strings.TrimSpace(opts.TenantID) == "" {
		return fmt.Errorf("entra: LocalSelfTest: TenantID must not be empty")
	}
	if strings.TrimSpace(opts.ClientID) == "" {
		return fmt.Errorf("entra: LocalSelfTest: ClientID must not be empty")
	}
	if strings.TrimSpace(opts.SATokenPath) == "" {
		return fmt.Errorf("entra: LocalSelfTest: SATokenPath must not be empty")
	}
	if err := validateAuthority(opts.Authority); err != nil {
		return fmt.Errorf("entra: LocalSelfTest: %w", err)
	}

	raw, err := os.ReadFile(opts.SATokenPath)
	if err != nil {
		return fmt.Errorf("entra: LocalSelfTest: read projected SA token %s: %w", opts.SATokenPath, err)
	}
	if decodeJWTUnverified(strings.TrimSpace(string(raw))) == nil {
		return fmt.Errorf("entra: LocalSelfTest: projected SA token at %s is not a valid JWT", opts.SATokenPath)
	}
	return nil
}
