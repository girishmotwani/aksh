package static

import (
	"fmt"
	"strings"
)

// LocalSelfTest validates static bearer readiness using only local inputs — it
// performs zero network calls. It checks that the options are well-formed and
// that the configured token file exists, is readable, and holds bounded
// non-empty material, so a misconfigured pod fails closed at startup instead of
// on first request.
//
// It never returns or logs the secret value: on success it returns nil, and on
// failure it returns only the classified, path-bounded error from readToken.
func LocalSelfTest(opts Options) error {
	if strings.TrimSpace(opts.TokenPath) == "" {
		return fmt.Errorf("static: LocalSelfTest: TokenPath must not be empty")
	}
	if _, err := readToken(strings.TrimSpace(opts.TokenPath)); err != nil {
		return fmt.Errorf("static: LocalSelfTest: %w", err)
	}
	return nil
}
