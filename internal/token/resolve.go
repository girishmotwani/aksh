package token

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

const credentialIdentityVersion = "aksh-cred-v1"

// Resolve canonicalizes a credential selector into the broker's wire form.
func Resolve(sel CredentialSelector) (ResolvedCredential, error) {
	if sel.IsEmpty() {
		// The sentinel is deliberately outside the fixed-length hex identity
		// space, so no-auth rules cannot collide with a real credential.
		return ResolvedCredential{Identity: "none"}, nil
	}

	provider := strings.ToLower(strings.TrimSpace(sel.Provider))
	if provider == "" {
		provider = "entra"
	}

	resource, err := normalizeResource(sel.Resource)
	if err != nil {
		return ResolvedCredential{}, err
	}

	wireScopes := make([]string, 0, len(sel.Scopes))
	seen := make(map[string]struct{}, len(sel.Scopes))
	for _, scope := range sel.Scopes {
		// Validate before composing the OAuth parameter: spaces or controls can
		// change its wire-level meaning and must not cross this boundary.
		if err := validateScope(scope); err != nil {
			return ResolvedCredential{}, err
		}

		wire := scope
		if !strings.Contains(scope, "://") {
			wire = joinResourceScope(resource, scope)
		}

		if _, ok := seen[wire]; ok {
			continue
		}
		seen[wire] = struct{}{}
		wireScopes = append(wireScopes, wire)
	}

	// Scopes are a set semantically. Sorting and de-duplicating keeps cache,
	// connection-pool, and audit identities stable across policy spellings.
	sort.Strings(wireScopes)

	return ResolvedCredential{
		Identity:   resolvedIdentity(provider, resource, wireScopes),
		Provider:   provider,
		Resource:   resource,
		WireScopes: wireScopes,
	}, nil
}

func normalizeResource(resource string) (string, error) {
	resource = strings.TrimSpace(resource)
	if resource == "" {
		return "", nil
	}

	parsed, err := url.Parse(resource)
	if err == nil && parsed.IsAbs() && parsed.Host != "" {
		parsed.Scheme = strings.ToLower(parsed.Scheme)
		parsed.Host = normalizeHostPort(parsed.Scheme, parsed.Host)
		if parsed.Path == "/" && parsed.RawPath == "" {
			parsed.Path = ""
		}

		value := parsed.String()
		for len(value) > 0 && strings.HasSuffix(value, "/") {
			reparsed, parseErr := url.Parse(value)
			if parseErr != nil || reparsed.Path != "" && reparsed.Path != "/" {
				break
			}
			value = strings.TrimSuffix(value, "/")
		}
		return value, nil
	}

	// Entra also accepts opaque resource identifiers such as GUIDs. Treating
	// only absolute hosted URLs as URLs avoids path normalization changing them.
	return strings.ToLower(resource), nil
}

func normalizeHostPort(scheme, host string) string {
	hostname := strings.ToLower(host)
	port := ""

	if strings.Contains(host, ":") {
		if parsedHost, parsedPort, err := net.SplitHostPort(host); err == nil {
			hostname = strings.ToLower(parsedHost)
			port = parsedPort
		}
	}

	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}

	if port == "" {
		return hostname
	}
	return net.JoinHostPort(hostname, port)
}

func validateScope(scope string) error {
	for _, r := range scope {
		if r == ' ' || unicode.IsControl(r) {
			return fmt.Errorf("invalid scope %q", scope)
		}
	}
	return nil
}

func joinResourceScope(resource, scope string) string {
	return strings.TrimRight(resource, "/") + "/" + strings.TrimLeft(scope, "/")
}

func resolvedIdentity(provider, resource string, wireScopes []string) string {
	h := sha256.New()
	// Versioned length prefixes make the tuple unambiguous even when fields
	// contain separator-like bytes and permit future derivation changes safely.
	writeLP(h, credentialIdentityVersion)
	writeLP(h, provider)
	// Resource remains explicit so credentials with no scopes cannot collapse
	// onto the same identity.
	writeLP(h, resource)
	writeLP(h, strconv.Itoa(len(wireScopes)))
	for _, scope := range wireScopes {
		writeLP(h, scope)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func writeLP(h interface{ Write([]byte) (int, error) }, value string) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = h.Write(length[:])
	_, _ = h.Write([]byte(value))
}
