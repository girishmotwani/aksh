package policy

import (
	"errors"
	"fmt"
	"strings"
)

// CanonicalizePath implements S2 §5.1.1. It produces the canonical path
// representation that is matched against policy AND forwarded upstream,
// so the two can never disagree.
func CanonicalizePath(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("empty path")
	}

	// Strip query string.
	path := raw
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		path = path[:idx]
	}

	// Reject literal backslash.
	if strings.ContainsRune(path, '\\') {
		return "", errors.New("path contains backslash")
	}

	// Percent-decode only unreserved characters, reject null and malformed escapes.
	decoded, err := decodeUnreserved(path)
	if err != nil {
		return "", err
	}
	path = decoded

	if path == "" || path[0] != '/' {
		return "", errors.New("path must start with /")
	}

	// Split into segments, resolve . and .., collapse empty segments.
	segments := strings.Split(path, "/")
	var resolved []string
	for _, seg := range segments[1:] { // skip leading empty from split
		switch seg {
		case "":
			// duplicate slash — skip
		case ".":
			// current dir — skip
		case "..":
			if len(resolved) == 0 {
				return "", errors.New("path traversal past root")
			}
			resolved = resolved[:len(resolved)-1]
		default:
			resolved = append(resolved, seg)
		}
	}

	// Preserve trailing slash if the original (post-query-strip) had one.
	trailing := len(path) > 1 && path[len(path)-1] == '/'
	result := "/" + strings.Join(resolved, "/")
	if trailing && !strings.HasSuffix(result, "/") {
		result += "/"
	}

	return result, nil
}

// decodeUnreserved percent-decodes only RFC 3986 unreserved characters:
// A-Z a-z 0-9 - . _ ~
// Rejects null bytes and malformed percent-escapes.
func decodeUnreserved(s string) (string, error) {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			b.WriteByte(s[i])
			continue
		}
		if i+2 >= len(s) {
			return "", fmt.Errorf("malformed percent-escape at position %d", i)
		}
		hi := unhex(s[i+1])
		lo := unhex(s[i+2])
		if hi < 0 || lo < 0 {
			return "", fmt.Errorf("malformed percent-escape at position %d", i)
		}
		decoded := byte(hi<<4 | lo)
		if decoded == 0 {
			return "", errors.New("path contains null byte")
		}
		if isUnreserved(decoded) {
			b.WriteByte(decoded)
		} else {
			// Keep the percent-encoding for reserved/other characters.
			b.WriteString(s[i : i+3])
		}
		i += 2
	}
	return b.String(), nil
}

// isUnreserved returns true for RFC 3986 §2.3 unreserved characters.
// These are the ONLY characters that percent-decoding normalises:
//
//	ALPHA / DIGIT / "-" / "." / "_" / "~"
//
// Dot (".") is included per the RFC, which is critical for path
// traversal resolution (../ segments must be decoded before resolving).
func isUnreserved(c byte) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

// unhex converts a single hex digit character to its integer value (0-15).
// Returns -1 for non-hex characters, which the caller uses to detect
// malformed percent-escapes like "%GG".
func unhex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	default:
		return -1
	}
}
