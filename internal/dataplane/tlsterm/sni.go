package tlsterm

import (
	"net/netip"
	"strings"
)

// maxSNIBytes is the RFC 1035-derived maximum length for a canonicalised
// server name, per spec rows #264/#277: 255 bytes, checked after trailing
// root-zone-dot stripping.
const maxSNIBytes = 255

// maxLabelBytes is the RFC 1035 maximum length of a single DNS label.
const maxLabelBytes = 63

// CanonicaliseServerName validates and canonicalises a TLS ClientHello server
// name (SNI) per the ordered rule set in
// docs/design/S1a-dataplane-capture.md §11.
func CanonicaliseServerName(name string) (string, error) {
	if name == "" {
		return "", ErrEmptySNI
	}

	// Strip a single trailing root-zone dot before the length check, so a
	// 256-byte input that becomes 255 bytes after stripping is accepted.
	name = strings.TrimSuffix(name, ".")

	if len(name) > maxSNIBytes {
		return "", ErrSNITooLong
	}

	name = strings.ToLower(name)

	// Reject IP literals (RFC 6066 disallows them in SNI). Checked on the
	// already-lowercased string so uppercase IPv6 literals are still caught.
	if _, err := netip.ParseAddr(name); err == nil {
		return "", ErrInvalidSNI
	}

	if !strings.Contains(name, ".") {
		return "", ErrInvalidSNI
	}

	labels := strings.Split(name, ".")
	canonLabels := make([]string, 0, len(labels))
	for _, label := range labels {
		if label == "" {
			return "", ErrInvalidSNI
		}
		if strings.Contains(label, "*") {
			return "", ErrInvalidSNI
		}
		if len(label) > maxLabelBytes {
			return "", ErrInvalidSNI
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", ErrInvalidSNI
		}

		if !isLDH(label) {
			return "", ErrInvalidSNI
		}

		canonLabels = append(canonLabels, label)
	}

	return strings.Join(canonLabels, "."), nil
}

// isLDH reports whether s consists only of letters, digits, and hyphens
// (the DNS "LDH" label alphabet), checked per-label -- '.' is the label
// separator and is never itself subject to this check. Callers must
// pre-lowercase s (CanonicaliseServerName does this before calling isLDH);
// only the lowercase-letter range is checked.
func isLDH(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-':
		default:
			return false
		}
	}
	return true
}
