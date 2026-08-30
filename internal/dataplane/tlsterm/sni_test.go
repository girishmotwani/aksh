package tlsterm_test

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/girishmotwani/aksh/internal/dataplane/tlsterm"
)

func TestCanonicaliseServerName(t *testing.T) {
	t.Run("CanonicaliseServerName_EmptyString_ReturnsErrEmptySNI", func(t *testing.T) {
		if _, err := tlsterm.CanonicaliseServerName(""); !errors.Is(err, tlsterm.ErrEmptySNI) {
			t.Fatalf("CanonicaliseServerName(\"\") error = %v, want ErrEmptySNI", err)
		}
	})

	t.Run("CanonicaliseServerName_ValidLowercaseFQDN_ReturnsUnchanged", func(t *testing.T) {
		const in = "svc.ns.svc.cluster.local"
		got, err := tlsterm.CanonicaliseServerName(in)
		if err != nil {
			t.Fatalf("CanonicaliseServerName(%q) error = %v, want nil", in, err)
		}
		if got != in {
			t.Fatalf("CanonicaliseServerName(%q) = %q, want unchanged", in, got)
		}
	})

	t.Run("CanonicaliseServerName_MixedCaseFQDN_ReturnsLowercased", func(t *testing.T) {
		got, err := tlsterm.CanonicaliseServerName("Svc.NS.svc.Cluster.Local")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if want := "svc.ns.svc.cluster.local"; got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("CanonicaliseServerName_TrailingDot_ReturnsWithDotStripped", func(t *testing.T) {
		got, err := tlsterm.CanonicaliseServerName("svc.ns.svc.cluster.local.")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if want := "svc.ns.svc.cluster.local"; got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("CanonicaliseServerName_IPLiteralAsSNI_ReturnsErrInvalidSNI", func(t *testing.T) {
		if _, err := tlsterm.CanonicaliseServerName("127.0.0.1"); !errors.Is(err, tlsterm.ErrInvalidSNI) {
			t.Fatalf("error = %v, want ErrInvalidSNI", err)
		}
	})

	t.Run("CanonicaliseServerName_ExceedsMaxLength_ReturnsErrSNITooLong", func(t *testing.T) {
		// One label of 62 bytes, repeated with dots, to exceed 255 bytes overall
		// without tripping the per-label 63-byte limit.
		label := strings.Repeat("a", 62)
		long := strings.Join([]string{label, label, label, label, label}, ".") // 5*62 + 4 dots = 314 bytes
		if _, err := tlsterm.CanonicaliseServerName(long); !errors.Is(err, tlsterm.ErrSNITooLong) {
			t.Fatalf("error = %v, want ErrSNITooLong", err)
		}
	})

	t.Run("CanonicaliseServerName_ContainsInvalidCharacters_ReturnsErrInvalidSNI", func(t *testing.T) {
		if _, err := tlsterm.CanonicaliseServerName("svc_ns.example.com"); !errors.Is(err, tlsterm.ErrInvalidSNI) {
			t.Fatalf("error = %v, want ErrInvalidSNI", err)
		}
	})

	t.Run("CanonicaliseServerName_LabelExceeds63Bytes_ReturnsErrInvalidSNI", func(t *testing.T) {
		label := strings.Repeat("a", 64)
		if _, err := tlsterm.CanonicaliseServerName(label + ".example.com"); !errors.Is(err, tlsterm.ErrInvalidSNI) {
			t.Fatalf("error = %v, want ErrInvalidSNI", err)
		}
	})

	t.Run("CanonicaliseServerName_PunycodeIDN_ReturnsErrInvalidSNIOrCanonicalForm", func(t *testing.T) {
		// "münchen.example.com" A-label-encoded.
		got, err := tlsterm.CanonicaliseServerName("xn--mnchen-3ya.example.com")
		if err != nil {
			if !errors.Is(err, tlsterm.ErrInvalidSNI) {
				t.Fatalf("error = %v, want ErrInvalidSNI or nil", err)
			}
			return
		}
		if want := "xn--mnchen-3ya.example.com"; got != want {
			t.Fatalf("got %q, want %q (already-ACE label must pass through unchanged)", got, want)
		}
	})

	t.Run("CanonicaliseServerName_WildcardPattern_ReturnsErrInvalidSNI", func(t *testing.T) {
		if _, err := tlsterm.CanonicaliseServerName("*.example.com"); !errors.Is(err, tlsterm.ErrInvalidSNI) {
			t.Fatalf("error = %v, want ErrInvalidSNI", err)
		}
	})

	t.Run("CanonicaliseServerName_SingleLabelHostname_ReturnsErrInvalidSNI", func(t *testing.T) {
		if _, err := tlsterm.CanonicaliseServerName("localhost"); !errors.Is(err, tlsterm.ErrInvalidSNI) {
			t.Fatalf("error = %v, want ErrInvalidSNI", err)
		}
	})

	t.Run("CanonicaliseServerName_LeadingHyphenLabel_ReturnsErrInvalidSNI", func(t *testing.T) {
		if _, err := tlsterm.CanonicaliseServerName("-svc.ns.svc.cluster.local"); !errors.Is(err, tlsterm.ErrInvalidSNI) {
			t.Fatalf("error = %v, want ErrInvalidSNI", err)
		}
	})

	t.Run("CanonicaliseServerName_TrailingHyphenLabel_ReturnsErrInvalidSNI", func(t *testing.T) {
		if _, err := tlsterm.CanonicaliseServerName("svc-.ns.svc.cluster.local"); !errors.Is(err, tlsterm.ErrInvalidSNI) {
			t.Fatalf("error = %v, want ErrInvalidSNI", err)
		}
	})

	t.Run("CanonicaliseServerName_ConsecutiveDots_ReturnsErrInvalidSNI", func(t *testing.T) {
		if _, err := tlsterm.CanonicaliseServerName("svc..ns"); !errors.Is(err, tlsterm.ErrInvalidSNI) {
			t.Fatalf("error = %v, want ErrInvalidSNI", err)
		}
	})

	t.Run("CanonicaliseServerName_Idempotent_SecondCallOnOutputIsNoOp", func(t *testing.T) {
		inputs := []string{
			"svc.ns.svc.cluster.local",
			"Svc.NS.svc.Cluster.Local",
			"svc.ns.svc.cluster.local.",
		}
		for _, in := range inputs {
			first, err := tlsterm.CanonicaliseServerName(in)
			if err != nil {
				t.Fatalf("CanonicaliseServerName(%q) error = %v", in, err)
			}
			second, err := tlsterm.CanonicaliseServerName(first)
			if err != nil {
				t.Fatalf("CanonicaliseServerName(%q) [second pass] error = %v", first, err)
			}
			if first != second {
				t.Fatalf("not idempotent: first=%q second=%q", first, second)
			}
		}
	})

	// CanonicaliseServerName_UsedForT3Classification_MismatchTriggersRejectNoSNI and
	// CanonicaliseServerName_UsedForPostHandshakeAssertion_MismatchTriggersHandshakeReject
	// are Integration-tier tests (spec rows #274, #275) exercised in terminator_test.go
	// against the terminator's actual ClientHello/post-handshake flow, not standalone
	// SNI-canonicalisation unit tests -- see terminator_test.go.

	t.Run("CanonicaliseServerName_UnicodeNonASCIIBytes_ReturnsErrInvalidSNI", func(t *testing.T) {
		if _, err := tlsterm.CanonicaliseServerName("münchen.example.com"); !errors.Is(err, tlsterm.ErrInvalidSNI) {
			t.Fatalf("error = %v, want ErrInvalidSNI", err)
		}
	})

	t.Run("CanonicaliseServerName_MaxLengthBoundaryExactly255Bytes_Passes", func(t *testing.T) {
		// Build a name of exactly 255 bytes using labels <= 63 bytes each,
		// separated by dots, no trailing dot.
		label63 := strings.Repeat("a", 63)
		// 4 labels of 63 bytes + 3 dots = 255 bytes exactly.
		name := strings.Join([]string{label63, label63, label63, label63}, ".")
		if len(name) != 255 {
			t.Fatalf("test construction error: len(name) = %d, want 255", len(name))
		}
		if _, err := tlsterm.CanonicaliseServerName(name); err != nil {
			t.Fatalf("CanonicaliseServerName(255-byte name) error = %v, want nil", err)
		}
	})

	t.Run("CanonicaliseServerName_TableDriven_MatchesGoldenFixtureSet", func(t *testing.T) {
		matches, err := filepath.Glob(filepath.Join("testdata", "sni-fixtures", "*.tsv"))
		if err != nil {
			t.Fatalf("glob fixtures: %v", err)
		}
		if len(matches) == 0 {
			t.Fatal("no fixture files found under testdata/sni-fixtures")
		}

		total := 0
		for _, path := range matches {
			n, err := scanFixtureFile(t, path)
			if err != nil {
				t.Fatalf("scan %s: %v", path, err)
			}
			total += n
		}
		if total < 20 {
			t.Fatalf("fixture set has %d cases, want >= 20 (spec #278)", total)
		}
	})
}

// scanFixtureFile reads one golden-fixture TSV file and asserts each row
// against tlsterm.CanonicaliseServerName, returning the number of cases
// processed. It is a standalone function (rather than inlined into the
// caller's loop) specifically so f.Close() runs at the end of each file via
// defer, instead of accumulating open descriptors across every fixture file
// until the whole enclosing test function returns.
func scanFixtureFile(t *testing.T, path string) (int, error) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	total := 0
	scanner := bufio.NewScanner(f)
	line := 0
	for scanner.Scan() {
		line++
		raw := scanner.Text()
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		parts := strings.SplitN(raw, "\t", 2)
		if len(parts) != 2 {
			t.Fatalf("%s:%d: malformed fixture line %q (want input<TAB>expected)", path, line, raw)
		}
		input, expected := parts[0], parts[1]
		total++

		got, err := tlsterm.CanonicaliseServerName(input)
		if strings.HasPrefix(expected, "ERROR:") {
			wantErrName := strings.TrimPrefix(expected, "ERROR:")
			if err == nil {
				t.Errorf("%s:%d: CanonicaliseServerName(%q) = %q, nil; want error %s", path, line, input, got, wantErrName)
				continue
			}
			if !sentinelMatches(err, wantErrName) {
				t.Errorf("%s:%d: CanonicaliseServerName(%q) error = %v; want %s", path, line, input, err, wantErrName)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s:%d: CanonicaliseServerName(%q) error = %v; want %q", path, line, input, err, expected)
			continue
		}
		if got != expected {
			t.Errorf("%s:%d: CanonicaliseServerName(%q) = %q; want %q", path, line, input, got, expected)
		}
	}
	if err := scanner.Err(); err != nil {
		return total, fmt.Errorf("scan %s: %w", path, err)
	}
	return total, nil
}

// sentinelMatches maps a fixture's "ErrXxx" name to the actual sentinel error
// and checks errors.Is against it, so fixtures stay a data file rather than
// requiring a Go-syntax error reference.
func sentinelMatches(err error, name string) bool {
	switch name {
	case "ErrEmptySNI":
		return errors.Is(err, tlsterm.ErrEmptySNI)
	case "ErrSNITooLong":
		return errors.Is(err, tlsterm.ErrSNITooLong)
	case "ErrInvalidSNI":
		return errors.Is(err, tlsterm.ErrInvalidSNI)
	default:
		return false
	}
}
