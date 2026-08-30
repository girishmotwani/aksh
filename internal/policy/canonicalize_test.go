package policy_test

import (
	"testing"

	"github.com/girishmotwani/aksh/internal/policy"
)

func TestCanonicalizePath(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		// Clean paths pass through.
		{name: "clean path unchanged", input: "/a/b/c", want: "/a/b/c"},
		{name: "root unchanged", input: "/", want: "/"},
		{name: "trailing slash preserved", input: "/a/b/", want: "/a/b/"},

		// Slash and dot normalisation.
		{name: "duplicate slashes collapsed", input: "/a//b", want: "/a/b"},
		{name: "triple slashes collapsed", input: "/a///b", want: "/a/b"},
		{name: "single dot resolved", input: "/a/./b", want: "/a/b"},
		{name: "double dot resolved", input: "/a/b/../c", want: "/a/c"},
		{name: "multi-level dotdot", input: "/a/b/../../c", want: "/c"},
		{name: "trailing dotdot", input: "/a/b/..", want: "/a"},
		{name: "combined collapse and resolve", input: "/a///b/../c", want: "/a/c"},

		// Percent-decoding: only unreserved chars are decoded.
		{name: "unreserved char decoded", input: "/a/%41/b", want: "/a/A/b"},
		{name: "tilde unreserved decoded", input: "/%7E/file", want: "/~/file"},
		{name: "encoded slash NOT decoded", input: "/a/%2F/b", want: "/a/%2F/b"},
		{name: "encoded backslash NOT decoded", input: "/a/%5C/b", want: "/a/%5C/b"},
		{name: "encoded dots decoded and resolved", input: "/a/%2e%2e/b", want: "/b"},

		// Query string stripped.
		{name: "query string stripped", input: "/a/b?query=1", want: "/a/b"},

		// Rejections.
		{name: "traversal past root rejected", input: "/../escape", wantErr: true},
		{name: "literal backslash rejected", input: "/a/b\\c", wantErr: true},
		{name: "null byte rejected", input: "/a/b%00c", wantErr: true},
		{name: "malformed percent-escape rejected", input: "/a/%GG/b", wantErr: true},
		{name: "empty string rejected", input: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := policy.CanonicalizePath(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("CanonicalizePath(%q) = %q, want error", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("CanonicalizePath(%q) unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("CanonicalizePath(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
