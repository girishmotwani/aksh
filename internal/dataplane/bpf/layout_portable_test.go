package bpf

import (
	"os"
	"strings"
	"testing"
)

func TestLicenseString_IsGPL_MatchesSourceLicenseDeclaration(t *testing.T) {
	if _, err := os.Stat(bpfPackagePath("akshbpf_bpfel.o")); err != nil {
		t.Fatalf("generated object missing: %v", err)
	}

	spec, err := loadEmbeddedCollectionSpecPortable()
	if err != nil {
		t.Fatalf("loadEmbeddedCollectionSpecPortable() error = %v", err)
	}

	if len(spec.Programs) == 0 {
		t.Fatal("spec.Programs is empty")
	}
	for name, prog := range spec.Programs {
		if prog.License != "GPL" {
			t.Fatalf("program %q license = %q, want %q", name, prog.License, "GPL")
		}
	}
}

func TestAksh_CFileHasGoBuildIgnoreTag_WindowsBuildUnaffected(t *testing.T) {
	content, err := os.ReadFile(bpfPackagePath("aksh_capture.c"))
	if err != nil {
		t.Fatalf("ReadFile(aksh_capture.c) error = %v", err)
	}

	// Split on \n rather than requiring an exact "...ignore\n" prefix so a
	// CRLF checkout (first line ending "...ignore\r\n") doesn't produce a
	// false negative purely from line-ending style; TestGitAttributes below
	// enforces eol=lf for this directory, but this test's own assertion
	// should check tag presence, not checkout line-ending configuration.
	firstLine, _, _ := strings.Cut(string(content), "\n")
	firstLine = strings.TrimRight(firstLine, "\r")
	if firstLine != "//go:build ignore" {
		t.Fatalf("aksh_capture.c first line = %q, want %q", firstLine, "//go:build ignore")
	}
}

func TestGitAttributes_PinsLFForBPFDirectory_ReproducibleObjectAcrossCheckoutLineEndings(t *testing.T) {
	content, err := os.ReadFile(bpfPackagePath(".gitattributes"))
	if err != nil {
		t.Fatalf("ReadFile(.gitattributes) error = %v", err)
	}

	// Parse line by line and require concrete rules pinning eol=lf for the
	// specific patterns this directory's reproducibility depends on (the C
	// source and headers whose lines end up verbatim in the committed
	// BPF object's BTF line info, per ADR-S1a-05) rather than a bare
	// substring search, which would pass on any unrelated "eol=lf" text
	// anywhere in the file.
	required := map[string]bool{"*.c": false, "*.h": false}
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pattern := fields[0]
		if _, tracked := required[pattern]; !tracked {
			continue
		}
		for _, attr := range fields[1:] {
			if strings.EqualFold(attr, "eol=lf") {
				required[pattern] = true
			}
		}
	}
	for pattern, found := range required {
		if !found {
			t.Fatalf(".gitattributes missing a %q rule with eol=lf: %q", pattern, string(content))
		}
	}
}
