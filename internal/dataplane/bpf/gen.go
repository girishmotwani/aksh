// Package bpf holds the Aksh capture layer's BPF C source, the minimal UAPI
// headers it needs, and the generated Go bindings and object committed
// alongside them.
//
// The bindings and the object are generated artefacts that are committed to the
// repository on purpose (ADR-S1a-05): most of this team develops on Windows and
// CI has no clang, so `go generate` is an explicit developer step rather than
// part of `go build`. CI regenerates on Linux and fails on any diff. See
// README.md in this directory for the regeneration command, the pinned clang
// version and the artefact checksums.
package bpf

// The directive below is design section 6.4.4, with two adaptations recorded in
// the Findings document: the paths are relative to this directory rather than to
// internal/dataplane/capture, and the config struct is `aksh_cfg` because bpf2go
// cannot disambiguate a BTF struct from a BTF var of the same name.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target bpfel -type orig_dst -type pair_key -type aksh_cfg Akshbpf ./aksh_capture.c -- -I./include -O2 -g -Wall -Werror
