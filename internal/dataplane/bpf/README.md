# `internal/dataplane/bpf` - the Aksh capture layer, kernel side

This package holds the BPF C source for the phase 5A capture layer, the minimal
UAPI headers it needs, and the **generated Go bindings and BPF object, which are
committed on purpose** (ADR-S1a-05). Design: `docs/design/S1a-dataplane-capture.md`,
section 6.

## Contents

| File | What it is |
| ---- | ---------- |
| `aksh_capture.c` | The six BPF programs and four maps (design 6.2, 6.3, 6.4, 6.9) |
| `include/aksh_uapi_bpf.h` | Vendored subset of `<linux/bpf.h>`: `bpf_sock_addr`, `bpf_sock`, `bpf_sock_ops` and the constants used |
| `include/aksh_bpf_helpers.h` | Vendored subset of libbpf's `bpf_helpers.h` / `bpf_endian.h`: `SEC`, the map macros, six helper IDs, the byte-order macros |
| `gen.go` | The `//go:generate` directive (design 6.4.4) and the package doc |
| `akshbpf_bpfel.go` | Generated bindings. `//go:build ... && linux`, so this file is absent from a Windows build |
| `akshbpf_bpfel.o` | Generated object, embedded into the bindings with `//go:embed` |

Nothing here is imported by anything yet: `internal/dataplane/capture` is a
later deliverable of the same phase.

## Regeneration

Generation is an explicit developer step and is **not** part of `go build`.

```sh
cd internal/dataplane/bpf
go generate ./...
```

which expands to

```sh
go run github.com/cilium/ebpf/cmd/bpf2go \
    -tags linux -target bpfel \
    -type orig_dst -type pair_key -type aksh_cfg \
    Akshbpf ./aksh_capture.c -- -I./include -O2 -g -Wall -Werror
```

Requires Linux and clang. It does **not** require kernel headers, `vmlinux.h`,
BTF from the build host, or libbpf: everything the C source includes is in
`include/`, which is what makes the object depend on the pinned toolchain and
nothing else.

## Pinned toolchain

The artefacts below were generated with exactly these versions. The `bpf-object`
job in [`.github/workflows/ci.yml`](../../../.github/workflows/ci.yml)
regenerates them on every push and pull request using the pinned image in
[`test/ci/bpfgen.Dockerfile`](../../../test/ci/bpfgen.Dockerfile), and fails on
any diff -- so a toolchain change, or an edit to `aksh_capture.c` committed
without regenerating, shows up as a build failure rather than a runtime
surprise.

| Tool | Version |
| ---- | ------- |
| clang | `Ubuntu clang version 14.0.0-1ubuntu1.1` (`/usr/bin/clang`) |
| `bpf2go` / `github.com/cilium/ebpf` | `v0.22.0` |
| Go | `go1.26.0 linux/amd64` |
| Validation kernel | `5.15.167.4-microsoft-standard-WSL2` (the design's 5.15 floor) |

Regenerating twice in a row produces a byte-identical object, and a CRLF
checkout produces the same object as an LF checkout (the `.gitattributes` in
this directory pins LF anyway).

## Artefact checksums

SHA-256 of the committed artefacts, as generated:

| File | SHA-256 |
| ---- | ------- |
| `akshbpf_bpfel.o` | `40313bf61337d2b8652e6be8c3a6d4c565b1c6f22414d4ac09397e0cf7ad7b3f` |
| `akshbpf_bpfel.go` | `4938a67396f3ef9bb68e0c75c8a0ace48d1ef6ce08649be557b0029d24980e91` |

Verify with:

```sh
sha256sum internal/dataplane/bpf/akshbpf_bpfel.o
```

## Programs and maps

| Program | Section | Attach type | Verdict convention |
| ------- | ------- | ----------- | ------------------ |
| `aksh_connect4` | `cgroup/connect4` | `BPF_CGROUP_INET4_CONNECT` | 1 allow, 0 = `EPERM` from `connect()` |
| `aksh_sockops` | `sockops` | `BPF_CGROUP_SOCK_OPS` | return value is not a verdict |
| `aksh_sock_create` | `cgroup/sock_create` | `BPF_CGROUP_INET_SOCK_CREATE` | 1 allow, 0 = `EPERM` from `socket()` |
| `aksh_sendmsg4` | `cgroup/sendmsg4` | `BPF_CGROUP_UDP4_SENDMSG` | 1 allow, 0 = `EPERM` |
| `aksh_connect6_deny` | `cgroup/connect6` | `BPF_CGROUP_INET6_CONNECT` | 1 allow, 0 = `EPERM` |
| `aksh_sendmsg6` | `cgroup/sendmsg6` | `BPF_CGROUP_UDP6_SENDMSG` | 1 allow, 0 = `EPERM` |

| Map | Type | Key | Value | Default `max_entries` |
| --- | ---- | --- | ----- | --------------------- |
| `cookie_orig_dst` | `LRU_HASH` | `__u64` socket cookie | `struct orig_dst` (24 B) | 16384 |
| `pair_orig_dst` | `LRU_HASH` | `struct pair_key` (8 B) | `struct orig_dst` (24 B) | 16384 |
| `aksh_config` | `ARRAY` | `__u32` (always 0) | `struct aksh_cfg` (32 B) | 1 |
| `bypass_cidr4` | `LPM_TRIE` | `struct bypass_key` (8 B) | `__u8` | 64 |

`max_entries` is overridden by the loader on the `CollectionSpec` before
`NewCollection`, so section 13.1's sizes are configurable without regenerating
the object.

## Constraints the Go loader must honour

These are properties of the kernel, observed on the 5.15 floor kernel during
validation. They are recorded
here because the loader is what has to satisfy them.

1. **No policy literal belongs in this C source.** The proxy UID, the listener
   address and port, and the DNS exception are read from `aksh_config` on every
   hook invocation. Writing the config is a load-time step that happens *before*
   attach; the programs treat a missing config as "loader is mid-init".
2. **A link pin must be chowned to the post-drop UID.** `BPF_OBJ_GET` on a
   pinned link resolves the path through the ordinary VFS. A root-owned `0600`
   pin gives a `CAP_BPF`-only reader `EACCES (13)`, not a capability error, so
   the attachment health check of design 6.8.5 fails after the privilege drop
   unless gate P15's `fchownat` to `(ProxyUID, ProxyGID)` actually ran.
   `BPF_F_RDONLY` is not an escape hatch: it fails `EINVAL (22)` on a link pin
   on 5.15.
3. **`PinLinks` must default to `false`.** M1 - whether a pinned cgroup
   `bpf_link` prevents the kubelet from removing a pod cgroup - is not validated
   and cannot be validated without a real kubelet.
4. **Freeze `aksh_config` and `bypass_cidr4`, and only those two.**
   `BPF_MAP_FREEZE` succeeds on 5.15 and makes every later
   `BPF_MAP_UPDATE_ELEM` return `EPERM`, from the same fd, from a re-opened pin,
   and from another process, while the programs keep reading the map correctly.
   `bypass_cidr4` gets the same treatment for the same reason: it is a list of
   destinations that are *not* policed, so a proxy that could still write it
   after attach could grant itself `0.0.0.0/0` and turn capture off. The two
   destination maps must never be frozen: the programs write them on every
   connection.
5. **`aksh_config` is `struct aksh_cfg` in C.** Design 6.4.1 gives the struct and
   the map the same name; BTF cannot hold both under one name and `bpf2go`
   rejects it. The **map** name `aksh_config` is the externally significant one
   and is unchanged; only the C struct tag differs.

## Licensing

`aksh_capture.c` is GPL-2.0 and declares `char _license[] SEC("license") = "GPL"`,
which is required for BPF programs that may call GPL-only helpers. The two
headers in `include/` reproduce definitions from the Linux UAPI header
`<linux/bpf.h>` and from libbpf, both of which are licensed
`GPL-2.0 WITH Linux-syscall-note` / `LGPL-2.1 OR BSD-2-Clause` precisely so that
they may be included by out-of-tree programs. The SPDX identifiers are on the
files.
