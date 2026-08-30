# Production aksh-proxy image. Built and published by .github/workflows/release.yml
# and also consumed by the kind e2e harness (test/e2e/run.ps1).
#
# The eBPF objects are committed (bpf2go: internal/dataplane/bpf/akshbpf_bpfel.o
# is embedded into the Go binary via go:embed), so a plain golang builder with
# CGO_ENABLED=0 is sufficient -- no clang/llvm needed at image-build time.
#
# Build context MUST be the repo root:
#   docker build -f build/proxy.Dockerfile -t aksh-proxy:latest .
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/aksh-proxy ./cmd/aksh-proxy
# Assert the artefact is actually cgo-free rather than trusting the flag above.
# DropPrivileges drops uid/gid and supplementary groups with
# syscall.AllThreadsSyscall, the only call that applies a credential change to
# every OS thread. The Go runtime refuses it in a cgo-linked binary and returns
# ENOTSUP, because it cannot stop threads created by C code. Nothing crashes:
# the proxy keeps running with some threads holding pre-drop credentials, which
# silently voids the privilege boundary (issue #66).
#
# Preflight gate P1 rejects such a binary at startup with E_CGO_ENABLED, but
# only once the image has been built, published and deployed. This check fails
# the build instead. It reads the setting the toolchain stamps into the binary,
# so it cannot be fooled by an edited build line, and unlike a //go:build cgo
# source guard it costs developers nothing: a source guard would break
# `go build ./...` and `go test ./...` on any machine with a C toolchain, since
# CGO_ENABLED defaults to 1 there.
RUN go version -m /out/aksh-proxy | grep -q 'CGO_ENABLED=0' \
 || (echo 'FATAL: aksh-proxy was linked with cgo; AllThreadsSyscall returns ENOTSUP and the privilege drop silently half-fails (issue #66)' >&2; exit 1)

FROM debian:bookworm-slim
# iproute2/procps/curl are for in-pod debugging and the workload driver; the
# proxy itself is a static binary and needs none of them.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl iproute2 procps libcap2-bin \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/aksh-proxy /usr/local/bin/aksh-proxy
RUN chmod 0755 /usr/local/bin/aksh-proxy
# File capabilities so the proxy can create/attach eBPF objects while running as a
# NON-root uid (1774). Kubernetes does not promote securityContext.capabilities.add
# into the ambient/effective set for a non-root runAsUser -- they only reach the
# bounding set -- so a non-root eBPF loader gets EPERM on BPF_MAP_CREATE. File caps
# (like setuid) grant permitted+effective on execve regardless of uid. This is the
# same mechanism Cilium/Pixie use to run their eBPF agents unprivileged.
RUN setcap 'cap_bpf,cap_net_admin,cap_sys_admin,cap_sys_resource,cap_perfmon,cap_net_raw,cap_setgid,cap_setuid,cap_setpcap+ep' /usr/local/bin/aksh-proxy
ENTRYPOINT ["/usr/local/bin/aksh-proxy"]
