# Pinned toolchain for regenerating the committed BPF object.
#
# internal/dataplane/bpf/README.md records a sha256 for akshbpf_bpfel.o and
# states that CI regenerates it and fails on any diff. This image is what makes
# that true: the .o is only byte-reproducible against a fixed clang, so the
# distro is pinned rather than tracking ubuntu:latest.
#
# Ubuntu 22.04 provides "Ubuntu clang version 14.0.0-1ubuntu1.1", which is the
# version that README pins. Do not bump this image without regenerating the
# object and updating the checksum table there -- a newer clang emits a
# different (still correct) object and the bpf-object CI job will fail.
#
# Go comes from the official image rather than apt so it matches go.mod. The Go
# version does not affect the .o -- clang produces it -- but bpf2go runs under
# Go and generates the accompanying bindings.
#
# Usage (mirrors the bpf-object job in .github/workflows/ci.yml):
#
#   docker build -f test/ci/bpfgen.Dockerfile -t aksh-bpfgen .
#   docker run --rm -v "$PWD:/src" -w /src/internal/dataplane/bpf aksh-bpfgen \
#     sh -c "go generate ./... && sha256sum akshbpf_bpfel.o"

FROM golang:1.26-bookworm AS go

FROM ubuntu:22.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        clang \
        llvm \
        ca-certificates \
        git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=go /usr/local/go /usr/local/go

# GOTOOLCHAIN=local stops the Go toolchain from silently downloading a version
# other than the one baked into this image, which would defeat the pinning.
ENV PATH=/usr/local/go/bin:/go/bin:$PATH \
    GOPATH=/go \
    GOTOOLCHAIN=local

# The repo is bind-mounted at /src owned by a different uid, which git
# otherwise refuses to operate on ("dubious ownership"). The CI job runs
# git diff inside this container to detect a regenerated object.
RUN git config --global --add safe.directory /src

WORKDIR /src
