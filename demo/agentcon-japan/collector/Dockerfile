# AgentCon Japan demo — telemetry collector image.
#
# Build context MUST be this directory (it is a self-contained Go module that
# depends only on the standard library, so no repository-root files are needed):
#
#   docker build -t collector:demo demo/agentcon-japan/collector
#
# The build is native by default: `docker build` on Apple Silicon Docker Desktop
# produces a linux/arm64 image, and on WSL/x86 a linux/amd64 image, because
# TARGETARCH is supplied automatically from the build platform. buildx can also
# target the other arch explicitly, e.g.
#
#   docker buildx build --platform linux/amd64 -t collector:demo demo/agentcon-japan/collector
#
# The binary is statically linked (CGO disabled) so it runs on a distroless
# static base as a non-root user with no libc dependency.
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS build
ARG TARGETOS=linux
ARG TARGETARCH
WORKDIR /src

# Module metadata first for layer caching; there are no external dependencies to
# download, so this stays a single cheap layer.
COPY go.mod ./
COPY cmd/ ./cmd/
COPY internal/ ./internal/

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/collector ./cmd/collector

# Distroless static: no shell, no package manager, runs as nonroot (uid 65532).
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/collector /usr/local/bin/collector
USER nonroot:nonroot
# 8443: HTTPS diagnostic ingest. 8080: plain HTTP observer UI / harness.
EXPOSE 8443 8080
ENTRYPOINT ["/usr/local/bin/collector"]
