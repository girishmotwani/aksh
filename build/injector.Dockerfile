# Production aksh-injector image. Built and published by .github/workflows/release.yml
# and also consumed by the kind e2e harness (test/e2e/run.ps1).
#
# The injector is a plain admission webhook (no eBPF), so a CGO-free static
# build with no file capabilities is sufficient -- it runs as a non-root,
# read-only-rootfs, drop-ALL container (see deploy/30-deployment.yaml).
#
# Build context MUST be the repo root:
#   docker build -f build/injector.Dockerfile -t aksh-injector:latest .
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/aksh-injector ./cmd/aksh-injector

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/aksh-injector /usr/local/bin/aksh-injector
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/aksh-injector"]
