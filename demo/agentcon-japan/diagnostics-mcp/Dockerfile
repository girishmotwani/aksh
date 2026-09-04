# Multi-arch image for the AgentCon Japan diagnostics MCP workstream.
#
# Build (both target platforms, standard Docker buildx):
#   docker buildx build \
#     --platform linux/amd64,linux/arm64 \
#     -t aksh-diagnostics-mcp:demo \
#     demo/agentcon-japan/diagnostics-mcp
#
# The build context MUST be this directory (it holds the self-contained module).
#
# The final image is FROM scratch and runs as an explicit, NON-1774 numeric UID.
# 1774 is the aksh proxy's own uid, which aksh excludes from capture; this
# workload must run as a DIFFERENT uid so its telemetry egress IS captured,
# policed and audited by the sidecar. Any uid != 1774 satisfies the contract;
# 10001 is chosen here and may be overridden by the manifest's runAsUser.

FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src

# Copy the module. There are no third-party dependencies (stdlib only), so there
# is nothing to download and the build is hermetic and reproducible.
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w" -o /out/diagnostics-mcp ./cmd/diagnostics-mcp

# Non-root, non-1774 runtime. scratch has no system CA store on purpose: this
# client trusts ONLY the operator-mounted combined CA bundle, never system roots.
FROM scratch
COPY --from=build /out/diagnostics-mcp /usr/local/bin/diagnostics-mcp

# Explicit non-1774 UID:GID so aksh captures this container's egress.
USER 10001:10001

EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/diagnostics-mcp"]
# Default mode is the MCP server; the probe sidecar overrides args with ["probe"].
CMD ["serve"]
