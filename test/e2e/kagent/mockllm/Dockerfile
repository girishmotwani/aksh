# Mock OpenAI-compatible upstream for the kagent kind e2e harness.
# Build context MUST be test/e2e/kagent/mockllm, and certs/ must be populated
# first by running ../../certs/gencert.go with LEAF_NAMES=api.openai.com (the
# run.ps1 driver does this automatically):
#   docker build -f test/e2e/kagent/mockllm/Dockerfile -t mockllm:e2e test/e2e/kagent/mockllm
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY main.go .
RUN go mod init mockllm && CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/mockllm .

FROM debian:bookworm-slim
COPY --from=build /out/mockllm /usr/local/bin/mockllm
COPY certs/server.crt /certs/server.crt
COPY certs/server.key /certs/server.key
ENTRYPOINT ["/usr/local/bin/mockllm"]
