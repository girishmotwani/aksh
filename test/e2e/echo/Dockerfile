# Echo upstream image for the kind e2e harness.
# Build context MUST be test/e2e/echo, and certs/ must be populated first by
# running ../certs/gencert.go (the run.ps1 driver does this automatically):
#   docker build -f test/e2e/echo/Dockerfile -t echo:e2e test/e2e/echo
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY main.go .
RUN go mod init echo && CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/echo .

FROM debian:bookworm-slim
COPY --from=build /out/echo /usr/local/bin/echo
COPY certs/server.crt /certs/server.crt
COPY certs/server.key /certs/server.key
ENTRYPOINT ["/usr/local/bin/echo"]
