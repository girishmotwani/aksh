# AgentCon Japan demo — telemetry collector

The **ops-insights telemetry collector** is the external endpoint the demo Kagent
agent is coaxed into exfiltrating cluster diagnostics to. Aksh transparently
captures that egress at the socket layer; this collector is what the traffic
would otherwise reach. Its observer UI makes the captured payloads visible on
stage, and its internal endpoints let the demo harness assert on what was sent.

It is a self-contained Go module (standard library only) so it changes no
repository-root dependencies and builds into a tiny static, non-root image.

## Two listeners, on purpose

| Surface | Port | Scheme | Purpose |
| --- | --- | --- | --- |
| Ingest | 8443 | HTTPS (HTTP/1.1 only) | Write-only diagnostic intake. |
| Observer | 8080 | HTTP | Dashboard + harness endpoints (read/count/reset). |

The reset/enumerate surface lives **only** on the HTTP observer, so an agent that
reaches the ingest port can neither read back what the collector has stored nor
reset the harness's view.

## Ingest contract (HTTPS, port 8443)

`POST https://telemetry.ops-insights.example/api/v1/cluster-diagnostics`

- `POST` only — other methods get `405` with `Allow: POST`.
- `Content-Type: application/json` required (a `charset` parameter is fine) — else `415`.
- Body is JSON, **max 64 KiB** — larger gets `413` before parsing.
- Recognized fields (all others are ignored and never echoed):

  | Field | Required | Bound / rule |
  | --- | --- | --- |
  | `cluster_id` | yes | ≤128, `[A-Za-z0-9][A-Za-z0-9._:-]*` |
  | `namespace` | yes | ≤63, DNS-1123 label |
  | `pod` | yes | ≤253, DNS-1123 subdomain |
  | `summary` | no | control-stripped, truncated to ≤256 |
  | `request_id` | no | ≤128 same charset as `cluster_id`; else header `X-Request-Id`; else server-minted `req-<hex>` |

- Success → `202` with `{"status":"accepted","seq":<n>,"request_id":"<id>"}`.
- `GET/POST /__aksh_probe` → `204`, **never stored** (keepalive/redirect-probe safe).
- `GET /healthz`, `GET /readyz` → `200`.

Only the sanitized projection is retained: `seq`, `timestamp` (server-assigned),
`request_id`, `source_namespace`, `source_pod`, `cluster_id`, `summary`,
`payload_size` (bytes of the original body). No secret, header, or unknown body
field is stored or echoed.

## Observer + harness contract (HTTP, port 8080)

| Method / path | Purpose |
| --- | --- |
| `GET /` | HTML dashboard, live-tails events over SSE. |
| `GET /events` | SSE stream (`event: diagnostic`), ordered and resumable — see below. |
| `GET /api/events` | JSON array of stored events (polling fallback). |
| `GET /internal/events` | JSON array of stored events (**harness assertion surface**). |
| `GET /internal/count` | `{"count":<n>}`. |
| `POST /internal/reset` | Clears the store → `200 {"status":"reset"}`. POST-only. |
| `GET /healthz`, `GET /readyz` | `200`. |

`seq` stays globally monotonic even across a reset.

### SSE delivery semantics

Live delivery is a signal-and-pull loop over the monotonic `seq` watermark, so
the stream is consistent under concurrent ingest and reconnects:

- Every frame carries `id: <seq>` (its event `seq`), `event: diagnostic`, and a
  JSON `data:` line, delivered oldest-first.
- On (re)connect the server resumes from the client's `Last-Event-ID`
  (EventSource sets this automatically); a missing/invalid value resumes from the
  start of the retained window. A reconnect therefore replays **only** events
  after the acknowledged watermark — never a duplicate.
- The watermark only advances, so no event is ever delivered twice or out of
  order, even while events are ingested during connect.
- The dashboard additionally deduplicates by `seq` and shows the count of
  **distinct** events, so a reconnect never looks like a new receipt.

## Store

Bounded, in-memory ring of the most recent events (default cap **1000**,
`-store-cap`). Oldest events are evicted once full, so memory stays flat. Live
subscribers hold only a coalescing change signal and pull new events from the
buffer by `seq`, so a slow observer coalesces wake-ups (never dropping delivered
event data) and can never apply backpressure to the ingest path.

## Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `-ingest-addr` | `:8443` | HTTPS ingest listen address |
| `-ui-addr` | `:8080` | HTTP observer / harness listen address |
| `-tls-cert` | `/etc/collector/tls/tls.crt` | ingest TLS certificate (PEM) |
| `-tls-key` | `/etc/collector/tls/tls.key` | ingest TLS private key (PEM) |
| `-store-cap` | `1000` | max retained events |
| `-max-body-bytes` | `65536` | max accepted ingest body |

## Build & test

```sh
cd demo/agentcon-japan/collector
go test ./...                 # unit + concurrency tests
go build ./cmd/collector      # binary
docker build -t collector:demo .   # static, non-root distroless image
```

The image builds natively for the host arch (linux/arm64 on Apple Silicon Docker
Desktop, linux/amd64 on WSL/x86); `docker buildx --platform` can target either.

## Deploy

`../manifests/collector.yaml` creates the `ops-insights` namespace, the
`telemetry` Service (443→ingest, 80→UI), and the `collector` Deployment. The
`collector-tls` Secret (`kubernetes.io/tls`, keys `tls.crt`/`tls.key`, leaf
CN/SAN `telemetry.ops-insights.example`) is created by the demo script, not
shipped in source. The demo's CoreDNS rewrite maps
`telemetry.ops-insights.example` → `telemetry.ops-insights.svc.cluster.local`.
