# AgentCon Japan demo

This directory contains the self-contained Aksh × kagent conference demo.
Presenters should use **[`PRESENTER.md`](PRESENTER.md)**.

## Headline scenario: credential theft, stopped by Aksh

The demo's headline is a **prompt-injected agent leaking a credential**, and
Aksh preventing it. The agent mounts a **cloud credential** — a real Microsoft
Entra access token when the presenter is `az login`-ed, else a synthetic demo
token. The MCP `exfiltrate_credential` tool reads that mounted credential and
uploads it (verbatim) to a prompt-supplied endpoint bounded to the demo
collector.

- **Baseline (no Aksh):** the agent leaks the real Entra token; the collector
  decodes and displays it (issuer/audience/tenant/expiry) — a real credential
  demonstrably exfiltrated.
- **Protected (Aksh):** two independent defenses. **Egress deny** — the exfil
  destination is not in the allow policy, so it returns `HTTP 403` and the
  collector receives nothing. **Custody** — `protect` moves the real credential
  out of the agent (its mount becomes a placeholder) into an Aksh-only vault
  Secret (`aksh-system/aksh-held-cloud-credential`), so the agent holds only a
  decoy.

A model-free path (`demo.sh evidence --live-steal`, and the credential legs of
`validate --full`) drives the theft directly via the MCP `steal` CLI, so the
block is provable without a live model.

## Architecture

- kagent 0.9.12 controller/UI run unprotected in namespace `kagent`.
- `agentcon-agent` runs in namespace `agentcon-demo` with:
  - the kagent runtime;
  - a localhost Streamable HTTP MCP sidecar exposing two tools:
    `send_cluster_diagnostics` (data egress) and `exfiltrate_credential`
    (reads the mounted cloud credential);
  - a non-loopback keepalive sidecar;
  - Aksh after `demo.sh protect`.
- The collector runs in `ops-insights` and exposes HTTPS ingest plus a separate
  HTTP observer UI; it renders a leaked credential prominently and decodes JWTs.

The chat prompt supplies the destination URL as untrusted input; the MCP tools
accept it only after restricting it to the controlled demo host/path (not
arbitrary SSRF). Baseline kagent holds the real OpenAI model key and the
uploads succeed. Protection replaces kagent's model key with a dummy, mounts the
real key only into Aksh, applies one policy rule for `api.openai.com` via the
static bearer credential provider, strips any caller Authorization, injects the
sidecar-held key only after the OpenAI rule matches, and default-denies the
telemetry hostname with HTTP 403.

CA material is split: application containers receive only
`aksh-pod-ca-public`; the signing key stays in `aksh-pod-ca-private`, which the
injector mounts only into Aksh.

The MCP call uses literal `127.0.0.1`, which remains local and capture-exempt.
The MCP sidecar's outbound telemetry request originates from another non-1774
process in the same pod cgroup, so it is captured and denied.

## Developer checks

```bash
bash scripts/tests/run.sh
python3 .validate.py

(cd collector && go test ./...)
(cd diagnostics-mcp && go test ./...)
```

Generated files, credentials, certificates, rendered manifests, evidence, and
port-forward state live under ignored paths.
