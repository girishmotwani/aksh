# Aksh — Design & Planning

This directory holds design notes, architecture decisions, and the implementation plan.

> **The design phase is complete and the MVP dataplane is implemented.** Phases 1–9 are merged
> to `main`: eBPF capture, TLS termination, the policy engine, credential brokering, audit and
> metrics, and a kind end-to-end harness. Feasibility was originally confirmed by a
> proof-of-concept study (see [`FEASIBILITY.md`](FEASIBILITY.md)); that throwaway PoC code
> is not part of this repository. Sidecar injection (FR2) is the one MVP
> requirement still unimplemented — see the root [`../README.md`](../README.md) for current
> status and limitations.
>
> The documents in [`design/`](design/) describe intended design. Where a design doc and the
> code disagree, the code is authoritative.

## Source of truth

Requirements are derived from the **Market Requirements Document (MRD):**
*"Aksh — Security Sidecar for Kagents"*.

## Functional requirements (summary)

| ID | Requirement | Priority |
| --- | ----------- | -------- |
| FR1 | Run as a sidecar / companion proxy for kagent workloads | MVP |
| FR2 | Be injected into the network path so all ingress/egress passes through it | MVP |
| FR3 | Store/manage OAuth/OIDC tokens outside the agent runtime | MVP |
| FR4 | Acquire, refresh, rotate, cache, and expire tokens | MVP |
| FR5 | Inject `Authorization` only after policy allows the request | MVP |
| FR6 | Support policy-as-code via Kubernetes CRDs | MVP |
| FR7 | Destination allow/deny by FQDN, URL path, method, MCP server/tool, API category | MVP |
| FR8 | Fail closed when token acquisition, policy lookup, or audit logging fails | MVP |
| FR9 | Emit structured audit logs (allow/deny, token provider, resource, policy version, identity) | MVP |
| FR10 | Entra ID first, with provider abstraction (Okta, Auth0, Keycloak, generic OIDC) | v1 |
| FR11 | Data-flow policies (e.g. "SharePoint-derived content cannot be sent to GitHub") | v1 |
| FR12 | Request-body inspection where TLS termination is enabled | v1 |
| FR13 | Approval hooks for high-risk actions | v1 |
| FR14 | MCP-aware controls: tool allowlists, parameter constraints, response redaction | v1 |
| FR15 | Integrate with mesh / CNI / Kubernetes NetworkPolicy to prevent bypass | v1 |

## Non-functional requirements (summary)

- **Security:** the agent must never receive raw long-lived credentials.
- **Availability:** graceful token refresh; fail closed for protected actions.
- **Performance:** define explicit P95/P99 latency budgets during MVP validation.
- **Operability:** expose Prometheus metrics and structured logs.
- **Compatibility:** Kubernetes-native deployment and kagent CRD/GitOps workflows.
- **Extensibility:** policy engine should support future OPA/CEL/Rego backends.
- **Compliance:** preserve audit evidence; support retention/export to SIEM.

## Reading order

Start with [`design/README.md`](design/README.md) for the reading order and scope boundary of
the low-level design. For what is actually implemented today, and the known gaps, see the root
[`../README.md`](../README.md).
