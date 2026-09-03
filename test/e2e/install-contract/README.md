# Install-contract e2e

Answers a question no other suite in this repo can: **does what we ship actually deploy?**

## Why this exists

Every other harness hand-rolls the workload-side prerequisites — the `AkshPolicy` CRD, the sidecar's
`Role`/`RoleBinding` — from its own fixtures. That makes them structurally blind to omissions in
`deploy/`: when the shipped manifests forget something, the harness quietly supplies it and the run
goes green. Two bugs reached `main` exactly that way:

- [#2](https://github.com/girishmotwani/aksh/issues/2) — `deploy/` shipped no RBAC for the sidecar,
  so a by-the-book install produced crash-looping pods.
- The `AkshPolicy` CRD existed **only** under `test/e2e/manifests/`, so `kubectl apply` of any policy
  failed with `no matches for kind "AkshPolicy"`.

A harness is written to make the test pass, so it provisions whatever the workload needs. That is
reasonable when testing the data plane, and fatal when the thing under test is the install itself.

## What it does

Installs **only** from `deploy/`, following `deploy/README.md` Option B (raw manifests) plus the
documented Step 3, and asserts:

| # | Assertion |
|---|-----------|
| 1 | The harness's own fixtures contain no aksh install artifacts |
| 2 | This harness never references the sibling fixture directory |
| 3 | `kubectl apply -f deploy/` succeeds and the CRD reaches `Established` |
| 4 | The injector reaches Ready and patches both webhook `caBundle`s |
| 5 | An `AkshPolicy` can be created — i.e. the shipped CRD is real |
| 6 | A plain pod in an opted-in namespace is injected **and reaches Ready** |
| 7 | **Negative:** with the `RoleBinding` removed, the pod does *not* become Ready and the diagnostic names the missing permission |

Assertion 6 is the one that matters. Reaching `Ready` means the sidecar obtained a policy snapshot,
which is only possible if the documented install is genuinely sufficient.

Assertion 7 is the first end-to-end exercise of the `Forbidden` path anywhere in the repo. Before it,
the operator-visible symptom in #2 had to be described by reading `run.go` rather than by observing a
run.

## What it deliberately does not do

**Traffic.** Allow/deny enforcement is covered by [`../run.ps1`](../run.ps1) and is not duplicated
here. A second copy of the data-plane test would add cost and flakiness without testing anything
about the install. This harness is about deployability; "the sidecar started and loaded policy" is
precisely the signal that breaks when the install contract is incomplete.

## The anti-rot guards

Assertions 1 and 2 are the reason this harness will still be honest in a year. Without them, the
first person debugging a red pipeline reaches for the fixture that makes it green, and the coverage
silently disappears — which is how the gap arose in the first place.

- **Fixtures are scanned** for `CustomResourceDefinition`, `akshpolicies` RBAC, and webhook
  configurations. Adding any of them here fails the run.
- **The script scans itself** for references to `test/e2e/manifests`. You cannot reach for the
  sibling fixtures without failing the test. The search needle is assembled at runtime so the check
  does not match its own source.

Both guards run **before anything is installed**, and both are mutation-tested: copying the CRD or
the policy-reader RBAC into `manifests/`, or adding a reference to the sibling directory, each turn
the run red.

## Running it

```powershell
./test/e2e/install-contract/run.ps1
```

Requires `kind`, `kubectl` and `docker`. Creates and destroys its own cluster.

| Flag | Effect |
|------|--------|
| `-Cluster <name>` | kind cluster name (default `aksh-install-contract`) |
| `-KeepUp` | leave the cluster running for debugging |
| `-SkipNegative` | skip assertion 7, which costs ~90s waiting out the first-snapshot timeout |

In CI it runs from [`../../../.github/workflows/install-contract.yml`](../../../.github/workflows/install-contract.yml)
on changes to `deploy/**`, `build/**`, or this directory. It is intentionally **not** a required
check on `main`: a required check that a paths filter skips leaves PRs pending forever. Treat a red
run as blocking by convention.
