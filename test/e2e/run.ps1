<#
.SYNOPSIS
  aksh kind e2e harness: proves the production aksh-proxy allows a policy-matched
  egress flow (allowed.test -> HTTP 200 relayed to an upstream) and denies an
  unmatched one (blocked.test -> HTTP 403), on a real kind cluster, with eBPF
  cgroup capture running as a non-root uid.

.DESCRIPTION
  Steps (all verified by hand before being scripted here):
    1. Create a kind cluster.
    2. Generate throwaway TLS material (CA + allowed.test leaf) via certs/gencert.go.
    3. Build the production proxy image (build/proxy.Dockerfile) and the echo image.
    4. kind load both images (locally-built images load cleanly; multi-arch pulls do not).
    5. Create the upstream-ca configmap the proxy trusts via SSL_CERT_FILE.
    6. Apply manifests 00..50 in order.
    7. Wait for the pod, drive traffic (the workload container loops on its own),
       then scrape evidence from the NODE (in-pod scrapes would themselves be captured).
    8. ASSERT on that evidence and exit non-zero if any check fails (#70).

  This harness is a gate, not a report. Every setup command is exit-code checked
  and every piece of evidence is asserted. A run that does not print
  "E2E PASSED" and exit 0 is a failure, including the cases that used to pass
  silently: the proxy never starting, the pod never becoming Ready, and the
  workload reaching the upstream directly without traversing the proxy.

  Re-run safe: it deletes and recreates the cluster.

.PARAMETER Cluster   kind cluster name (default aksh-e2e).
.PARAMETER KeepUp    Leave the cluster running after capturing evidence.
#>
[CmdletBinding()]
param(
  [string]$Cluster = "aksh-e2e",
  [switch]$KeepUp
)
$ErrorActionPreference = "Stop"
# Pinned so the harness behaves identically whichever way the host has this set:
# Invoke-Native is the single source of truth for native exit codes.
$PSNativeCommandUseErrorActionPreference = $false
$repo = (Resolve-Path "$PSScriptRoot\..\..").Path
$node = "$Cluster-control-plane"
$ns   = "aksh-e2e"

$script:Failures = New-Object System.Collections.Generic.List[string]

function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Pass($m) { Write-Host "  [ok]   $m" -ForegroundColor DarkGreen }
function Fail($m) { $script:Failures.Add($m); Write-Host "  [FAIL] $m" -ForegroundColor Red }
function Check([bool]$ok, [string]$m) { if ($ok) { Pass $m } else { Fail $m } }

# Native commands do not honour $ErrorActionPreference in Windows PowerShell, so
# without an explicit $LASTEXITCODE check a failed kind/docker/kubectl call is
# silently ignored and the harness sails on to report success (#70).
function Invoke-Native([string]$What, [scriptblock]$Cmd) {
  & $Cmd
  if ($LASTEXITCODE -ne 0) { throw "$What failed (exit $LASTEXITCODE)" }
}

# The workload echoes the response body followed by curl's ' CODE=n VIA=ip'
# trailer. The allowed upstream's body ends in a newline, so for an ALLOW probe
# the trailer lands on the NEXT log line -- a naive per-line regex sees only the
# empty-body CODE=000 startup probes and concludes the allow flow is broken.
# Parse statefully: a probe label claims the next CODE=/VIA= trailer it meets.
function Get-Probes([string[]]$lines) {
  $out = New-Object System.Collections.Generic.List[psobject]
  $cur = $null
  foreach ($l in $lines) {
    if ($l -match '\[workload\]\s+(ALLOW|BLOCK)\s+->') { $cur = $Matches[1] }
    if ($cur -and $l -match 'CODE=(\d{3})\s+VIA=(\S*)') {
      $out.Add([pscustomobject]@{ Kind = $cur; Code = [int]$Matches[1]; Via = $Matches[2] })
      $cur = $null
    }
  }
  , $out.ToArray()
}

try {
  Step "Recreating kind cluster '$Cluster'"
  kind delete cluster --name $Cluster 2>&1 | Out-Null
  Invoke-Native "kind create cluster" { kind create cluster --name $Cluster }

  Step "Generating throwaway TLS material (CA + allowed.test leaf)"
  Invoke-Native "gencert" {
    docker run --rm -v "${repo}/test/e2e/certs:/out" -w /out -e OUT_DIR=/out `
      golang:1.26-bookworm sh -c "go run gencert.go"
  }
  # Copy-Item does not create intermediate directories and echo/certs/ is not in
  # the repo, so without this the harness aborts here on a clean checkout.
  New-Item -ItemType Directory -Force "$repo\test\e2e\echo\certs" | Out-Null
  Copy-Item "$repo\test\e2e\certs\server.crt" "$repo\test\e2e\echo\certs\server.crt" -Force
  Copy-Item "$repo\test\e2e\certs\server.key" "$repo\test\e2e\echo\certs\server.key" -Force

  Step "Building images (proxy + echo + injector)"
  Invoke-Native "docker build proxy" { docker build -f "$repo\build\proxy.Dockerfile" -t aksh-proxy:e2e $repo }
  Invoke-Native "docker build echo"  { docker build -f "$repo\test\e2e\echo\Dockerfile" -t echo:e2e "$repo\test\e2e\echo" }
  Invoke-Native "docker build injector" { docker build -f "$repo\build\injector.Dockerfile" -t aksh-injector:latest $repo }
  # The injector injects `aksh-proxy:latest` by default (cmd/aksh-injector proxy-image
  # default), so tag the e2e proxy image under that name too -- an injected sidecar
  # must reference an image that is actually side-loaded into the node.
  Invoke-Native "docker tag proxy:latest" { docker tag aksh-proxy:e2e aksh-proxy:latest }

  Step "Loading images into kind"
  Invoke-Native "kind load proxy"        { kind load docker-image aksh-proxy:e2e --name $Cluster }
  Invoke-Native "kind load proxy:latest" { kind load docker-image aksh-proxy:latest --name $Cluster }
  Invoke-Native "kind load echo"         { kind load docker-image echo:e2e --name $Cluster }
  Invoke-Native "kind load injector"     { kind load docker-image aksh-injector:latest --name $Cluster }

  Step "Deploying the aksh-injector via its Helm chart (deploy/helm/aksh-injector)"
  # Install the injector the same way an operator would (Step 1 of deploy/README.md).
  # The chart's default values already match the e2e image names
  # (aksh-injector:latest, aksh-proxy:latest), so no --set overrides are needed.
  # Render with the pinned alpine/helm image (no host helm required) and apply,
  # so this run also gates the chart templating + values wiring.
  #
  # --include-crds is required: `helm install` installs everything under crds/
  # automatically, but `helm template` omits it unless asked. Without the flag
  # this render-and-apply path silently ships no AkshPolicy CRD and every policy
  # apply below fails with `no matches for kind "AkshPolicy"`.
  $rendered = "$env:TEMP\aksh-injector-helm.yaml"
  Invoke-Native "helm template aksh-injector" {
    docker run --rm -v "${repo}:/src" -w /src alpine/helm:latest `
      template aksh deploy/helm/aksh-injector --include-crds > $rendered
  }
  Invoke-Native "kubectl apply injector (helm-rendered)" { kubectl apply -f $rendered }
  Invoke-Native "rollout status aksh-injector" { kubectl -n aksh-system rollout status deploy/aksh-injector --timeout=120s }

  Step "Asserting the caBundle reconciler patched both webhook configurations"
  # The manifests ship caBundle: "" + failurePolicy: Fail (fail closed); the
  # injector generates a self-signed CA at startup and patches it in. A non-empty
  # caBundle proves the reconciler ran and the RBAC to patch the configs is correct.
  $mutCA = "$(kubectl get mutatingwebhookconfiguration aksh-injector-mutating -o jsonpath='{.webhooks[0].clientConfig.caBundle}')"
  $valCA = "$(kubectl get validatingwebhookconfiguration aksh-injector-validating -o jsonpath='{.webhooks[0].clientConfig.caBundle}')"
  Check ($mutCA.Length -gt 0) "mutating webhook caBundle was populated at runtime (len=$($mutCA.Length))"
  Check ($valCA.Length -gt 0) "validating webhook caBundle was populated at runtime (len=$($valCA.Length))"

  Step "Opting a dedicated namespace in (aksh-inject: label aksh.dev/inject=enabled)"
  # Kept separate from the golden egress pod's namespace so the hand-written pod
  # below is never routed through the webhook (avoids API-defaulting idempotency
  # noise); this namespace exercises the injector's mutate/validate/opt-in contract.
  kubectl create namespace aksh-inject --dry-run=client -o yaml | kubectl apply -f - | Out-Null
  Invoke-Native "label ns aksh-inject" { kubectl label namespace aksh-inject aksh.dev/inject=enabled --overwrite }

  Step "Proving sidecar INJECTION on a plain opted-in pod"
  kubectl -n aksh-inject delete pod inject-target --ignore-not-found | Out-Null
  Invoke-Native "apply inject-target" { kubectl -n aksh-inject apply -f "$repo\test\e2e\manifests\60-inject-target.yaml" }
  $c0     = "$(kubectl -n aksh-inject get pod inject-target -o jsonpath='{.spec.containers[0].name}')"
  $c0img  = "$(kubectl -n aksh-inject get pod inject-target -o jsonpath='{.spec.containers[0].image}')"
  $ann    = "$(kubectl -n aksh-inject get pod inject-target -o jsonpath='{.metadata.annotations.aksh\.dev/injected}')"
  $hpid   = "$(kubectl -n aksh-inject get pod inject-target -o jsonpath='{.spec.hostPID}')"
  $fsg    = "$(kubectl -n aksh-inject get pod inject-target -o jsonpath='{.spec.securityContext.fsGroup}')"
  $names  = "$(kubectl -n aksh-inject get pod inject-target -o jsonpath='{.spec.containers[*].name}')"
  $uid    = "$(kubectl -n aksh-inject get pod inject-target -o jsonpath='{.spec.containers[0].securityContext.runAsUser}')"
  Write-Host "`n--- INJECTED pod inject-target (containers: $names) ---" -ForegroundColor Green
  Check ($c0 -eq 'aksh')              "first container is the aksh sidecar (got '$c0')"
  Check ($c0img -eq 'aksh-proxy:latest') "aksh sidecar uses the configured proxy image (got '$c0img')"
  Check ($uid -eq '1774')             "aksh sidecar runs as reserved uid 1774 (got '$uid')"
  Check ($ann -eq 'v1')               "pod carries annotation aksh.dev/injected=v1 (got '$ann')"
  Check ($hpid -eq 'true')            "pod sets hostPID=true (got '$hpid')"
  Check ($fsg -eq '1774')             "pod sets fsGroup=1774 (got '$fsg')"
  Check ($names -match '(^|\s)app(\s|$)') "the original app container is preserved (containers: $names)"

  Step "Proving INV-10 DENIAL of a tampering pod (app adds NET_ADMIN)"
  kubectl -n aksh-inject delete pod tamper-target --ignore-not-found | Out-Null
  $denyOut = (kubectl -n aksh-inject apply -f "$repo\test\e2e\manifests\61-tamper-target.yaml" 2>&1 | Out-String)
  Check ($LASTEXITCODE -ne 0) "validating webhook denied the tampering pod (kubectl apply failed as expected)"
  Check ($denyOut -match 'capab|denied|admission webhook') "denial came from the aksh validating webhook"
  Write-Host "  denial: $(($denyOut.Trim() -replace '\s+',' '))" -ForegroundColor DarkGray

  Step "Proving OPT-OUT: a plain pod in the unlabeled 'default' namespace is NOT injected"
  kubectl -n default delete pod inject-target --ignore-not-found | Out-Null
  Invoke-Native "apply optout pod" { kubectl -n default apply -f "$repo\test\e2e\manifests\60-inject-target.yaml" }
  $optNames = "$(kubectl -n default get pod inject-target -o jsonpath='{.spec.containers[*].name}')"
  Check ($optNames -notmatch 'aksh') "un-opted-in namespace pod was left untouched (containers: $optNames)"
  kubectl -n default delete pod inject-target --ignore-not-found | Out-Null
  kubectl -n aksh-inject delete pod inject-target,tamper-target --ignore-not-found | Out-Null

  Step "Asserting the chart shipped the AkshPolicy CRD (no fixture copy exists)"
  # The CRD arrives via the chart's crds/ directory above, not from a fixture in
  # this directory. If someone reintroduces a local copy to make a red run green,
  # the install-contract harness fails -- see test/e2e/install-contract.
  Invoke-Native "wait for CRD established" {
    kubectl wait --for=condition=Established crd/akshpolicies.aksh.dev --timeout=60s
  }

  Step "Applying manifests 00..40"
  foreach ($m in "00-namespace","20-rbac","30-policy","40-targets") {
    Invoke-Native "kubectl apply $m" { kubectl apply -f "$repo\test\e2e\manifests\$m.yaml" }
  }

  Step "Creating upstream-ca configmap (proxy trusts this via SSL_CERT_FILE)"
  kubectl -n $ns delete configmap upstream-ca --ignore-not-found | Out-Null
  Invoke-Native "create configmap upstream-ca" {
    kubectl -n $ns create configmap upstream-ca --from-file=upstream-ca.crt="$repo\test\e2e\certs\ca.crt"
  }

  Step "Waiting for echo upstream"
  Invoke-Native "rollout status echo-upstream" { kubectl -n $ns rollout status deploy/echo-upstream --timeout=120s }

  Step "Launching aksh pod (proxy + captured workload)"
  Invoke-Native "kubectl apply 50-aksh-pod" { kubectl -n $ns apply -f "$repo\test\e2e\manifests\50-aksh-pod.yaml" }
  # This is the check that used to be ignored: if the proxy cannot start (failed
  # preflight gate, missing bpffs, bad cgroup path) the pod never goes Ready and
  # the whole run is meaningless.
  Invoke-Native "pod/aksh-e2e Ready" { kubectl -n $ns wait --for=condition=Ready pod/aksh-e2e --timeout=150s }

  # The workload starts probing before the proxy finishes loading eBPF and
  # binding its listener, so the first probes legitimately report CODE=000. Wait
  # for the expected steady state rather than sampling the first lines that
  # appear -- but fail on timeout, so a proxy that never serves is still caught.
  Step "Waiting for the workload to reach steady state (ALLOW 200 via proxy, BLOCK 403)"
  $deadline = (Get-Date).AddSeconds(120)
  $settled = $false
  while ($true) {
    $probes = Get-Probes @(kubectl -n $ns logs aksh-e2e -c workload --tail=400 2>$null)
    $okAllow = @($probes | Where-Object { $_.Kind -eq 'ALLOW' -and $_.Code -eq 200 -and $_.Via -eq '127.0.0.1' })
    $okBlock = @($probes | Where-Object { $_.Kind -eq 'BLOCK' -and $_.Code -eq 403 })
    if ($okAllow.Count -ge 1 -and $okBlock.Count -ge 1) { $settled = $true; break }
    if ((Get-Date) -ge $deadline) { break }
    Start-Sleep 3
  }
  Check $settled "workload reached the expected steady state within 120s"
  # Let a few more probe cycles land so the assertions below judge steady-state
  # behaviour rather than the first success.
  Start-Sleep 8

  $probes = Get-Probes @(kubectl -n $ns logs aksh-e2e -c workload --tail=400 2>$null)
  $allow  = @($probes | Where-Object { $_.Kind -eq 'ALLOW' })
  $block  = @($probes | Where-Object { $_.Kind -eq 'BLOCK' })

  Write-Host "`n--- WORKLOAD (expect ALLOW CODE=200 VIA=127.0.0.1, BLOCK CODE=403) ---" -ForegroundColor Green
  $probes | Select-Object -Last 8 | ForEach-Object { Write-Host "  $($_.Kind) CODE=$($_.Code) VIA=$($_.Via)" }

  Step "Asserting workload evidence"
  Check ($allow.Count -ge 1) "workload produced at least one ALLOW probe result"
  Check ($block.Count -ge 1) "workload produced at least one BLOCK probe result"

  # Judge the tail: once settled, every probe must succeed. A flow that works
  # only intermittently is a failure, not a pass.
  $tailAllow = @($allow | Select-Object -Last 3)
  $tailBlock = @($block | Select-Object -Last 3)
  $badAllow  = @($tailAllow | Where-Object { $_.Code -ne 200 })
  Check ($badAllow.Count -eq 0) `
        "every ALLOW probe in steady state returned HTTP 200; bad=$($badAllow.Count)/$($tailAllow.Count)"
  # VIA is curl's remote_ip. 127.0.0.1 means the connection was redirected into
  # the local proxy listener; anything else means eBPF capture did not happen and
  # the workload talked to the upstream directly -- a silent loss of enforcement.
  $unproxied = @($tailAllow | Where-Object { $_.Code -eq 200 -and $_.Via -ne '127.0.0.1' })
  Check ($unproxied.Count -eq 0) `
        "every successful ALLOW went through the proxy (VIA=127.0.0.1); unproxied=$($unproxied.Count)"
  $badBlock = @($tailBlock | Where-Object { $_.Code -ne 403 })
  Check ($badBlock.Count -eq 0) `
        "every BLOCK probe in steady state was denied with HTTP 403; bad=$($badBlock.Count)/$($tailBlock.Count)"
  # A blocked host answering 200 is a policy bypass, the single worst outcome.
  Check (@($block | Where-Object { $_.Code -eq 200 }).Count -eq 0) `
        "BLOCK flow never returned HTTP 200 (no policy bypass)"

  Step "Asserting metrics"
  $pod = kubectl -n $ns get pod aksh-e2e -o jsonpath="{.status.podIP}"
  $metrics = @(docker exec $node sh -c "curl -s http://${pod}:15020/metrics" 2>$null)
  $decisions = @($metrics | Where-Object { $_ -match '^aksh_decisions_total\{' })
  Write-Host "`n--- METRICS (from node; in-pod scrape would be captured) ---" -ForegroundColor Green
  $decisions | ForEach-Object { Write-Host "  $_" }
  Check ($decisions.Count -ge 1) "control plane served aksh_decisions_total on :15020/metrics"
  Check (@($decisions | Where-Object { $_ -match 'disposition="allow"' }).Count -ge 1) `
        "aksh_decisions_total recorded an allow"
  Check (@($decisions | Where-Object { $_ -match 'disposition="deny"' }).Count -ge 1) `
        "aksh_decisions_total recorded a deny"

  Step "Asserting the upstream saw only the allowed host"
  $echo = @(kubectl -n $ns logs deploy/echo-upstream --tail=200)
  Write-Host "`n--- ECHO upstream (must show ONLY allowed.test) ---" -ForegroundColor Green
  $echo | Select-Object -Last 6 | ForEach-Object { Write-Host "  $_" }
  Check (@($echo | Where-Object { $_ -match 'allowed\.test' }).Count -ge 1) `
        "upstream received the allowed.test request"
  Check (@($echo | Where-Object { $_ -match 'blocked\.test' }).Count -eq 0) `
        "upstream never received blocked.test"

  Step "Asserting audit records"
  $recs = @()
  foreach ($line in @(kubectl -n $ns logs aksh-e2e -c aksh --tail=500)) {
    if ($line -match '"disposition"') {
      try { $recs += ($line | ConvertFrom-Json) } catch { }
    }
  }
  Write-Host "`n--- AUDIT (allow allowed.test / deny blocked.test) ---" -ForegroundColor Green
  $recs | Select-Object -Last 4 | ForEach-Object { Write-Host "  $($_ | ConvertTo-Json -Compress -Depth 6)" }
  Check ($recs.Count -ge 1) "proxy emitted parseable JSON audit records"
  Check (@($recs | Where-Object { $_.decision.disposition -eq 'allow' }).Count -ge 1) `
        "an allow decision was audited"
  Check (@($recs | Where-Object { $_.decision.disposition -eq 'deny' }).Count -ge 1) `
        "a deny decision was audited"
  # Attribution regression guard (#62): a record that cannot name the pod it came
  # from is not usable evidence.
  $unattributed = @($recs | Where-Object { -not $_.pod.name -or -not $_.pod.namespace })
  Check ($unattributed.Count -eq 0) `
        "every audit record carries pod name and namespace; unattributed=$($unattributed.Count)"
}
catch {
  Fail "harness error: $($_.Exception.Message)"
  Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed
}
finally {
  if ($script:Failures.Count -gt 0) {
    Write-Host "`n--- DIAGNOSTICS (collected because the run failed) ---" -ForegroundColor Yellow
    try {
      kubectl -n $ns get pods -o wide 2>&1 | ForEach-Object { Write-Host "  $_" }
      kubectl -n $ns describe pod aksh-e2e 2>&1 | Select-String -Pattern "State:|Reason:|Message:|Events:|Warning" |
        ForEach-Object { Write-Host "  $($_.Line.Trim())" }
      Write-Host "  --- aksh container (last 40) ---"
      kubectl -n $ns logs aksh-e2e -c aksh --tail=40 2>&1 | ForEach-Object { Write-Host "  $_" }
      Write-Host "  --- aksh container, previous instance (last 40) ---"
      kubectl -n $ns logs aksh-e2e -c aksh --previous --tail=40 2>&1 | ForEach-Object { Write-Host "  $_" }
      Write-Host "  --- aksh-injector (last 40) ---"
      kubectl -n aksh-system get pods -o wide 2>&1 | ForEach-Object { Write-Host "  $_" }
      kubectl -n aksh-system logs deploy/aksh-injector --tail=40 2>&1 | ForEach-Object { Write-Host "  $_" }
    } catch {
      Write-Host "  (diagnostics collection failed: $($_.Exception.Message))" -ForegroundColor DarkRed
    }
  }

  if (-not $KeepUp) {
    Step "Tearing down cluster '$Cluster' (pass -KeepUp to keep it)"
    kind delete cluster --name $Cluster 2>&1 | Out-Null
  }

  if ($script:Failures.Count -gt 0) {
    Write-Host "`nE2E FAILED - $($script:Failures.Count) check(s):" -ForegroundColor Red
    $script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
  }
  Write-Host "`nE2E PASSED - all checks green." -ForegroundColor Green
  exit 0
}