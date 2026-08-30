<#
.SYNOPSIS
  End-to-end harness: a real kagent AI agent running behind an aksh sidecar.

.DESCRIPTION
  The other harness (test/e2e/run.ps1) drives a synthetic curl loop. This one
  drives an actual kagent Agent: the agent is asked a question over A2A
  JSON-RPC, it calls its configured LLM over TLS, and that call is captured,
  terminated, matched against an AkshPolicy, relayed and audited by aksh.

  What is real and what is faked:
    REAL  kagent 0.9.12 controller, Agent CRD, agent container and its config
    REAL  the agent's verifying TLS handshake (no disableVerify anywhere)
    REAL  aksh: eBPF capture, TLS termination, policy match, audit
    FAKE  the LLM. mockllm serves a leaf for api.openai.com and CoreDNS maps
          that name to it, so the SNI aksh sees is the SNI it would see against
          real OpenAI, and the AkshPolicy under test is one a user would write.

  Every assertion is verified in both directions. Proving the agent works
  proves nothing on its own -- an aksh that captured nothing would also let it
  work -- so the harness also breaks the policy and re-drives the agent, and
  removes the bypass and re-drives the agent, and requires both to fail.

.PARAMETER Cluster
  kind cluster name. Created if absent.

.PARAMETER KeepUp
  Leave the cluster running on exit (for debugging).

.PARAMETER SkipInstall
  Reuse an already-installed kagent/mockllm. Use when iterating on aksh only.

.EXAMPLE
  pwsh test/e2e/kagent/run.ps1
#>
[CmdletBinding()]
param(
  [string]$Cluster = "aksh-kagent",
  [switch]$KeepUp,
  [switch]$SkipInstall
)
$ErrorActionPreference = "Stop"
# Pinned so the harness behaves identically whichever way the host has this
# set: Invoke-Native is the single source of truth for native exit codes.
$PSNativeCommandUseErrorActionPreference = $false

$repo = (Resolve-Path "$PSScriptRoot\..\..\..").Path
$here = $PSScriptRoot
$node = "$Cluster-control-plane"
$ctx  = "kind-$Cluster"
$ns   = "kagent"

$script:Failures = New-Object System.Collections.Generic.List[string]

function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Pass($m) { Write-Host "  [ok]   $m" -ForegroundColor DarkGreen }
function Fail($m) { $script:Failures.Add($m); Write-Host "  [FAIL] $m" -ForegroundColor Red }
function Check([bool]$ok, [string]$m) { if ($ok) { Pass $m } else { Fail $m } }

# Native commands do not honour $ErrorActionPreference, so without an explicit
# $LASTEXITCODE check a failed kind/docker/kubectl call is silently ignored and
# the harness sails on to report success (#70).
function Invoke-Native([string]$What, [scriptblock]$Cmd) {
  & $Cmd
  if ($LASTEXITCODE -ne 0) { throw "$What failed (exit $LASTEXITCODE)" }
}

# The shim runs outside the controller's Service, so the agent is addressed by
# pod IP. Select on phase so a terminating pod from a previous rollout is never
# picked up -- doing so silently drives the OLD configuration and produces a
# false negative.
#
# Note: do NOT wrap kubectl in a helper named "Kubectl". PowerShell resolves
# command names case-insensitively, so the body's `kubectl` binds to the
# function itself and the harness dies with "call depth overflow".
function Get-ShimIP {
  (kubectl --context $ctx -n $ns get pods -l app=aksh-kagent-e2e `
     --field-selector=status.phase=Running -o jsonpath='{.items[0].status.podIP}')
}

# Ask the agent a question over A2A JSON-RPC and return the raw response. Run
# from the node: the shim has no Service and the pod network is not routable
# from the host.
function Invoke-Agent([string]$ip, [string]$id, [string]$text) {
  $payload = "{`"jsonrpc`":`"2.0`",`"id`":`"$id`",`"method`":`"message/send`",`"params`":{`"message`":{`"role`":`"user`",`"messageId`":`"m$id`",`"kind`":`"message`",`"parts`":[{`"kind`":`"text`",`"text`":`"$text`"}]}}}"
  (docker exec $node curl -s -m 90 -X POST -H "Content-Type: application/json" -d $payload "http://${ip}:8080/" 2>&1) -join ''
}

function Wait-Rollout([string]$deploy) {
  Invoke-Native "rollout $deploy" { kubectl --context $ctx -n $ns rollout status deployment $deploy --timeout=240s }
}

# Patch the net ConfigMap and restart the shim so the new value is picked up.
function Set-NetConfig([string]$key, [string]$value) {
  $f = Join-Path ([IO.Path]::GetTempPath()) "aksh-net-patch.json"
  [IO.File]::WriteAllText($f, (@{ data = @{ $key = $value } } | ConvertTo-Json -Compress))
  Invoke-Native "patch configmap" { kubectl --context $ctx -n $ns patch configmap aksh-kagent-net --type=merge --patch-file $f }
  Invoke-Native "restart shim"    { kubectl --context $ctx -n $ns rollout restart deployment aksh-agent-shim }
  Wait-Rollout "aksh-agent-shim"
  Start-Sleep -Seconds 15
}

try {
  # ---------------------------------------------------------------- cluster
  Step "Ensuring kind cluster '$Cluster'"
  $existing = (kind get clusters 2>$null)
  if ($existing -notcontains $Cluster) {
    Invoke-Native "kind create" { kind create cluster --name $Cluster }
  } else {
    Write-Host "  (reusing existing cluster)"
  }

  if (-not $SkipInstall) {
    # kagent 0.10.x is a breaking rearchitecture; 0.9.12 is pinned on purpose.
    # The rendered manifests are build output and are not committed.
    $kagentVersion = "0.9.12"
    $rendered = Join-Path $here "rendered"
    New-Item -ItemType Directory -Force $rendered | Out-Null

    Step "Rendering kagent $kagentVersion charts (helm runs in a container; helm is not required on the host)"
    Invoke-Native "helm template kagent-crds" {
      docker run --rm -v "${here}:/work" -w /work alpine/helm:3.16.3 `
        template kagent-crds oci://ghcr.io/kagent-dev/kagent/helm/kagent-crds --version $kagentVersion --namespace $ns |
        Out-File -Encoding utf8 "$rendered\crds.yaml"
    }
    Invoke-Native "helm template kagent" {
      docker run --rm -v "${here}:/work" -w /work alpine/helm:3.16.3 `
        template kagent oci://ghcr.io/kagent-dev/kagent/helm/kagent --version $kagentVersion `
        --namespace $ns --values /work/values-minimal.yaml |
        Out-File -Encoding utf8 "$rendered\kagent.yaml"
    }

    Step "Installing kagent"
    Invoke-Native "create namespace" { kubectl --context $ctx create namespace $ns --dry-run=client -o yaml | kubectl --context $ctx apply -f - }
    # Server-side apply is required, not a preference: client-side apply stores
    # the whole object in a last-applied-configuration annotation, and kagent's
    # Agent/SandboxAgent CRDs are larger than the 262144-byte annotation limit.
    Invoke-Native "apply kagent CRDs" { kubectl --context $ctx apply --server-side --force-conflicts -f "$rendered\crds.yaml" }
    # The chart requires a provider secret to exist even though the ModelConfig
    # under test carries its own key and the mock ignores it entirely.
    kubectl --context $ctx -n $ns create secret generic kagent-openai `
      --from-literal=OPENAI_API_KEY=sk-mock-not-a-real-key `
      --dry-run=client -o yaml | kubectl --context $ctx apply -f - | Out-Null
    Invoke-Native "apply kagent" { kubectl --context $ctx apply -f "$rendered\kagent.yaml" }
    Wait-Rollout "kagent-controller"

    Step "Building the mock LLM"
    # gencert.go writes ca.crt/server.crt/server.key into OUT_DIR, which is
    # pointed straight at the mock's build context (its serving cert is baked
    # into the image). It is copied into a scratch dir rather than run in
    # test/e2e/certs so this harness never clobbers the other harness's certs.
    # LEAF_NAMES makes the leaf's CN and SAN the real provider hostname, so the
    # SNI aksh sees is the SNI it would see against real OpenAI.
    New-Item -ItemType Directory -Force "$here\mockllm\certs" | Out-Null
    Invoke-Native "gencert" {
      docker run --rm -v "${repo}/test/e2e/certs:/src:ro" -v "${here}/mockllm/certs:/out" -w /gen `
        -e OUT_DIR=/out -e LEAF_NAMES=api.openai.com golang:1.26-bookworm `
        sh -c "mkdir -p /gen && cp /src/gencert.go /gen/ && cd /gen && go run gencert.go"
    }
    Invoke-Native "docker build mockllm" { docker build -q -t mockllm:e2e "$here\mockllm" }
    Invoke-Native "kind load mockllm"    { kind load docker-image mockllm:e2e --name $Cluster }
    # aksh is the client on the upstream leg, so it must trust the mock's CA.
    # The shim mounts this secret and concatenates it onto the system bundle.
    kubectl --context $ctx -n $ns create secret generic mockllm-ca `
      --from-file=ca.crt="$here\mockllm\certs\ca.crt" --dry-run=client -o yaml |
      kubectl --context $ctx apply -f - | Out-Null
    Invoke-Native "apply mockllm" { kubectl --context $ctx apply -f "$here\manifests\10-mockllm.yaml" }
    Wait-Rollout "mockllm"

    Step "Pointing api.openai.com at the mock via CoreDNS"
    # The whole Corefile is rewritten from a literal here-string. Round-tripping
    # it through `kubectl get -o jsonpath` flattens the newlines and CoreDNS
    # then crash-loops on "Unexpected '}'".
    $corefile = @"
.:53 {
    errors
    health {
       lameduck 5s
    }
    ready
    rewrite name api.openai.com mockllm.$ns.svc.cluster.local
    kubernetes cluster.local in-addr.arpa ip6.arpa {
       pods insecure
       fallthrough in-addr.arpa ip6.arpa
       ttl 30
    }
    prometheus :9153
    forward . /etc/resolv.conf {
       max_concurrent 1000
    }
    cache 30
    loop
    reload
    loadbalance
}
"@
    $cf = Join-Path ([IO.Path]::GetTempPath()) "Corefile"
    [IO.File]::WriteAllText($cf, $corefile)
    kubectl --context $ctx -n kube-system create configmap coredns --from-file=Corefile=$cf `
      --dry-run=client -o yaml | kubectl --context $ctx apply -f - | Out-Null
    Invoke-Native "restart coredns" { kubectl --context $ctx -n kube-system rollout restart deployment coredns }
    Invoke-Native "coredns rollout" { kubectl --context $ctx -n kube-system rollout status deployment coredns --timeout=180s }
  }

  # ------------------------------------------------------------ aksh image
  Step "Building and loading aksh-proxy:e2e"
  Invoke-Native "docker build" { docker build -q -f "$repo\test\e2e\Dockerfile" -t aksh-proxy:e2e $repo }
  Invoke-Native "kind load"    { kind load docker-image aksh-proxy:e2e --name $Cluster }

  # --------------------------------------------------------------- pod CA
  # Pre-seeded rather than generated by the proxy at run time: the agent's
  # trust anchor is a plain file path in its config, so the CA must exist
  # before the agent container starts. See certs/genca.go.
  Step "Generating the aksh pod CA"
  Invoke-Native "genca" {
    docker run --rm -v "${here}/certs:/out" -w /out -e OUT_DIR=/out golang:1.26-bookworm sh -c "go run genca.go"
  }
  Invoke-Native "apply AkshPolicy CRD" { kubectl --context $ctx apply -f "$repo\test\e2e\manifests\10-crd.yaml" }
  kubectl --context $ctx -n $ns create secret generic aksh-pod-ca `
    --from-file=ca-cert.pem="$here\certs\ca-cert.pem" `
    --from-file=ca-key.pem="$here\certs\ca-key.pem" `
    --dry-run=client -o yaml | kubectl --context $ctx apply -f - | Out-Null

  # ------------------------------------------------------- cluster-assigned
  # These are assigned by the cluster, so they are read from it rather than
  # hard-coded. The bypass is a single /32 for the kagent controller: bypassing
  # the whole Service CIDR would also bypass the mock LLM and quietly gut the
  # test, since the traffic under test would stop being captured at all.
  Step "Reading cluster-assigned addresses"
  $dns  = (kubectl --context $ctx -n kube-system get svc kube-dns          -o jsonpath='{.spec.clusterIP}')
  $ctrl = (kubectl --context $ctx -n $ns          get svc kagent-controller -o jsonpath='{.spec.clusterIP}')
  $up   = (kubectl --context $ctx -n $ns          get svc mockllm           -o jsonpath='{.spec.clusterIP}')
  if (-not $dns -or -not $ctrl -or -not $up) { throw "could not read kube-dns/kagent-controller/mockllm ClusterIPs" }
  Write-Host "  dns=$dns controller=$ctrl upstream=$up"
  kubectl --context $ctx -n $ns create configmap aksh-kagent-net `
    --from-literal=dnsServer="${dns}:53" `
    --from-literal=bypassCIDRs="$ctrl/32" `
    --from-literal=upstreamIP="$up" `
    --dry-run=client -o yaml | kubectl --context $ctx apply -f - | Out-Null

  # ------------------------------------------------------------- manifests
  Step "Applying policy, model config, Agent and shim"
  foreach ($m in @("40-rbac.yaml", "50-policy.yaml", "60-modelconfig-aksh.yaml", "70-agent-aksh.yaml")) {
    Invoke-Native "apply $m" { kubectl --context $ctx apply -f (Join-Path "$here\manifests" $m) }
  }
  # The controller must render Secret aksh-agent from the Agent CR before the
  # shim can mount it.
  $deadline = (Get-Date).AddSeconds(120)
  while ((Get-Date) -lt $deadline) {
    if ((kubectl --context $ctx -n $ns get secret aksh-agent --ignore-not-found -o name)) { break }
    Start-Sleep -Seconds 3
  }
  Check ([bool](kubectl --context $ctx -n $ns get secret aksh-agent --ignore-not-found -o name)) `
        "kagent controller generated Secret/aksh-agent from the Agent CR"

  Invoke-Native "apply shim" { kubectl --context $ctx apply -f "$here\manifests\80-agent-shim.yaml" }
  Wait-Rollout "aksh-agent-shim"
  Start-Sleep -Seconds 15

  $ip = Get-ShimIP
  if (-not $ip) { throw "no Running shim pod" }
  Write-Host "  shim pod IP = $ip"

  # ============================================================== assertions

  Step "A. The agent works through aksh"
  $r = Invoke-Agent $ip "1" "Say the magic word."
  Check ($r -match 'MOCK-LLM-OK') "agent answered over A2A with the mock LLM's reply"

  Step "B. The agent's own LLM call was captured, policed and audited"
  $pod  = (kubectl --context $ctx -n $ns get pods -l app=aksh-kagent-e2e --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
  $logs = (kubectl --context $ctx -n $ns logs $pod -c aksh --tail=1000) -join "`n"
  # The agent's call is a POST to /v1/chat/completions; the driver container's
  # keepalive traffic is GET /. Matching the POST is what proves the AGENT's
  # egress went through aksh, not merely that aksh was running.
  $agentCall = $logs -split "`n" | Where-Object { $_ -match '/v1/chat/completions' } | Select-Object -Last 1
  Check ([bool]$agentCall) "an audit record exists for the agent's POST /v1/chat/completions"
  Check ($agentCall -match '"disposition":"allow"')          "  ... decision was allow"
  Check ($agentCall -match '"identity":"api.openai.com"')    "  ... identity was the real provider hostname"
  Check ($agentCall -match '"ref":"kagent/allow-openai')     "  ... attributed to the AkshPolicy under test"
  Check ($agentCall -match '"namespace":"kagent"')           "  ... carries pod attribution"

  Step "C. A host with no matching rule is denied"
  $blocked = $logs -split "`n" | Where-Object { $_ -match '"identity":"blocked.test"' } | Select-Object -Last 1
  Check ([bool]$blocked) "an audit record exists for the denied host"
  Check ($blocked -match '"disposition":"deny"')             "  ... decision was deny"
  Check ($blocked -match '"reason":"policy_no_match"')       "  ... denied for policy_no_match"

  # --------------------------------------------------------- negative tests
  # Everything above would still pass against an aksh that captured nothing and
  # a policy that was never consulted. These two steps are what make the
  # assertions load-bearing.

  Step "D. NEGATIVE: breaking the policy must break the agent"
  $f = Join-Path ([IO.Path]::GetTempPath()) "aksh-pol-patch.json"
  [IO.File]::WriteAllText($f, '{"spec":{"egress":{"rules":[{"name":"allow-openai","to":{"host":"nowhere.invalid"},"effect":"Allow"}]}}}')
  Invoke-Native "patch policy" { kubectl --context $ctx -n $ns patch akshpolicy allow-openai --type=merge --patch-file $f }
  Start-Sleep -Seconds 20
  $r = Invoke-Agent $ip "2" "Say the magic word."
  Check (-not ($r -match 'MOCK-LLM-OK')) "agent could NOT reach its model once the policy stopped matching"
  $logs = (kubectl --context $ctx -n $ns logs $pod -c aksh --tail=300) -join "`n"
  $denied = $logs -split "`n" | Where-Object { $_ -match '/v1/chat/completions' } | Select-Object -Last 1
  Check ($denied -match '"disposition":"deny"') "  ... and the LLM call was audited as a deny"
  Invoke-Native "restore policy" { kubectl --context $ctx apply -f "$here\manifests\50-policy.yaml" }
  Start-Sleep -Seconds 20

  Step "E. NEGATIVE: removing the bypass must break the agent (issue #80)"
  # 192.0.2.0/32 is TEST-NET-1: a syntactically valid bypass that covers
  # nothing, so this isolates the bypass from 'is a bypass configured at all'.
  Set-NetConfig "bypassCIDRs" "192.0.2.0/32"
  $ip = Get-ShimIP
  $r = Invoke-Agent $ip "3" "Say the magic word."
  Check (-not ($r -match 'MOCK-LLM-OK')) "agent could NOT serve once its control-plane traffic was captured"

  Step "F. Restoring the bypass must make the agent work again"
  Set-NetConfig "bypassCIDRs" "$ctrl/32"
  $ip = Get-ShimIP
  $r = Invoke-Agent $ip "4" "Say the magic word."
  Check ($r -match 'MOCK-LLM-OK') "agent recovered once the control-plane prefix was bypassed again"
}
catch {
  Fail "harness error: $($_.Exception.Message)"
  Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
}
finally {
  if (-not $KeepUp) {
    Step "Tearing down"
    kind delete cluster --name $Cluster | Out-Null
  } else {
    Write-Host "==> Cluster '$Cluster' left running (-KeepUp)" -ForegroundColor Yellow
  }
}

Write-Host ""
if ($script:Failures.Count -gt 0) {
  Write-Host "FAILED ($($script:Failures.Count)):" -ForegroundColor Red
  $script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
  exit 1
}
Write-Host "ALL CHECKS PASSED" -ForegroundColor Green
exit 0
