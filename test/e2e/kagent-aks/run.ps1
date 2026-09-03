<#
.SYNOPSIS
  End-to-end harness: a real kagent AI agent running behind an aksh sidecar on a
  real AKS cluster.

.DESCRIPTION
  This is the AKS counterpart to test/e2e/kagent/run.ps1 (which runs the same
  scenario on kind). It answers the question the kind harness cannot: does aksh
  capture, terminate, police and audit a real, unmodified kagent agent's LLM
  egress on a production-shaped node -- one with per-pod cgroup namespaces, an
  enforcing AppArmor profile, and images pulled from a registry rather than
  side-loaded?

  What is real and what is faked is identical to the kind harness:
    REAL  kagent 0.9.12 controller, Agent CRD, agent container and its config
    REAL  the agent's verifying TLS handshake (no disableVerify anywhere)
    REAL  aksh: eBPF capture, TLS termination, policy match, audit -- on AKS
    FAKE  the LLM. mockllm serves a leaf for api.openai.com and CoreDNS maps
          that name to it, so the SNI aksh sees is the SNI it would see against
          real OpenAI, and the AkshPolicy under test is one a user would write.

  The three things a real node forces (and kind does not) are handled here:
    1. Images are built into the cluster's ACR and pulled (no `kind load`).
    2. The aksh sidecar runs AppArmor Unconfined and discovers its pod cgroup by
       inode (Case-B), because /proc/self/cgroup reads 0::/ under a cgroup
       namespace. See manifests/80-agent-shim.yaml.
    3. The agent is reached with `kubectl exec` into the in-pod driver (the AKS
       pod network is not routable from the host, and the shim has no Service),
       instead of `docker exec` into a kind node.

  As on kind, every assertion is verified in both directions: the harness also
  breaks the policy and re-drives the agent, and removes the bypass and
  re-drives the agent, and requires both to fail.

.PARAMETER SkipInfra
  Reuse an already-deployed cluster/ACR (resolve names from the Bicep
  deployment outputs). Use this to run against the shared soak cluster.

.PARAMETER SkipBuild
  Reuse already-pushed :$Tag images.

.PARAMETER SkipInstall
  Reuse an already-installed kagent/mockllm/CoreDNS rewrite. Iterate on aksh.

.PARAMETER KeepUp
  (default true on AKS) Never deletes the cluster. Pass -Cleanup to remove the
  kagent namespace and the CoreDNS rewrite when done.

.EXAMPLE
  # Provision a dedicated cluster, run everything, leave it up:
  pwsh test/e2e/kagent-aks/run.ps1

.EXAMPLE
  # Run against the already-running soak cluster (fast):
  pwsh test/e2e/kagent-aks/run.ps1 -SkipInfra -ResourceGroup aksh-soak-rg -DeploymentName aksh-soak
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string] $SubscriptionId,
  [string] $ResourceGroup  = "aksh-kagent-rg",
  [string] $Location       = "eastus2",
  [string] $NodeVmSize     = "Standard_E4s_v5",
  [string] $DeploymentName = "aksh-kagent",
  [string] $Tag            = "kagent-e2e",
  [switch] $SkipInfra,
  [switch] $SkipBuild,
  [switch] $SkipInstall,
  [switch] $Cleanup
)

$ErrorActionPreference = "Stop"
# Pinned so the harness behaves identically whichever way the host has this set:
# Invoke-Native is the single source of truth for native exit codes.
$PSNativeCommandUseErrorActionPreference = $false

$here    = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo    = (Resolve-Path (Join-Path $here "..\..\..")).Path
$kagent  = (Resolve-Path (Join-Path $here "..\kagent")).Path    # shared assets from the kind harness
$mani    = Join-Path $here "manifests"
$kcfg    = Join-Path $here ".kubeconfig"
$ns      = "kagent"
$env:KUBECONFIG = $kcfg

# Local, gitignored build scratch.
$certDir = Join-Path $here ".certs"        # pod CA (ca-cert.pem, ca-key.pem)
$mockCtx = Join-Path $here ".mockllm"      # mockllm build context (main.go, Dockerfile, certs/)
$rendered = Join-Path $here ".rendered"    # helm output

$script:Failures = New-Object System.Collections.Generic.List[string]

function Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Pass($m) { Write-Host "  [ok]   $m" -ForegroundColor DarkGreen }
function Fail($m) { $script:Failures.Add($m); Write-Host "  [FAIL] $m" -ForegroundColor Red }
function Check([bool]$ok, [string]$m) { if ($ok) { Pass $m } else { Fail $m } }

# Native commands do not honour $ErrorActionPreference, so without an explicit
# $LASTEXITCODE check a failed az/kubectl/docker call is silently ignored and the
# harness sails on to report success (#70).
function Invoke-Native([string]$What, [scriptblock]$Cmd) {
  & $Cmd
  if ($LASTEXITCODE -ne 0) { throw "$What failed (exit $LASTEXITCODE)" }
}

# The shim runs outside the controller's Service, so it is selected by label and
# addressed in-pod. Select on phase so a terminating pod from a previous rollout
# is never picked up -- that would silently drive the OLD config (false result).
function Get-ShimPod {
  (kubectl -n $ns get pods -l app=aksh-kagent-e2e `
     --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
}

# Ask the agent a question over A2A JSON-RPC and return the raw response. On AKS
# the pod network is not routable from the host and the shim has no Service, so
# the request is issued from INSIDE the pod via the uid-0 driver container, which
# curls the agent container over the pod's shared loopback (127.0.0.1 is exempt
# from capture, so the A2A request itself is never policed -- only the agent's
# outbound LLM call is). The body is piped on stdin (-d @-) to dodge quoting.
function Invoke-Agent([string]$id, [string]$text) {
  $payload = '{"jsonrpc":"2.0","id":"' + $id + '","method":"message/send","params":{"message":{"role":"user","messageId":"m' + $id + '","kind":"message","parts":[{"kind":"text","text":"' + $text + '"}]}}}'
  $pod = Get-ShimPod
  if (-not $pod) { return "" }
  ($payload | kubectl -n $ns exec -i $pod -c driver -- `
     curl -s -m 90 -X POST -H "Content-Type: application/json" -d '@-' "http://localhost:8080/" 2>&1) -join ''
}

# Positive-expectation probe. A fresh kagent pod needs ~15-45s after a rollout
# to become ready and re-establish its controller session, so a single shot
# right after a restart can race the agent's own startup. Retry until it answers
# or the deadline. The negative legs (D, E) deliberately do NOT use this: they
# assert the agent CANNOT serve and must not wait for a success that won't come.
function Invoke-AgentUntilOk([string]$id, [string]$text, [int]$TimeoutSec = 150) {
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  $n = 0; $last = ""
  do {
    $n++
    $last = Invoke-Agent "$id-$n" $text
    if ($last -match 'MOCK-LLM-OK') { return $last }
    Start-Sleep -Seconds 6
  } while ((Get-Date) -lt $deadline)
  return $last
}

function Wait-Rollout([string]$deploy) {
  Invoke-Native "rollout $deploy" { kubectl -n $ns rollout status deployment $deploy --timeout=240s }
}

# Patch the net ConfigMap and restart the shim so the new value is picked up.
function Set-NetConfig([string]$key, [string]$value) {
  $f = Join-Path ([IO.Path]::GetTempPath()) "aksh-net-patch.json"
  [IO.File]::WriteAllText($f, (@{ data = @{ $key = $value } } | ConvertTo-Json -Compress))
  Invoke-Native "patch configmap" { kubectl -n $ns patch configmap aksh-kagent-net --type=merge --patch-file $f }
  Invoke-Native "restart shim"    { kubectl -n $ns rollout restart deployment aksh-agent-shim }
  Wait-Rollout "aksh-agent-shim"
  Start-Sleep -Seconds 15
}

# Apply a manifest with ${ACR}/${TAG} substituted and imagePullPolicy: Never
# rewritten to IfNotPresent (there is nothing to side-load into on AKS).
function Apply-Templated($file) {
  $t = (Get-Content $file -Raw) `
    -replace '\$\{ACR\}', $acrServer `
    -replace '\$\{TAG\}', $Tag `
    -replace 'imagePullPolicy:\s*Never', 'imagePullPolicy: IfNotPresent' `
    -replace 'image:\s*mockllm:e2e', "image: $acrServer/mockllm:$Tag"
  $t | kubectl apply -f -
  if ($LASTEXITCODE -ne 0) { throw "apply failed: $file" }
}

try {
  Invoke-Native "az account set" { az account set --subscription $SubscriptionId }

  # ------------------------------------------------------------ infra (Bicep)
  if (-not $SkipInfra) {
    Step "Deploying infra (ACR + AKS) via Bicep"
    Invoke-Native "az group create" { az group create -n $ResourceGroup -l $Location -o none }
    Invoke-Native "az deployment group create" {
      az deployment group create -g $ResourceGroup --name $DeploymentName `
        --template-file (Join-Path $here "infra\main.bicep") `
        --parameters location=$Location nodeVmSize=$NodeVmSize -o none
    }
  }

  Step "Resolving cluster / ACR names from the '$DeploymentName' deployment"
  $dep = az deployment group show -g $ResourceGroup -n $DeploymentName --query properties.outputs -o json 2>$null | ConvertFrom-Json
  if (-not $dep) { throw "No '$DeploymentName' deployment outputs in $ResourceGroup. Run without -SkipInfra first." }
  $acrName   = $dep.acrName.value
  $acrServer = $dep.acrLoginServer.value
  $aksName   = $dep.aksName.value
  Write-Host "  ACR=$acrServer  AKS=$aksName"

  # ------------------------------------------------------ build images -> ACR
  if (-not $SkipBuild) {
    Step "Building aksh-proxy:$Tag into ACR ($acrName)"
    Invoke-Native "acr build aksh-proxy" {
      az acr build --registry $acrName --image "aksh-proxy:$Tag" --file (Join-Path $repo "build\proxy.Dockerfile") $repo -o none
    }

    Step "Generating mockllm serving cert (leaf CN/SAN = api.openai.com) and building mockllm:$Tag"
    # Assemble a self-contained build context so nothing is written into the
    # sibling kind harness. gencert.go issues a CA + a leaf whose CN/SAN is the
    # real provider hostname, so aksh sees the production SNI.
    Remove-Item -Recurse -Force $mockCtx -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force "$mockCtx\certs" | Out-Null
    Copy-Item "$kagent\mockllm\main.go"    "$mockCtx\main.go"
    Copy-Item "$kagent\mockllm\Dockerfile" "$mockCtx\Dockerfile"
    Invoke-Native "gencert" {
      docker run --rm -v "${repo}/test/e2e/certs:/src:ro" -v "${mockCtx}/certs:/out" -w /gen `
        -e OUT_DIR=/out -e LEAF_NAMES=api.openai.com golang:1.26-bookworm `
        sh -c "mkdir -p /gen && cp /src/gencert.go /gen/ && cd /gen && go run gencert.go"
    }
    Invoke-Native "acr build mockllm" {
      az acr build --registry $acrName --image "mockllm:$Tag" $mockCtx -o none
    }
  }

  # ------------------------------------------------------------- kubeconfig
  Step "Fetching kubeconfig -> $kcfg"
  Invoke-Native "az aks get-credentials" {
    az aks get-credentials -g $ResourceGroup -n $aksName --file $kcfg --overwrite-existing --only-show-errors
  }

  # --------------------------------------------------------- install kagent
  if (-not $SkipInstall) {
    $kagentVersion = "0.9.12"   # 0.10.x is a breaking rearchitecture; pinned on purpose.
    Remove-Item -Recurse -Force $rendered -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force $rendered | Out-Null

    Step "Rendering kagent $kagentVersion charts (helm runs in a container)"
    Invoke-Native "helm template kagent-crds" {
      docker run --rm -v "${kagent}:/work" -w /work alpine/helm:3.16.3 `
        template kagent-crds oci://ghcr.io/kagent-dev/kagent/helm/kagent-crds --version $kagentVersion --namespace $ns |
        Out-File -Encoding utf8 "$rendered\crds.yaml"
    }
    Invoke-Native "helm template kagent" {
      docker run --rm -v "${kagent}:/work" -w /work alpine/helm:3.16.3 `
        template kagent oci://ghcr.io/kagent-dev/kagent/helm/kagent --version $kagentVersion `
        --namespace $ns --values /work/values-minimal.yaml |
        Out-File -Encoding utf8 "$rendered\kagent.yaml"
    }

    Step "Installing kagent"
    Invoke-Native "create namespace" { kubectl create namespace $ns --dry-run=client -o yaml | kubectl apply -f - }
    # Server-side apply: kagent's Agent/SandboxAgent CRDs exceed the 262144-byte
    # last-applied-configuration annotation limit client-side apply would use.
    Invoke-Native "apply kagent CRDs" { kubectl apply --server-side --force-conflicts -f "$rendered\crds.yaml" }
    kubectl -n $ns create secret generic kagent-openai `
      --from-literal=OPENAI_API_KEY=sk-mock-not-a-real-key `
      --dry-run=client -o yaml | kubectl apply -f - | Out-Null
    Invoke-Native "apply kagent" { kubectl apply -f "$rendered\kagent.yaml" }
    Wait-Rollout "kagent-controller"

    Step "Deploying the mock LLM"
    kubectl -n $ns create secret generic mockllm-ca `
      --from-file=ca.crt="$mockCtx\certs\ca.crt" --dry-run=client -o yaml |
      kubectl apply -f - | Out-Null
    Apply-Templated (Join-Path $kagent "manifests\10-mockllm.yaml")
    Wait-Rollout "mockllm"

    Step "Pointing api.openai.com at the mock via the AKS coredns-custom ConfigMap"
    # AKS owns and periodically reconciles the `coredns` ConfigMap, so it must
    # NOT be overwritten (the kind harness does that; here it would be reverted).
    # The supported extension point is `coredns-custom`: entries ending .override
    # are imported into the default server block, which is exactly where a
    # rewrite belongs. See https://learn.microsoft.com/azure/aks/coredns-custom
    $override = "rewrite name exact api.openai.com mockllm.$ns.svc.cluster.local"
    kubectl -n kube-system create configmap coredns-custom `
      --from-literal=openai.override=$override `
      --dry-run=client -o yaml | kubectl apply -f - | Out-Null
    Invoke-Native "restart coredns" { kubectl -n kube-system rollout restart deployment coredns }
    Invoke-Native "coredns rollout" { kubectl -n kube-system rollout status deployment coredns --timeout=180s }
  }

  # --------------------------------------------------------------- pod CA
  # Pre-seeded rather than generated by the proxy at run time: the agent's trust
  # anchor is a plain file path in its config, so the CA must exist before the
  # agent container starts. See test/e2e/kagent/certs/genca.go.
  Step "Generating the aksh pod CA"
  Remove-Item -Recurse -Force $certDir -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Force $certDir | Out-Null
  Invoke-Native "genca" {
    docker run --rm -v "${kagent}/certs:/src:ro" -v "${certDir}:/out" -w /gen -e OUT_DIR=/out `
      golang:1.26-bookworm sh -c "mkdir -p /gen && cp /src/genca.go /gen/ && cd /gen && go run genca.go"
  }
  Invoke-Native "apply AkshPolicy CRD" { kubectl apply -f "$repo\deploy\05-crd.yaml" }
  kubectl -n $ns create secret generic aksh-pod-ca `
    --from-file=ca-cert.pem="$certDir\ca-cert.pem" `
    --from-file=ca-key.pem="$certDir\ca-key.pem" `
    --dry-run=client -o yaml | kubectl apply -f - | Out-Null

  # ------------------------------------------------------- cluster-assigned
  # ClusterIPs are cluster-assigned, so they are read live. The bypass is a
  # single /32 for the kagent controller: bypassing the whole Service CIDR would
  # also bypass the mock LLM and quietly gut the test.
  Step "Reading cluster-assigned addresses"
  $dns  = (kubectl -n kube-system get svc kube-dns          -o jsonpath='{.spec.clusterIP}')
  $ctrl = (kubectl -n $ns          get svc kagent-controller -o jsonpath='{.spec.clusterIP}')
  $up   = (kubectl -n $ns          get svc mockllm           -o jsonpath='{.spec.clusterIP}')
  if (-not $dns -or -not $ctrl -or -not $up) { throw "could not read kube-dns/kagent-controller/mockllm ClusterIPs" }
  Write-Host "  dns=$dns controller=$ctrl upstream=$up"
  kubectl -n $ns create configmap aksh-kagent-net `
    --from-literal=dnsServer="${dns}:53" `
    --from-literal=bypassCIDRs="$ctrl/32" `
    --from-literal=upstreamIP="$up" `
    --dry-run=client -o yaml | kubectl apply -f - | Out-Null

  # ------------------------------------------------------------- manifests
  Step "Applying RBAC, policy, model config and the Agent CR"
  foreach ($m in @("40-rbac.yaml", "50-policy.yaml", "60-modelconfig-aksh.yaml", "70-agent-aksh.yaml")) {
    Invoke-Native "apply $m" { kubectl apply -f (Join-Path "$kagent\manifests" $m) }
  }
  # The controller must render Secret aksh-agent from the Agent CR before the
  # shim can mount it.
  $deadline = (Get-Date).AddSeconds(120)
  while ((Get-Date) -lt $deadline) {
    if ((kubectl -n $ns get secret aksh-agent --ignore-not-found -o name)) { break }
    Start-Sleep -Seconds 3
  }
  Check ([bool](kubectl -n $ns get secret aksh-agent --ignore-not-found -o name)) `
        "kagent controller generated Secret/aksh-agent from the Agent CR"

  Step "Applying the aksh + agent shim (AKS)"
  Apply-Templated (Join-Path $mani "80-agent-shim.yaml")
  Wait-Rollout "aksh-agent-shim"
  Start-Sleep -Seconds 15

  $pod = Get-ShimPod
  if (-not $pod) { throw "no Running shim pod" }
  Write-Host "  shim pod = $pod"

  # ============================================================== assertions

  Step "A. The agent works through aksh"
  $r = Invoke-AgentUntilOk "1" "Say the magic word."
  Check ($r -match 'MOCK-LLM-OK') "agent answered over A2A with the mock LLM's reply"

  Step "B. The agent's own LLM call was captured, policed and audited"
  $logs = (kubectl -n $ns logs $pod -c aksh --tail=1000) -join "`n"
  # The agent's call is a POST to /v1/chat/completions; the driver's keepalive
  # traffic is GET /. Matching the POST proves the AGENT's egress went through
  # aksh, not merely that aksh was running.
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
  # a policy that was never consulted. These two steps make them load-bearing.

  Step "D. NEGATIVE: breaking the policy must break the agent"
  $f = Join-Path ([IO.Path]::GetTempPath()) "aksh-pol-patch.json"
  [IO.File]::WriteAllText($f, '{"spec":{"egress":{"rules":[{"name":"allow-openai","to":{"host":"nowhere.invalid"},"effect":"Allow"}]}}}')
  Invoke-Native "patch policy" { kubectl -n $ns patch akshpolicy allow-openai --type=merge --patch-file $f }
  Start-Sleep -Seconds 20
  $r = Invoke-Agent "2" "Say the magic word."
  Check (-not ($r -match 'MOCK-LLM-OK')) "agent could NOT reach its model once the policy stopped matching"
  $logs = (kubectl -n $ns logs $pod -c aksh --tail=300) -join "`n"
  $denied = $logs -split "`n" | Where-Object { $_ -match '/v1/chat/completions' } | Select-Object -Last 1
  Check ($denied -match '"disposition":"deny"') "  ... and the LLM call was audited as a deny"
  Invoke-Native "restore policy" { kubectl apply -f (Join-Path "$kagent\manifests" "50-policy.yaml") }
  Start-Sleep -Seconds 20

  Step "E. NEGATIVE: removing the bypass must break the agent (issue #80)"
  # 192.0.2.0/32 is TEST-NET-1: a syntactically valid bypass that covers
  # nothing, isolating the bypass from 'is a bypass configured at all'.
  Set-NetConfig "bypassCIDRs" "192.0.2.0/32"
  $r = Invoke-Agent "3" "Say the magic word."
  Check (-not ($r -match 'MOCK-LLM-OK')) "agent could NOT serve once its control-plane traffic was captured"

  Step "F. Restoring the bypass must make the agent work again"
  Set-NetConfig "bypassCIDRs" "$ctrl/32"
  $r = Invoke-AgentUntilOk "4" "Say the magic word."
  Check ($r -match 'MOCK-LLM-OK') "agent recovered once the control-plane prefix was bypassed again"
}
catch {
  Fail "harness error: $($_.Exception.Message)"
  Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
}
finally {
  if ($Cleanup) {
    Step "Cleaning up (namespace + CoreDNS rewrite; the cluster is left intact)"
    kubectl delete namespace $ns --ignore-not-found --wait=false | Out-Null
    kubectl -n kube-system delete configmap coredns-custom --ignore-not-found | Out-Null
    kubectl -n kube-system rollout restart deployment coredns 2>$null | Out-Null
  } else {
    Write-Host "`n==> Cluster left intact. Re-run with -SkipInfra -SkipBuild -SkipInstall to re-drive," -ForegroundColor Yellow
    Write-Host "    or pass -Cleanup to remove the kagent namespace and the CoreDNS rewrite." -ForegroundColor Yellow
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
