<#
.SYNOPSIS
  Repeatable AKS soak / performance harness for the aksh egress proxy.

.DESCRIPTION
  Deploys a real AKS cluster (Bicep), builds the proxy / echo / loadgen images
  into its ACR, then runs two continuous fortio load generators against the same
  echo upstream:

    * loadgen-aksh      - traffic is eBPF-captured and forced through the aksh
                          proxy sidecar (TLS-terminated + policy-evaluated).
    * loadgen-baseline  - identical fortio load, NO aksh, direct to the upstream.

  The latency delta between the two IS the end-to-end cost of aksh. Prometheus
  (deployed in-cluster, backed by a PVC so it survives the whole soak) scrapes
  the proxy's own metrics plus kubelet cAdvisor, giving aksh CPU / memory and
  decision counters over time. -Soak runs a timed collection loop that snapshots
  all of this into EVIDENCE.md.

  Everything is checked in and idempotent: re-running re-applies manifests and
  re-collects evidence. Nothing here depends on the host's default kubeconfig -
  a dedicated .kubeconfig is written next to this script.

.NOTES
  Subscription VM-size allow-list: this harness defaults to Standard_E4s_v5.
  Some subscriptions restrict which VM SKUs may be deployed in a given region;
  override with -NodeVmSize if that default is not available to you.

  The cluster is LEFT RUNNING so the soak can complete. Tear down with:
    az group delete -g <ResourceGroup> --yes --no-wait
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string] $SubscriptionId,
  [string] $ResourceGroup  = "aksh-soak-rg",
  [string] $Location       = "eastus2",
  [string] $NodeVmSize     = "Standard_E4s_v5",
  [int]    $Qps            = 200,
  [int]    $Conn           = 16,
  [int]    $Interval       = 60,        # seconds per fortio batch (interim report cadence)
  [double] $DurationHours  = 6,
  [int]    $SampleMinutes  = 15,        # evidence snapshot cadence during -Soak
  [switch] $SkipInfra,                  # reuse an already-deployed cluster/ACR
  [switch] $SkipBuild,                  # reuse already-pushed :soak images
  [switch] $Soak,                       # run the timed collection loop + write EVIDENCE.md
  [switch] $ReportOnly                  # just collect one evidence snapshot and exit
)

$ErrorActionPreference = "Stop"
$here   = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo   = (Resolve-Path (Join-Path $here "..\..\..")).Path
$kcfg   = Join-Path $here ".kubeconfig"
$mani   = Join-Path $here "manifests"
$ns     = "aksh-e2e"
$depName = "aksh-soak"
$env:KUBECONFIG = $kcfg

function Step($m) { Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Native($desc, [scriptblock]$sb) {
  & $sb
  if ($LASTEXITCODE -ne 0) { throw "FAILED: $desc (exit $LASTEXITCODE)" }
}
# Query in-cluster Prometheus without a port-forward: exec wget inside its pod.
function Prom($query) {
  $px = kubectl -n $ns get pod -l app=prometheus -o jsonpath='{.items[0].metadata.name}'
  $enc = [uri]::EscapeDataString($query)
  $raw = kubectl -n $ns exec $px -c prometheus -- wget -qO- "http://localhost:9090/api/v1/query?query=$enc" 2>$null
  if (-not $raw) { return @() }
  return (($raw | ConvertFrom-Json).data.result)
}
function PromScalar($query) {
  $r = Prom $query
  if ($r -and $r.Count -ge 1) { return [double]$r[0].value[1] }
  return $null
}
# Pull a fortio -json report out of a loadgen pod and return its latency stats (ms).
function FortioStats($pod, $file) {
  $tmp = Join-Path $env:TEMP "$pod.json"
  kubectl -n $ns exec $pod -c fortio -- cat $file > $tmp 2>$null
  if (-not (Test-Path $tmp) -or (Get-Item $tmp).Length -eq 0) { return $null }
  $j = Get-Content $tmp -Raw | ConvertFrom-Json
  $p = { param($pct) (($j.DurationHistogram.Percentiles | Where-Object { $_.Percentile -eq $pct }).Value) * 1000 }
  [pscustomobject]@{
    Count = $j.DurationHistogram.Count
    Qps   = [math]::Round($j.ActualQPS, 1)
    Codes = ($j.RetCodes.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ","
    Avg   = [math]::Round($j.DurationHistogram.Avg * 1000, 3)
    P50   = [math]::Round((& $p 50), 3)
    P90   = [math]::Round((& $p 90), 3)
    P99   = [math]::Round((& $p 99), 3)
    Max   = [math]::Round($j.DurationHistogram.Max * 1000, 3)
  }
}

$evidence = Join-Path $here "EVIDENCE.md"
function Write-Evidence-Snapshot {
  $now = (Get-Date).ToUniversalTime().ToString("u")
  $a = FortioStats "loadgen-aksh"     "/reports/aksh-latest.json"
  $b = FortioStats "loadgen-baseline" "/reports/baseline-latest.json"
  $cpu = PromScalar 'rate(container_cpu_usage_seconds_total{pod="loadgen-aksh",container="aksh"}[5m])'
  $mem = PromScalar 'container_memory_working_set_bytes{pod="loadgen-aksh",container="aksh"}'
  $allow = PromScalar 'sum(aksh_decisions_total{disposition="allow"})'
  $deny  = PromScalar 'sum(aksh_decisions_total{disposition="deny"})'
  if ($null -eq $allow) { $allow = 0 }
  if ($null -eq $deny)  { $deny  = 0 }
  $memMi = if ($mem) { [math]::Round($mem/1MB,1) } else { $null }
  $cpuM  = if ($cpu) { [math]::Round($cpu*1000,1) } else { $null }

  $d50 = $null; $d90 = $null; $d99 = $null
  if ($a -and $b) {
    $d50 = [math]::Round($a.P50 - $b.P50, 3)
    $d90 = [math]::Round($a.P90 - $b.P90, 3)
    $d99 = [math]::Round($a.P99 - $b.P99, 3)
  }
  Write-Host ("[{0}] aksh p50/p90/p99={1}/{2}/{3}ms  base={4}/{5}/{6}ms  delta={7}/{8}/{9}ms  cpu={10}m mem={11}Mi allow={12} deny={13}" -f `
    $now,$a.P50,$a.P90,$a.P99,$b.P50,$b.P90,$b.P99,$d50,$d90,$d99,$cpuM,$memMi,$allow,$deny) -ForegroundColor Green

  if (-not (Test-Path $evidence)) {
@"
# aksh AKS Soak - Evidence

Cluster: AKS ($NodeVmSize) / K8s cgroup v2.
Load: fortio $Qps qps, $Conn connections, to ``allowed.test`` (echo upstream).
``loadgen-aksh`` = traffic eBPF-captured through the aksh proxy; ``loadgen-baseline`` = same load, no aksh.
Latency columns are ms. Delta = aksh - baseline = the end-to-end cost of aksh.

| UTC | aksh p50 | aksh p90 | aksh p99 | base p50 | base p90 | base p99 | dp50 | dp90 | dp99 | aksh cpu (m) | aksh mem (Mi) | allow | deny |
|-----|---------:|---------:|---------:|---------:|---------:|---------:|-----:|-----:|-----:|-------------:|--------------:|------:|-----:|
"@ | Set-Content $evidence
  }
  "| $now | $($a.P50) | $($a.P90) | $($a.P99) | $($b.P50) | $($b.P90) | $($b.P99) | $d50 | $d90 | $d99 | $cpuM | $memMi | $allow | $deny |" |
    Add-Content $evidence
}

# --------------------------------------------------------------------------
# Phase 1 - infra (Bicep): ACR + AKS
# --------------------------------------------------------------------------
Native "az account set" { az account set --subscription $SubscriptionId }

if (-not $SkipInfra) {
  Step "Deploying infra (ACR + AKS) via Bicep"
  Native "az group create" { az group create -n $ResourceGroup -l $Location -o none }
  Native "az deployment group create" {
    az deployment group create -g $ResourceGroup --name $depName `
      --template-file (Join-Path $here "infra\main.bicep") `
      --parameters location=$Location nodeVmSize=$NodeVmSize -o none
  }
}

Step "Resolving cluster / ACR names from the deployment"
$dep = az deployment group show -g $ResourceGroup -n $depName --query properties.outputs -o json 2>$null | ConvertFrom-Json
if (-not $dep) { throw "No '$depName' deployment outputs in $ResourceGroup. Run without -SkipInfra first." }
$acrName   = $dep.acrName.value
$acrServer = $dep.acrLoginServer.value
$aksName   = $dep.aksName.value
Write-Host "ACR=$acrServer  AKS=$aksName"

# --------------------------------------------------------------------------
# Phase 2 - build images into the ACR
# --------------------------------------------------------------------------
if (-not $SkipBuild) {
  Step "Building images into ACR ($acrName)"
  Native "acr build aksh-proxy" {
    az acr build --registry $acrName --image aksh-proxy:soak --file (Join-Path $repo "build\proxy.Dockerfile") $repo -o none
  }
  Native "acr build echo" {
    az acr build --registry $acrName --image echo:soak (Join-Path $repo "test\e2e\echo") -o none
  }
  Native "acr build loadgen" {
    az acr build --registry $acrName --image loadgen:soak --file (Join-Path $here "infra\loadgen.Dockerfile") (Join-Path $here "infra") -o none
  }
}

# --------------------------------------------------------------------------
# Phase 3 - kubeconfig (dedicated file, never touch the host default)
# --------------------------------------------------------------------------
Step "Fetching kubeconfig -> $kcfg"
Native "az aks get-credentials" {
  az aks get-credentials -g $ResourceGroup -n $aksName --file $kcfg --overwrite-existing --only-show-errors
}

if ($ReportOnly) { Write-Evidence-Snapshot; return }

# --------------------------------------------------------------------------
# Phase 4 - deploy workloads
# --------------------------------------------------------------------------
Step "Applying base manifests (namespace, CRD, RBAC, policy)"
foreach ($m in "00-namespace","10-crd","20-rbac","30-policy") {
  Native "apply $m" { kubectl apply -f (Join-Path $repo "test\e2e\manifests\$m.yaml") }
}

Step "Creating upstream-ca configmap (proxy trusts the echo leaf via this CA)"
kubectl -n $ns delete configmap upstream-ca --ignore-not-found | Out-Null
$caArg = "--from-file=upstream-ca.crt=" + (Join-Path $repo "test\e2e\certs\ca.crt")
Native "create upstream-ca" {
  kubectl -n $ns create configmap upstream-ca $caArg
}

Step "Applying echo + Prometheus + load generators"
# ${...} placeholders are substituted here so the manifests stay declarative.
function ApplyTemplated($file, [bool]$forcePull) {
  $t = (Get-Content $file) `
    -replace '\$\{ACR\}',      $acrServer `
    -replace '\$\{QPS\}',      $Qps `
    -replace '\$\{CONN\}',     $Conn `
    -replace '\$\{INTERVAL\}', $Interval `
    -replace '\$\{MODE\}',     'loop'
  if ($forcePull) { $t = $t -replace 'imagePullPolicy: IfNotPresent','imagePullPolicy: Always' }
  $t | kubectl apply -f -
  if ($LASTEXITCODE -ne 0) { throw "apply failed: $file" }
}
ApplyTemplated (Join-Path $mani "40-echo.yaml")            $false
kubectl apply -f (Join-Path $mani "60-prometheus.yaml") | Out-Null
# Force a pull for the loadgens so a rebuilt :soak image is always picked up.
ApplyTemplated (Join-Path $mani "70-loadgen-aksh.yaml")    $true
ApplyTemplated (Join-Path $mani "71-loadgen-baseline.yaml") $true

Step "Waiting for workloads to become Ready"
Native "rollout echo"       { kubectl -n $ns rollout status deploy/echo-upstream --timeout=180s }
Native "rollout prometheus" { kubectl -n $ns rollout status deploy/prometheus  --timeout=180s }
Native "ready loadgen-aksh" { kubectl -n $ns wait --for=condition=Ready pod/loadgen-aksh --timeout=240s }
Native "ready baseline"     { kubectl -n $ns wait --for=condition=Ready pod/loadgen-baseline --timeout=120s }
kubectl -n $ns get pods -o wide

# --------------------------------------------------------------------------
# Phase 5 - evidence
# --------------------------------------------------------------------------
Step "Initial evidence snapshot"
Start-Sleep -Seconds ([math]::Max($Interval + 15, 75))   # let the first fortio batch finish
Write-Evidence-Snapshot

if ($Soak) {
  $end = (Get-Date).AddHours($DurationHours)
  Step ("Soaking until {0} (every {1} min) -> {2}" -f $end.ToString("u"), $SampleMinutes, $evidence)
  while ((Get-Date) -lt $end) {
    Start-Sleep -Seconds ($SampleMinutes * 60)
    try { Write-Evidence-Snapshot } catch { Write-Warning "snapshot failed: $_" }
  }
  Step "Soak complete - final snapshot"
  Write-Evidence-Snapshot
  Write-Host "Evidence written to $evidence" -ForegroundColor Green
} else {
  Write-Host "`nWorkloads deployed. Re-run with -Soak to run the timed $DurationHours-hour collection, or -ReportOnly for a one-off snapshot." -ForegroundColor Yellow
}
