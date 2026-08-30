<#
.SYNOPSIS
  Two supplemental aksh performance tests on the AKS soak cluster:

    1. Connection handshake / churn - fortio with keep-alive DISABLED, so every
       request opens a fresh TCP+TLS connection (Sockets ~= request count). The
       6h soak reused warm connections and so hid per-connection cost. aksh's
       transport listener enforces a handshake-RATE limit (default 50/s, burst
       100 - listener.DefaultOptions()), a deliberate resource guard. So we
       measure at two rates:
         * BELOW the limit  -> clean; the aksh-vs-baseline delta is the true
                               per-connection TLS-handshake tax.
         * ABOVE the limit  -> the limiter engages and sheds the excess
                               (aksh_transport_reject_total{bound=handshake_rate}).
    2. QPS ramp - increasing warm-connection request rates through aksh to find
       the latency knee / saturation point and the CPU curve.

  Both reuse the loadgen pods from run.ps1, switched to LOADGEN_MODE=idle so THIS
  script is the only load source. Load is driven with `kubectl exec` (the exec'd
  fortio runs in the pod cgroup, so on loadgen-aksh it is still eBPF-captured -
  confirmed by the proxy's own reject counter incrementing).

  Writes CHURN.md and RAMP.md next to this script (git-ignored, per-run).

.NOTES
  Requires the cluster/images from run.ps1. Leaves loadgens idle; restore the
  soak loop with `run.ps1 -SkipInfra -SkipBuild`.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]   $SubscriptionId,
  [string]   $ResourceGroup  = "aksh-soak-rg",
  [int]      $ChurnConn      = 16,
  [int]      $BelowLimitRate = 40,      # < 50/s handshake limit -> clean
  [int]      $AboveLimitRate = 200,     # > limit -> limiter engages
  [int]      $ChurnSeconds   = 30,
  [int[]]    $RampQps        = @(100, 250, 500, 1000, 2000, 4000),
  [int]      $RampConn       = 32,
  [int]      $RampSeconds    = 45,
  [switch]   $SkipRedeploy
)

$ErrorActionPreference = "Stop"
$here    = Split-Path -Parent $MyInvocation.MyCommand.Path
$mani    = Join-Path $here "manifests"
$kcfg    = Join-Path $here ".kubeconfig"
$ns      = "aksh-e2e"
$depName = "aksh-soak"
$env:KUBECONFIG = $kcfg

function Step($m) { Write-Host "`n=== $m ===" -ForegroundColor Cyan }

Step "Resolving cluster"
az account set --subscription $SubscriptionId
$dep = az deployment group show -g $ResourceGroup -n $depName --query properties.outputs -o json | ConvertFrom-Json
$acrServer = $dep.acrLoginServer.value
$aksName   = $dep.aksName.value
az aks get-credentials -g $ResourceGroup -n $aksName --file $kcfg --overwrite-existing --only-show-errors | Out-Null
Write-Host "ACR=$acrServer AKS=$aksName"

# Prometheus instant query -> returns [sampleTimestamp, value] or $null.
function PromSample($query) {
  $px = kubectl -n $ns get pod -l app=prometheus -o jsonpath='{.items[0].metadata.name}'
  $enc = [uri]::EscapeDataString($query)
  $raw = kubectl -n $ns exec $px -c prometheus -- wget -qO- "http://localhost:9090/api/v1/query?query=$enc" 2>$null
  if (-not $raw) { return $null }
  $r = ($raw | ConvertFrom-Json).data.result
  if ($r -and $r.Count -ge 1) { return @([double]$r[0].value[0], [double]$r[0].value[1]) }
  return $null
}
function PromScalar($query) { $s = PromSample $query; if ($s) { return $s[1] } return $null }

# Average aksh-container CPU (cores) between two counter samples, using the
# samples' REAL Prometheus timestamps so scrape lag cancels out.
$cpuQ = 'container_cpu_usage_seconds_total{pod="loadgen-aksh",container="aksh"}'
function CpuSampleNow { return (PromSample $cpuQ) }
function CpuCores($before, $after) {
  if ($before -and $after -and ($after[0] -gt $before[0])) {
    return [math]::Round(($after[1] - $before[1]) / ($after[0] - $before[0]), 3)
  }
  return $null
}

# Run one fortio job inside a loadgen pod; returns latency stats (ms) + sockets/codes.
function RunFortio {
  param([string]$Pod, [int]$Qps, [int]$Conn, [int]$Seconds, [bool]$KeepAlive)
  $ka = if ($KeepAlive) { "true" } else { "false" }
  $out = "/reports/perf.json"
  kubectl -n $ns exec $Pod -c fortio -- /usr/bin/fortio load -quiet `
    "-keepalive=$ka" -qps $Qps -c $Conn -t "${Seconds}s" -https-insecure `
    -json $out "https://allowed.test:8443/" 2>&1 | Out-Null
  $tmp = Join-Path $env:TEMP "$Pod-perf.json"
  kubectl -n $ns exec $Pod -c fortio -- cat $out > $tmp 2>$null
  if (-not (Test-Path $tmp) -or (Get-Item $tmp).Length -eq 0) { return $null }
  $j = Get-Content $tmp -Raw | ConvertFrom-Json
  $pct = { param($p) [math]::Round((($j.DurationHistogram.Percentiles | Where-Object { $_.Percentile -eq $p }).Value) * 1000, 3) }
  $ok = 0; if ($j.RetCodes.PSObject.Properties['200']) { $ok = [int]$j.RetCodes.'200' }
  [pscustomobject]@{
    TargetQps = $Qps
    ActualQps = [math]::Round($j.ActualQPS, 1)
    Count     = $j.DurationHistogram.Count
    Sockets   = $j.SocketCount
    Ok200     = $ok
    Codes     = ($j.RetCodes.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ","
    Avg       = [math]::Round($j.DurationHistogram.Avg * 1000, 3)
    P50       = (& $pct 50)
    P90       = (& $pct 90)
    P99       = (& $pct 99)
    Max       = [math]::Round($j.DurationHistogram.Max * 1000, 3)
  }
}

# --------------------------------------------------------------------------
# Switch loadgens to idle so only this script drives load.
# --------------------------------------------------------------------------
function ApplyIdle($file) {
  $t = (Get-Content (Join-Path $mani $file)) `
    -replace '\$\{ACR\}',$acrServer -replace '\$\{QPS\}','1' `
    -replace '\$\{CONN\}','1' -replace '\$\{INTERVAL\}','1' -replace '\$\{MODE\}','idle'
  $t | kubectl -n $ns apply -f - | Out-Null
}
if (-not $SkipRedeploy) {
  Step "Switching load generators to idle mode"
  "70-loadgen-aksh.yaml","71-loadgen-baseline.yaml" | ForEach-Object { ApplyIdle $_ }
  kubectl -n $ns delete pod loadgen-aksh loadgen-baseline --ignore-not-found --wait=true | Out-Null
  "70-loadgen-aksh.yaml","71-loadgen-baseline.yaml" | ForEach-Object { ApplyIdle $_ }
  kubectl -n $ns wait --for=condition=Ready pod/loadgen-aksh --timeout=240s
  kubectl -n $ns wait --for=condition=Ready pod/loadgen-baseline --timeout=120s
}

Step "Warm-up (discarded) - primes the proxy accept path + JIT"
RunFortio -Pod "loadgen-aksh"     -Qps 100 -Conn 8 -Seconds 10 -KeepAlive $true | Out-Null
RunFortio -Pod "loadgen-baseline" -Qps 100 -Conn 8 -Seconds 10 -KeepAlive $true | Out-Null

# --------------------------------------------------------------------------
# Test 1 - handshake / churn (below-limit clean, above-limit limiter)
# --------------------------------------------------------------------------
Step "Handshake test: keepalive ref, below-limit ($BelowLimitRate/s), above-limit ($AboveLimitRate/s)"
function RejectCount { $v = PromScalar 'sum(aksh_transport_reject_total{bound="handshake_rate"})'; if ($null -eq $v) { return 0 } return [int]$v }

# keepalive reference (warm connections)
$rj0 = RejectCount
$akw = RunFortio -Pod "loadgen-aksh"     -Qps $AboveLimitRate -Conn $ChurnConn -Seconds $ChurnSeconds -KeepAlive $true
$bkw = RunFortio -Pod "loadgen-baseline" -Qps $AboveLimitRate -Conn $ChurnConn -Seconds $ChurnSeconds -KeepAlive $true
$rejKw = (RejectCount) - $rj0
# below the handshake limit -> should be clean (near-zero rejects)
$rj0 = RejectCount
$abl = RunFortio -Pod "loadgen-aksh"     -Qps $BelowLimitRate -Conn $ChurnConn -Seconds $ChurnSeconds -KeepAlive $false
$bbl = RunFortio -Pod "loadgen-baseline" -Qps $BelowLimitRate -Conn $ChurnConn -Seconds $ChurnSeconds -KeepAlive $false
$rejBl = (RejectCount) - $rj0
# above the handshake limit -> limiter engages
$rj0 = RejectCount
$aal = RunFortio -Pod "loadgen-aksh"     -Qps $AboveLimitRate -Conn $ChurnConn -Seconds $ChurnSeconds -KeepAlive $false
$bal = RunFortio -Pod "loadgen-baseline" -Qps $AboveLimitRate -Conn $ChurnConn -Seconds $ChurnSeconds -KeepAlive $false
$rejAl = (RejectCount) - $rj0

$rows = @(
  [pscustomobject]@{ Scn="keepalive $AboveLimitRate/s";        A=$akw; B=$bkw; Rej=$rejKw }
  [pscustomobject]@{ Scn="churn $BelowLimitRate/s (under limit)"; A=$abl; B=$bbl; Rej=$rejBl }
  [pscustomobject]@{ Scn="churn $AboveLimitRate/s (over limit)";  A=$aal; B=$bal; Rej=$rejAl }
)
function Dline($a,$b) { "p50 +{0} / p90 +{1} / p99 +{2} ms" -f [math]::Round($a.P50-$b.P50,3),[math]::Round($a.P90-$b.P90,3),[math]::Round($a.P99-$b.P99,3) }
$churnMd = Join-Path $here "CHURN.md"
$sb = [System.Text.StringBuilder]::new()
[void]$sb.AppendLine("# aksh AKS - Connection Handshake / Churn Test")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("c=$ChurnConn, ${ChurnSeconds}s per run, to ``allowed.test``. ``churn`` = ``-keepalive=false`` (fresh TCP+TLS per request; ``Sockets`` ~= requests).")
[void]$sb.AppendLine("aksh's listener caps new handshakes at **50/s (burst 100)** by default (``listener.DefaultOptions``); excess is rejected as ``aksh_transport_reject_total{bound=handshake_rate}``.")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("| Scenario | Pod | Actual qps | Sockets | 200s | p50 | p90 | p99 | max | aksh rejects |")
[void]$sb.AppendLine("|----------|-----|-----------:|--------:|-----:|----:|----:|----:|----:|-------------:|")
foreach ($r in $rows) {
  [void]$sb.AppendLine("| $($r.Scn) | aksh     | $($r.A.ActualQps) | $($r.A.Sockets) | $($r.A.Ok200) | $($r.A.P50) | $($r.A.P90) | $($r.A.P99) | $($r.A.Max) | $($r.Rej) |")
  [void]$sb.AppendLine("| $($r.Scn) | baseline | $($r.B.ActualQps) | $($r.B.Sockets) | $($r.B.Ok200) | $($r.B.P50) | $($r.B.P90) | $($r.B.P99) | $($r.B.Max) | - |")
}
[void]$sb.AppendLine("")
[void]$sb.AppendLine("- **Steady-state (keepalive) aksh cost:** $(Dline $akw $bkw)")
[void]$sb.AppendLine("- **Per-connection handshake tax (under limit):** $(Dline $abl $bbl)  (rejects=$rejBl)")
[void]$sb.AppendLine("- **Over the limit:** aksh admitted $($aal.Ok200)/$($aal.Sockets) sockets, rejected $rejAl at ``bound=handshake_rate`` - the resource guard working as designed. NOTE: the 50/s default is currently hard-coded (not exposed via config/env); workloads with low connection reuse needing >50 new conn/s would require this raised.")
$sb.ToString() | Set-Content $churnMd
Write-Host "  under-limit handshake tax: $(Dline $abl $bbl) (rejects=$rejBl)" -ForegroundColor Green
Write-Host "  over-limit: admitted $($aal.Ok200) rejected $rejAl" -ForegroundColor Green

# --------------------------------------------------------------------------
# Test 2 - QPS ramp with proper CPU (counter-delta)
# --------------------------------------------------------------------------
Step "QPS ramp: $($RampQps -join ', ') qps (c=$RampConn, ${RampSeconds}s each)"
$idleBefore = CpuSampleNow
Start-Sleep -Seconds 20
$idleCpu = CpuCores $idleBefore (CpuSampleNow)
$rampMd = Join-Path $here "RAMP.md"
$rb = [System.Text.StringBuilder]::new()
[void]$rb.AppendLine("# aksh AKS - QPS Ramp")
[void]$rb.AppendLine("")
[void]$rb.AppendLine("Warm-connection load (keep-alive on, c=$RampConn), ${RampSeconds}s/step. Achieved qps, latency, and aksh-container CPU (counter-delta over the step). Baseline = same load, no aksh. Proxy idle CPU floor ~ $idleCpu cores.")
[void]$rb.AppendLine("")
[void]$rb.AppendLine("| Target qps | aksh actual | aksh p50 | aksh p90 | aksh p99 | base p50 | base p99 | dp50 | dp99 | aksh cpu (cores) | 200s |")
[void]$rb.AppendLine("|-----------:|------------:|---------:|---------:|---------:|---------:|---------:|-----:|-----:|-----------------:|-----:|")
foreach ($q in $RampQps) {
  Write-Host "  ramp @ $q qps ..." -NoNewline
  $c0 = CpuSampleNow
  $a  = RunFortio -Pod "loadgen-aksh" -Qps $q -Conn $RampConn -Seconds $RampSeconds -KeepAlive $true
  Start-Sleep -Seconds 18
  $c1 = CpuSampleNow
  $b  = RunFortio -Pod "loadgen-baseline" -Qps $q -Conn $RampConn -Seconds $RampSeconds -KeepAlive $true
  $cpu = CpuCores $c0 $c1
  $d50 = [math]::Round($a.P50-$b.P50,3); $d99 = [math]::Round($a.P99-$b.P99,3)
  [void]$rb.AppendLine("| $q | $($a.ActualQps) | $($a.P50) | $($a.P90) | $($a.P99) | $($b.P50) | $($b.P99) | $d50 | $d99 | $cpu | $($a.Ok200) |")
  Write-Host (" actual={0} p50={1} p99={2} cpu={3}" -f $a.ActualQps,$a.P50,$a.P99,$cpu) -ForegroundColor Green
}
$rb.ToString() | Set-Content $rampMd

Write-Host "`nDone. Evidence: $churnMd , $rampMd" -ForegroundColor Green
Write-Host "Restore the soak loop with: ./run.ps1 -SkipInfra -SkipBuild" -ForegroundColor Yellow
