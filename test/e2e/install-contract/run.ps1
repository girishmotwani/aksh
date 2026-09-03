<#
.SYNOPSIS
  aksh install-contract e2e: proves that what we SHIP actually deploys, using
  nothing but deploy/ and the documented manual steps.

.DESCRIPTION
  Every other harness in this repo hand-rolls the workload-side prerequisites --
  the AkshPolicy CRD, the sidecar's Role/RoleBinding -- from its own fixtures.
  That makes them structurally incapable of noticing when deploy/ forgets to
  ship something: the harness silently compensates and the run goes green.
  Issue #2 (no sidecar RBAC in deploy/) and the missing CRD both reached main
  that way.

  This harness answers the other question: "does what we ship actually deploy?"

  It installs ONLY from deploy/, following deploy/README.md Option B (raw
  manifests) plus the documented Step 3. It applies no aksh install artifact
  from any fixture directory, and it enforces that mechanically -- see
  Assert-InstallContractIsolation. Without that enforcement the next person
  debugging a red pipeline reaches for the fixture that makes it green and the
  coverage silently disappears again, which is exactly how we got here.

  Scope: DEPLOYABILITY, not traffic. Allow/deny enforcement is covered by
  test/e2e/run.ps1 and is deliberately not duplicated here -- a second copy of
  the data-plane test would add cost and flakiness without testing the install.
  The signal this harness cares about is "the sidecar started and loaded policy",
  which is precisely what breaks when the install contract is incomplete.

  Assertions:
    1. The harness's own fixtures contain no aksh install artifacts (anti-rot).
    2. This script never references the sibling fixture directory (anti-rot).
    3. `kubectl apply -f deploy/` succeeds and establishes the CRD.
    4. The injector reaches Ready and patches both webhook caBundles.
    5. An AkshPolicy can be created -- i.e. the shipped CRD is real.
    6. A plain pod in an opted-in namespace is injected AND reaches Ready,
       which is only possible if the documented RBAC step is sufficient.
    7. NEGATIVE: with the RoleBinding removed, the pod does NOT reach Ready and
       the operator-visible diagnostic names the missing permission. This is the
       first end-to-end exercise of the Forbidden path (see #2).

.PARAMETER Cluster   kind cluster name (default aksh-install-contract).
.PARAMETER KeepUp    Leave the cluster running after the run.
.PARAMETER SkipNegative
  Skip assertion 7. It costs ~90s because it waits out the proxy's
  first-snapshot timeout. Off by default: the negative case is the one that
  regressed.
#>
[CmdletBinding()]
param(
  [string]$Cluster = "aksh-install-contract",
  [switch]$KeepUp,
  [switch]$SkipNegative
)
$ErrorActionPreference = "Stop"
# Native commands do not honour $ErrorActionPreference, so Invoke-Native is the
# single source of truth for exit codes (same rationale as test/e2e/run.ps1).
$PSNativeCommandUseErrorActionPreference = $false

$here = $PSScriptRoot
$repo = (Resolve-Path "$PSScriptRoot\..\..\..").Path
$ns   = "aksh-install"

$script:Failures = New-Object System.Collections.Generic.List[string]

function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Pass($m) { Write-Host "  [ok]   $m" -ForegroundColor DarkGreen }
function Fail($m) { $script:Failures.Add($m); Write-Host "  [FAIL] $m" -ForegroundColor Red }
function Check([bool]$ok, [string]$m) { if ($ok) { Pass $m } else { Fail $m } }

function Invoke-Native([string]$What, [scriptblock]$Cmd) {
  & $Cmd
  if ($LASTEXITCODE -ne 0) { throw "$What failed (exit $LASTEXITCODE)" }
}

# --------------------------------------------------------------------------
# Anti-rot enforcement.
#
# This is the part of the harness that matters most. A test that merely happens
# not to use fixtures today will use them again the first time someone needs a
# red pipeline to go green. These two checks make that impossible to do quietly.
# --------------------------------------------------------------------------
function Assert-InstallContractIsolation {
  # 1. Our own fixtures must contain only operator-authored objects. If someone
  #    drops a CRD or a policy-reader RoleBinding in here, the harness would
  #    start compensating for deploy/ exactly like every other suite does.
  $forbidden = @(
    @{ Pattern = 'kind:\s*CustomResourceDefinition'; What = 'the AkshPolicy CRD' },
    @{ Pattern = 'akshpolicies';                     What = 'RBAC for akshpolicies' },
    @{ Pattern = 'kind:\s*(Mutating|Validating)WebhookConfiguration'; What = 'a webhook configuration' }
  )
  $bad = @()
  foreach ($f in (Get-ChildItem "$here\manifests" -Filter *.yaml -File)) {
    $text = Get-Content $f.FullName -Raw
    foreach ($rule in $forbidden) {
      # Skip the comment lines that explain the rule itself.
      $body = ($text -split "`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
      if ($body -match $rule.Pattern) { $bad += "$($f.Name) contains $($rule.What)" }
    }
  }
  Check ($bad.Count -eq 0) `
        "harness fixtures contain no aksh install artifacts$(if($bad){ ': ' + ($bad -join '; ') })"

  # 2. This script must never reach into the sibling fixture directory. The
  #    needle is assembled at runtime so that this very check does not match
  #    itself -- otherwise the guard would always fire.
  $needle = 'e2e[\\/]man' + 'ifests'
  $self   = Get-Content $PSCommandPath -Raw
  $hits   = @(($self -split "`n") | Select-String -Pattern $needle | Where-Object { $_.Line -notmatch '^\s*#' })
  Check ($hits.Count -eq 0) `
        "harness does not reference the sibling fixture directory (hits=$($hits.Count))"
}

try {
  Step "Enforcing install-contract isolation before anything is installed"
  Assert-InstallContractIsolation

  Step "Recreating kind cluster '$Cluster'"
  kind delete cluster --name $Cluster 2>&1 | Out-Null
  Invoke-Native "kind create cluster" { kind create cluster --name $Cluster }

  Step "Building and loading images (proxy + injector)"
  # The shipped manifests default to aksh-injector:latest / aksh-proxy:latest,
  # so on kind no image edits are needed and Option B applies verbatim.
  Invoke-Native "docker build proxy"    { docker build -f "$repo\build\proxy.Dockerfile" -t aksh-proxy:latest $repo }
  Invoke-Native "docker build injector" { docker build -f "$repo\build\injector.Dockerfile" -t aksh-injector:latest $repo }
  Invoke-Native "kind load proxy"       { kind load docker-image aksh-proxy:latest --name $Cluster }
  Invoke-Native "kind load injector"    { kind load docker-image aksh-injector:latest --name $Cluster }

  # ------------------------------------------------------------------------
  # THE INSTALL. Everything from here to the workload comes from deploy/.
  # ------------------------------------------------------------------------
  Step "Installing from deploy/ exactly as deploy/README.md Option B describes"
  # Note this also asserts that deploy/examples/ cannot break a directory apply:
  # it holds placeholder manifests (<your-namespace>) that would be rejected by
  # the API server, and is only safe because `kubectl apply -f` is not recursive.
  Invoke-Native "kubectl apply -f deploy/" { kubectl apply -f "$repo\deploy" }

  Step "Asserting the AkshPolicy CRD was shipped by deploy/, not by a fixture"
  Invoke-Native "wait CRD Established" {
    kubectl wait --for=condition=Established crd/akshpolicies.aksh.dev --timeout=60s
  }
  $crdScope = "$(kubectl get crd akshpolicies.aksh.dev -o jsonpath='{.spec.scope}')"
  Check ($crdScope -eq 'Namespaced') "shipped CRD is Namespaced (got '$crdScope')"

  Step "Waiting for the injector installed from deploy/"
  Invoke-Native "rollout status aksh-injector" {
    kubectl -n aksh-system rollout status deploy/aksh-injector --timeout=180s
  }
  $mutCA = "$(kubectl get mutatingwebhookconfiguration aksh-injector-mutating -o jsonpath='{.webhooks[0].clientConfig.caBundle}')"
  $valCA = "$(kubectl get validatingwebhookconfiguration aksh-injector-validating -o jsonpath='{.webhooks[0].clientConfig.caBundle}')"
  Check ($mutCA.Length -gt 0) "mutating webhook caBundle populated (len=$($mutCA.Length))"
  Check ($valCA.Length -gt 0) "validating webhook caBundle populated (len=$($valCA.Length))"

  Step "Applying the operator's own namespace and workload fixtures"
  Invoke-Native "apply workload fixtures" { kubectl apply -f "$here\manifests\00-workload.yaml" }

  Step "Creating an AkshPolicy (proves the shipped CRD is usable)"
  $polOut = (kubectl apply -f "$here\manifests\10-policy.yaml" 2>&1 | Out-String)
  Check ($LASTEXITCODE -eq 0) "AkshPolicy applied against the shipped CRD"
  if ($LASTEXITCODE -ne 0) { Write-Host "  $($polOut.Trim())" -ForegroundColor DarkGray }

  # ------------------------------------------------------------------------
  # Step 3 of deploy/README.md, from the SHIPPED example -- not a fixture copy.
  # If deploy/examples/workload-rbac.yaml is wrong or missing, this fails, which
  # is the whole point.
  # ------------------------------------------------------------------------
  Step "Granting sidecar RBAC from the shipped example (deploy/README.md Step 3)"
  $example = "$repo\deploy\examples\workload-rbac.yaml"
  Check (Test-Path $example) "deploy/examples/workload-rbac.yaml is shipped"
  $rbac = (Get-Content $example -Raw).Replace('<your-namespace>', $ns)
  $rbacFile = "$env:TEMP\aksh-install-contract-rbac.yaml"
  [IO.File]::WriteAllText($rbacFile, $rbac)
  Invoke-Native "apply workload RBAC" { kubectl apply -f $rbacFile }

  Step "Opting the namespace in (deploy/README.md Step 4)"
  Invoke-Native "label namespace" { kubectl label namespace $ns aksh.dev/inject=enabled --overwrite }

  Step "Creating a plain pod and asserting it is injected and becomes Ready"
  kubectl -n $ns delete pod install-target --ignore-not-found | Out-Null
  Invoke-Native "create install-target" { kubectl -n $ns apply -f "$here\manifests\00-workload.yaml" }
  $c0    = "$(kubectl -n $ns get pod install-target -o jsonpath='{.spec.containers[0].name}')"
  $ann   = "$(kubectl -n $ns get pod install-target -o jsonpath='{.metadata.annotations.aksh\.dev/injected}')"
  Check ($c0 -eq 'aksh')  "sidecar was injected by the webhook (first container '$c0')"
  Check ($ann -eq 'v1')   "pod carries aksh.dev/injected=v1 (got '$ann')"

  # This is the assertion the whole harness exists for. Reaching Ready means the
  # sidecar obtained a policy snapshot, which means the documented install --
  # CRD from deploy/, RBAC from the shipped example -- is actually sufficient.
  $readyOut = (kubectl -n $ns wait --for=condition=Ready pod/install-target --timeout=180s 2>&1 | Out-String)
  Check ($LASTEXITCODE -eq 0) "injected pod reached Ready using ONLY what deploy/ ships"
  if ($LASTEXITCODE -ne 0) { Write-Host "  $($readyOut.Trim())" -ForegroundColor DarkGray }

  # ------------------------------------------------------------------------
  # Negative case: the failure mode #2 was filed for. Never exercised before.
  # ------------------------------------------------------------------------
  if (-not $SkipNegative) {
    Step "NEGATIVE: removing the policy-reader RoleBinding and asserting a clear failure"
    Invoke-Native "delete rolebinding" {
      kubectl -n $ns delete rolebinding aksh-proxy-policy-reader --ignore-not-found
    }
    kubectl -n $ns delete pod install-target --ignore-not-found --now | Out-Null
    Invoke-Native "recreate install-target" { kubectl -n $ns apply -f "$here\manifests\00-workload.yaml" }

    # The proxy's first-snapshot gate defaults to 30s; allow generously more than
    # that, then assert it did NOT come up. A pod that goes Ready here would mean
    # the sidecar runs without policy, which is the fail-open we must never have.
    $null = (kubectl -n $ns wait --for=condition=Ready pod/install-target --timeout=90s 2>&1 | Out-String)
    $becameReady = ($LASTEXITCODE -eq 0)
    Check (-not $becameReady) "pod did NOT become Ready without policy RBAC (no fail-open)"

    # And the operator must be able to tell WHY. Before #2 this produced only
    # 'context deadline exceeded' with the 403 appearing nowhere at all.
    $logs = ""
    foreach ($logArgs in @(@('-c','aksh','--tail=200'), @('-c','aksh','--previous','--tail=200'))) {
      $logs += (kubectl -n $ns logs install-target @logArgs 2>&1 | Out-String)
    }
    Check ($logs -match 'akshpolicies') `
          "sidecar diagnostic names the missing resource (akshpolicies)"
    Check ($logs -match 'list|watch|forbidden|Forbidden') `
          "sidecar diagnostic names the failing operation or the 403"
    $sample = @($logs -split "`n" | Where-Object { $_ -match 'akshpolicies' } | Select-Object -First 2)
    if ($sample) {
      Write-Host "`n--- OPERATOR-VISIBLE DIAGNOSTIC ---" -ForegroundColor Green
      $sample | ForEach-Object { Write-Host "  $($_.Trim())" }
    }
  }
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
      kubectl -n $ns describe pod install-target 2>&1 |
        Select-String -Pattern "State:|Reason:|Message:|Events:|Warning" |
        ForEach-Object { Write-Host "  $($_.Line.Trim())" }
      Write-Host "  --- aksh sidecar (last 40) ---"
      kubectl -n $ns logs install-target -c aksh --tail=40 2>&1 | ForEach-Object { Write-Host "  $_" }
      Write-Host "  --- aksh-injector (last 40) ---"
      kubectl -n aksh-system logs deploy/aksh-injector --tail=40 2>&1 | ForEach-Object { Write-Host "  $_" }
      Write-Host "  --- CRDs ---"
      kubectl get crd 2>&1 | ForEach-Object { Write-Host "  $_" }
    } catch {
      Write-Host "  (diagnostics collection failed: $($_.Exception.Message))" -ForegroundColor DarkRed
    }
  }

  if (-not $KeepUp) {
    Step "Tearing down cluster '$Cluster' (pass -KeepUp to keep it)"
    kind delete cluster --name $Cluster 2>&1 | Out-Null
  }

  if ($script:Failures.Count -gt 0) {
    Write-Host "`nINSTALL-CONTRACT FAILED - $($script:Failures.Count) check(s):" -ForegroundColor Red
    $script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
  }
  Write-Host "`nINSTALL-CONTRACT PASSED - deploy/ is sufficient on its own." -ForegroundColor Green
  exit 0
}
