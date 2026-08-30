// Repeatable infrastructure for the aksh AKS soak/performance harness.
//
// Provisions the two things the soak needs and nothing else:
//   1. An Azure Container Registry, because AKS nodes pull the aksh-proxy image
//      from a registry (there is no `kind load` equivalent on a real cluster).
//   2. An AKS cluster whose Linux node pool can actually run aksh's eBPF cgroup
//      programs -- Ubuntu (kernel 5.15+, cgroup v2 unified hierarchy) and a
//      plain Azure CNI. Cilium / "Azure CNI powered by Cilium" is deliberately
//      NOT used: it attaches its own eBPF to the same cgroups aksh hooks and the
//      two conflict (see test/e2e/kagent/README.md).
//
// Deploy:  az deployment group create -g <rg> -f main.bicep
// It is idempotent: re-deploying reconciles in place.

@description('Location for all resources. Defaults to the resource group location.')
param location string = resourceGroup().location

@description('Base name; resource names derive from it plus a per-RG suffix.')
param baseName string = 'akshsoak'

@description('AKS Linux node VM size. E4s_v5 = 4 vCPU / 32 GiB, enough for kagent (minimal), aksh, the load generators and a small Prometheus. NOTE: some subscriptions restrict the allowed sizes per region (e.g. D-series may be blocked); E4s_v5 is broadly allowed. Override with -p nodeVmSize=... if your subscription differs.')
param nodeVmSize string = 'Standard_E4s_v5'

@description('Number of Linux nodes.')
@minValue(1)
@maxValue(5)
param nodeCount int = 2

@description('Kubernetes version. Empty string lets AKS choose its default.')
param kubernetesVersion string = ''

// A registry name must be globally unique and alphanumeric; a login name must
// be <= 50 chars. uniqueString keeps re-deploys stable within the same RG.
var suffix = uniqueString(resourceGroup().id)
var acrName = toLower('${baseName}acr${suffix}')
var aksName = '${baseName}-aks'
var dnsPrefix = '${baseName}-${suffix}'

resource acr 'Microsoft.ContainerRegistry/registries@2023-11-01-preview' = {
  name: acrName
  location: location
  sku: {
    name: 'Basic'
  }
  properties: {
    // Pulls are authorized via the cluster's managed identity + AcrPull role
    // below, so the shared admin account stays disabled.
    adminUserEnabled: false
  }
}

resource aks 'Microsoft.ContainerService/managedClusters@2024-09-01' = {
  name: aksName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    dnsPrefix: dnsPrefix
    kubernetesVersion: empty(kubernetesVersion) ? null : kubernetesVersion
    agentPoolProfiles: [
      {
        name: 'ubuntu'
        mode: 'System'
        osType: 'Linux'
        // Ubuntu 22.04 gives the kernel 5.15 floor and cgroup v2 unified
        // hierarchy aksh's preflight gates require.
        osSKU: 'Ubuntu'
        vmSize: nodeVmSize
        count: nodeCount
        type: 'VirtualMachineScaleSets'
      }
    ]
    networkProfile: {
      // Plain Azure CNI overlay: routable enough for the harness, no Cilium.
      networkPlugin: 'azure'
      networkPluginMode: 'overlay'
      networkPolicy: 'none'
    }
  }
}

// Let the cluster's kubelet identity pull from the ACR (AcrPull).
var acrPullRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d')
resource acrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: acr
  name: guid(acr.id, aks.id, acrPullRoleId)
  properties: {
    roleDefinitionId: acrPullRoleId
    principalId: aks.properties.identityProfile.kubeletidentity.objectId
    principalType: 'ServicePrincipal'
  }
}

output acrName string = acr.name
output acrLoginServer string = acr.properties.loginServer
output aksName string = aks.name
output nodeResourceGroup string = aks.properties.nodeResourceGroup
