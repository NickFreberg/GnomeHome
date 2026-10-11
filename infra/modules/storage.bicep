// ADLS Gen2: the landing zone for the Pi's nightly export and the Delta lake.
// Encrypted with a customer-managed key (NFR-03), reachable only from the home
// network's public IP and trusted Azure services.

param location string
param namePrefix string
param suffix string

@description('The home network public IP (or CIDR) the Pi uploads from.')
param homePublicIp string

param keyVaultUri string
param keyName string
param cmkIdentityId string

var storageName = toLower('${take(replace(namePrefix, '-', ''), 10)}${take(suffix, 13)}')

resource account 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${cmkIdentityId}': {}
    }
  }
  properties: {
    isHnsEnabled: true // ADLS Gen2
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
    // Needed for the Pi's service SAS (create and write on one container, tied to a
    // revocable stored access policy). Everything else uses Entra ID.
    allowSharedKeyAccess: true
    defaultToOAuthAuthentication: true
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'AzureServices'
      ipRules: [
        {
          value: homePublicIp
          action: 'Allow'
        }
      ]
    }
    encryption: {
      keySource: 'Microsoft.Keyvault'
      requireInfrastructureEncryption: false
      identity: {
        userAssignedIdentity: cmkIdentityId
      }
      keyvaultproperties: {
        keyvaulturi: keyVaultUri
        keyname: keyName // no version: Azure follows key rotation automatically
      }
      services: {
        blob: {
          enabled: true
          keyType: 'Account'
        }
        file: {
          enabled: true
          keyType: 'Account'
        }
      }
    }
  }
}

resource blobs 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: account
  name: 'default'
  properties: {
    deleteRetentionPolicy: {
      enabled: true
      days: 7
    }
    containerDeleteRetentionPolicy: {
      enabled: true
      days: 7
    }
  }
}

// raw: what the Pi uploads. lake: Unity Catalog's managed Delta tables.
resource raw 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobs
  name: 'raw'
  properties: {
    publicAccess: 'None'
  }
}

resource lake 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobs
  name: 'lake'
  properties: {
    publicAccess: 'None'
  }
}

// reports: the weekly AI check-in's output, which only the check-in job may write.
resource reports 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobs
  name: 'reports'
  properties: {
    publicAccess: 'None'
  }
}

// Raw files move to the cool tier after 30 days and are deleted after 400.
resource lifecycle 'Microsoft.Storage/storageAccounts/managementPolicies@2023-05-01' = {
  parent: account
  name: 'default'
  properties: {
    policy: {
      rules: [
        {
          name: 'raw-retention'
          enabled: true
          type: 'Lifecycle'
          definition: {
            filters: {
              blobTypes: [
                'blockBlob'
              ]
              prefixMatch: [
                'raw/'
              ]
            }
            actions: {
              baseBlob: {
                tierToCool: {
                  daysAfterModificationGreaterThan: 30
                }
                delete: {
                  daysAfterModificationGreaterThan: 400
                }
              }
            }
          }
        }
      ]
    }
  }
}

output accountName string = account.name
output accountId string = account.id
output dfsEndpoint string = account.properties.primaryEndpoints.dfs
output blobEndpoint string = account.properties.primaryEndpoints.blob
