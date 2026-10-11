// Azure Databricks Premium (required for Unity Catalog and serverless SQL) and the
// access connector Unity Catalog uses to reach the storage account. Jobs run on
// serverless compute only: there are no clusters to forget running (R-08).

param location string
param namePrefix string
param storageAccountId string

@description('Optional customer-managed key for Databricks managed services. Empty to skip.')
param keyVaultUri string = ''
param keyName string = ''
param keyVersion string = ''

var storageBlobDataContributor = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
var useCmk = !empty(keyName)

resource connector 'Microsoft.Databricks/accessConnectors@2024-05-01' = {
  name: '${namePrefix}-uc-connector'
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {}
}

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' existing = {
  name: last(split(storageAccountId, '/'))
}

resource connectorStorageAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageAccountId, connector.id, storageBlobDataContributor)
  scope: storageAccount
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageBlobDataContributor)
    principalId: connector.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource workspace 'Microsoft.Databricks/workspaces@2024-05-01' = {
  name: '${namePrefix}-dbx'
  location: location
  sku: {
    name: 'premium'
  }
  properties: {
    managedResourceGroupId: subscriptionResourceId('Microsoft.Resources/resourceGroups', '${resourceGroup().name}-dbx-managed')
    publicNetworkAccess: 'Enabled'
    requiredNsgRules: 'AllRules'
    parameters: {
      enableNoPublicIp: {
        value: true
      }
    }
    encryption: useCmk
      ? {
          entities: {
            managedServices: {
              keySource: 'Microsoft.Keyvault'
              keyVaultProperties: {
                keyVaultUri: keyVaultUri
                keyName: keyName
                keyVersion: keyVersion
              }
            }
          }
        }
      : null
  }
}

output workspaceUrl string = workspace.properties.workspaceUrl
output accessConnectorId string = connector.id
