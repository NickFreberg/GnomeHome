// Key Vault Standard (no Managed HSM, R-08) holding the customer-managed keys
// for storage and, optionally, Databricks (NFR-03).

param location string
param namePrefix string
param suffix string

@description('Object ID of the owner, who administers keys. Leave empty to assign later.')
param ownerObjectId string = ''

@description('Object ID of the AzureDatabricks enterprise application in this tenant, to let Databricks use its key. Leave empty to skip Databricks CMK.')
param databricksAppObjectId string = ''

var cryptoServiceEncryptionUser = 'e147488a-f6f5-4113-8e2d-b22465e65bf6'
var keyVaultAdministrator = '00482a5a-887f-4fb3-b363-3b7fe8e74483'

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: '${take(namePrefix, 10)}-kv-${take(suffix, 8)}'
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: true // a CMK vault must not lose its keys
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'AzureServices' // storage and Databricks reach their keys as trusted services
    }
  }
}

resource storageKey 'Microsoft.KeyVault/vaults/keys@2023-07-01' = {
  parent: vault
  name: 'storage-cmk'
  properties: {
    kty: 'RSA'
    keySize: 3072
    rotationPolicy: {
      attributes: {
        expiryTime: 'P2Y'
      }
      lifetimeActions: [
        {
          action: {
            type: 'rotate'
          }
          trigger: {
            timeAfterCreate: 'P1Y'
          }
        }
      ]
    }
  }
}

resource databricksKey 'Microsoft.KeyVault/vaults/keys@2023-07-01' = if (!empty(databricksAppObjectId)) {
  parent: vault
  name: 'databricks-cmk'
  properties: {
    kty: 'RSA'
    keySize: 3072
  }
}

// The storage account's own identity unwraps its key.
resource storageIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${namePrefix}-storage-cmk'
  location: location
}

resource storageKeyAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageKey.id, storageIdentity.id, cryptoServiceEncryptionUser)
  scope: storageKey
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', cryptoServiceEncryptionUser)
    principalId: storageIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource databricksKeyAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(databricksAppObjectId)) {
  name: guid(vault.id, databricksAppObjectId, cryptoServiceEncryptionUser)
  scope: databricksKey
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', cryptoServiceEncryptionUser)
    principalId: databricksAppObjectId
    principalType: 'ServicePrincipal'
  }
}

resource ownerAdmin 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(ownerObjectId)) {
  name: guid(vault.id, ownerObjectId, keyVaultAdministrator)
  scope: vault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', keyVaultAdministrator)
    principalId: ownerObjectId
    principalType: 'User'
  }
}

output vaultUri string = vault.properties.vaultUri
output vaultId string = vault.id
output storageKeyName string = storageKey.name
output storageIdentityId string = storageIdentity.id
output databricksKeyName string = empty(databricksAppObjectId) ? '' : databricksKey.name
output databricksKeyVersion string = last(split(databricksKey.?properties.keyUriWithVersion ?? '', '/'))
