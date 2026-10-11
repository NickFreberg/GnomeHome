// GnomeHome's Azure side (Phase 6). Deploy into one resource group:
//
//   az deployment group create -g rg-gnomehome -f infra/main.bicep -p infra/main.parameters.json
//
// See infra/README.md first: it covers the cost guardrails, the steps Bicep can't do
// (the upload token, Unity Catalog), and how to tear everything down.

targetScope = 'resourceGroup'

@description('Azure region. Pick one where Databricks serverless and Azure OpenAI are both available.')
param location string = resourceGroup().location

@minLength(3)
@maxLength(12)
@description('Short lowercase prefix for every resource name.')
param namePrefix string = 'gnomehome'

@description('Your home network public IP (or CIDR). Storage accepts uploads from here only.')
param homePublicIp string

@description('Where budget alerts and pushes go. Use the account you sign in to the Azure mobile app with.')
param alertEmail string

@description('Monthly budget in your billing currency. The plan starts at 25.')
param monthlyBudget int = 25

@description('Log Analytics daily cap in GB (a string, because Bicep has no decimals).')
param logDailyCapGb string = '0.1'

@description('Your Entra object ID, for Key Vault administration. Optional.')
param ownerObjectId string = ''

@description('Object ID of the AzureDatabricks enterprise application, to encrypt Databricks with your key. Optional.')
param databricksAppObjectId string = ''

@description('Check-in job image (built from agent/). Empty: deploy everything but the job.')
param checkinImage string = ''

param openAiModel string = 'gpt-4.1-mini'
param openAiModelVersion string = '2025-04-14'

var suffix = uniqueString(resourceGroup().id)

module monitoring 'modules/monitoring.bicep' = {
  name: 'monitoring'
  params: {
    location: location
    namePrefix: namePrefix
    alertEmail: alertEmail
    dailyCapGb: logDailyCapGb
  }
}

module notifications 'modules/notifications.bicep' = {
  name: 'notifications'
  params: {
    location: location
    namePrefix: namePrefix
    workspaceId: monitoring.outputs.workspaceId
    actionGroupId: monitoring.outputs.actionGroupId
  }
}

module budget 'modules/budget.bicep' = {
  name: 'budget'
  params: {
    namePrefix: namePrefix
    amount: monthlyBudget
    alertEmail: alertEmail
    actionGroupId: monitoring.outputs.actionGroupId
  }
}

module keys 'modules/keyvault.bicep' = {
  name: 'keys'
  params: {
    location: location
    namePrefix: namePrefix
    suffix: suffix
    ownerObjectId: ownerObjectId
    databricksAppObjectId: databricksAppObjectId
  }
}

module storage 'modules/storage.bicep' = {
  name: 'storage'
  params: {
    location: location
    namePrefix: namePrefix
    suffix: suffix
    homePublicIp: homePublicIp
    keyVaultUri: keys.outputs.vaultUri
    keyName: keys.outputs.storageKeyName
    cmkIdentityId: keys.outputs.storageIdentityId
  }
}

module databricks 'modules/databricks.bicep' = {
  name: 'databricks'
  params: {
    location: location
    namePrefix: namePrefix
    storageAccountId: storage.outputs.accountId
    keyVaultUri: empty(databricksAppObjectId) ? '' : keys.outputs.vaultUri
    keyName: keys.outputs.databricksKeyName
    keyVersion: keys.outputs.databricksKeyVersion
  }
}

module checkin 'modules/checkin.bicep' = {
  name: 'checkin'
  params: {
    location: location
    namePrefix: namePrefix
    suffix: suffix
    logAnalyticsCustomerId: monitoring.outputs.workspaceCustomerId
    logAnalyticsWorkspaceId: monitoring.outputs.workspaceId
    storageAccountId: storage.outputs.accountId
    image: checkinImage
    modelName: openAiModel
    modelVersion: openAiModelVersion
    monitorEndpoint: notifications.outputs.ingestionEndpoint
    monitorDcrImmutableId: notifications.outputs.ruleImmutableId
    monitorDcrResourceId: notifications.outputs.ruleId
  }
}

output storageAccount string = storage.outputs.accountName
output storageDfsEndpoint string = storage.outputs.dfsEndpoint
output databricksUrl string = 'https://${databricks.outputs.workspaceUrl}'
output databricksAccessConnectorId string = databricks.outputs.accessConnectorId
output openAiEndpoint string = checkin.outputs.openAiEndpoint
output monitorEndpoint string = notifications.outputs.ingestionEndpoint
output monitorDcrId string = notifications.outputs.ruleImmutableId
output monitorDcrResourceId string = notifications.outputs.ruleId
