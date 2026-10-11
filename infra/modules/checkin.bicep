// The weekly AI check-in (FR-18): an Azure OpenAI model in the owner's tenant and a
// scheduled Container Apps job that reads the gold-layer summaries and writes the
// report. The job authenticates with its managed identity: no API keys anywhere.

param location string
param namePrefix string
param suffix string
param logAnalyticsCustomerId string
param logAnalyticsWorkspaceId string
param storageAccountId string

@description('Container image for the check-in job (built from agent/). Empty: create everything except the job.')
param image string = ''

param modelName string = 'gpt-4.1-mini'
param modelVersion string = '2025-04-14'

@description('Thousands of tokens per minute. The weekly check-in needs very little.')
param modelCapacity int = 10

@description('Cron schedule (UTC) for the weekly check-in.')
param schedule string = '0 9 * * 0'

@description('Logs Ingestion endpoint and rule for the "check-in ready" push.')
param monitorEndpoint string
param monitorDcrImmutableId string
param monitorDcrResourceId string

var openAiUser = '5e0bd9bd-7b93-4f28-af87-19fc36ad61bd'
var storageBlobDataReader = '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1'
var storageBlobDataContributor = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
var monitoringMetricsPublisher = '3913510d-42f4-4e42-8a64-420c390055eb'

resource openai 'Microsoft.CognitiveServices/accounts@2024-10-01' = {
  name: '${namePrefix}-aoai-${take(suffix, 6)}'
  location: location
  kind: 'OpenAI'
  sku: {
    name: 'S0'
  }
  properties: {
    customSubDomainName: '${namePrefix}-aoai-${take(suffix, 6)}'
    disableLocalAuth: true // Entra ID only, no keys
    publicNetworkAccess: 'Enabled'
  }
}

resource deployment 'Microsoft.CognitiveServices/accounts/deployments@2024-10-01' = {
  parent: openai
  name: 'checkin'
  sku: {
    name: 'GlobalStandard'
    capacity: modelCapacity
  }
  properties: {
    model: {
      format: 'OpenAI'
      name: modelName
      version: modelVersion
    }
  }
}

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${namePrefix}-checkin'
  location: location
}

resource openaiAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(openai.id, identity.id, openAiUser)
  scope: openai
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', openAiUser)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' existing = {
  name: last(split(storageAccountId, '/'))
}

// Read-only: the agent reads summaries and can change nothing (R-04).
resource summariesAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageAccountId, identity.id, storageBlobDataReader)
  scope: storageAccount
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageBlobDataReader)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' existing = {
  parent: storageAccount
  name: 'default'
}

resource reportsContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' existing = {
  parent: blobService
  name: 'reports'
}

// Write access to the reports container only: the agent can't change any data.
resource reportsAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(reportsContainer.id, identity.id, storageBlobDataContributor)
  scope: reportsContainer
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageBlobDataContributor)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource notifyRule 'Microsoft.Insights/dataCollectionRules@2023-03-11' existing = {
  name: last(split(monitorDcrResourceId, '/'))
}

resource pushAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(monitorDcrResourceId, identity.id, monitoringMetricsPublisher)
  scope: notifyRule
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', monitoringMetricsPublisher)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: last(split(logAnalyticsWorkspaceId, '/'))
}

resource environment 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: '${namePrefix}-apps'
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logAnalyticsCustomerId
        sharedKey: logs.listKeys().primarySharedKey
      }
    }
    workloadProfiles: [
      {
        name: 'Consumption'
        workloadProfileType: 'Consumption'
      }
    ]
  }
}

resource job 'Microsoft.App/jobs@2024-03-01' = if (!empty(image)) {
  name: '${namePrefix}-checkin'
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identity.id}': {}
    }
  }
  properties: {
    environmentId: environment.id
    workloadProfileName: 'Consumption'
    configuration: {
      triggerType: 'Schedule'
      replicaTimeout: 900
      replicaRetryLimit: 1
      scheduleTriggerConfig: {
        cronExpression: schedule
        parallelism: 1
        replicaCompletionCount: 1
      }
    }
    template: {
      containers: [
        {
          name: 'checkin'
          image: image
          resources: {
            cpu: json('0.25')
            memory: '0.5Gi'
          }
          env: [
            {
              name: 'AZURE_CLIENT_ID'
              value: identity.properties.clientId
            }
            {
              name: 'AZURE_OPENAI_ENDPOINT'
              value: openai.properties.endpoint
            }
            {
              name: 'AZURE_OPENAI_DEPLOYMENT'
              value: deployment.name
            }
            {
              name: 'GNOMEHOME_SUMMARIES_URL'
              value: '${storageAccount.properties.primaryEndpoints.blob}lake/gold/checkin/'
            }
            {
              name: 'GNOMEHOME_REPORTS_URL'
              value: '${storageAccount.properties.primaryEndpoints.blob}reports/checkin'
            }
            {
              name: 'GNOMEHOME_MONITOR_ENDPOINT'
              value: monitorEndpoint
            }
            {
              name: 'GNOMEHOME_MONITOR_DCR_ID'
              value: monitorDcrImmutableId
            }
          ]
        }
      ]
    }
  }
}

output openAiEndpoint string = openai.properties.endpoint
output checkinIdentityClientId string = identity.properties.clientId
