// Push notifications (FR-16). The Pi's `gnomehome notify` sends only a time and a fixed
// kind (approval_needed, action_taken, action_failed, weekly_assessment) through the
// Logs Ingestion API. One log alert rule turns new rows into a push to the Azure mobile
// app. The push says which kind, never anything about a device.

param location string
param namePrefix string
param workspaceId string
param actionGroupId string

var stream = 'Custom-GnomeHomeNotify_CL'

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: last(split(workspaceId, '/'))
}

resource table 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: workspace
  name: 'GnomeHomeNotify_CL'
  properties: {
    plan: 'Analytics'
    retentionInDays: 30
    schema: {
      name: 'GnomeHomeNotify_CL'
      columns: [
        {
          name: 'TimeGenerated'
          type: 'datetime'
        }
        {
          name: 'Kind'
          type: 'string'
        }
      ]
    }
  }
}

resource endpoint 'Microsoft.Insights/dataCollectionEndpoints@2023-03-11' = {
  name: '${namePrefix}-dce'
  location: location
  properties: {
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
}

resource rule 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: '${namePrefix}-notify-dcr'
  location: location
  dependsOn: [
    table
  ]
  properties: {
    dataCollectionEndpointId: endpoint.id
    streamDeclarations: {
      '${stream}': {
        columns: [
          {
            name: 'TimeGenerated'
            type: 'datetime'
          }
          {
            name: 'Kind'
            type: 'string'
          }
        ]
      }
    }
    destinations: {
      logAnalytics: [
        {
          name: 'logs'
          workspaceResourceId: workspaceId
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          stream
        ]
        destinations: [
          'logs'
        ]
        // Keep only the two expected columns and the four known kinds.
        transformKql: 'source | where Kind in ("approval_needed", "action_taken", "action_failed", "weekly_assessment") | project TimeGenerated, Kind'
        outputStream: stream
      }
    ]
  }
}

resource push 'Microsoft.Insights/scheduledQueryRules@2023-12-01' = {
  name: '${namePrefix}-push'
  location: location
  properties: {
    displayName: 'GnomeHome needs your attention'
    description: 'GnomeHome queued a notification. Open the dashboard or run `just incidents`.'
    severity: 3
    enabled: true
    scopes: [
      workspaceId
    ]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT5M'
    criteria: {
      allOf: [
        {
          query: 'GnomeHomeNotify_CL'
          timeAggregation: 'Count'
          dimensions: [
            {
              name: 'Kind'
              operator: 'Include'
              values: [
                '*'
              ]
            }
          ]
          operator: 'GreaterThan'
          threshold: 0
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
    autoMitigate: false
    actions: {
      actionGroups: [
        actionGroupId
      ]
    }
  }
}

output ingestionEndpoint string = endpoint.properties.logsIngestion.endpoint
output ruleImmutableId string = rule.properties.immutableId
output ruleId string = rule.id
