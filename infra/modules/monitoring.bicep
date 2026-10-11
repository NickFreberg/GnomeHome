// Log Analytics with a hard daily cap (R-08), and the action group that pushes
// alerts to the Azure mobile app on the owner's iPhone (FR-16).

param location string
param namePrefix string
param alertEmail string

@description('Daily ingestion cap in GB. Logging stops for the day when it is reached, so costs cannot run away.')
param dailyCapGb string = '0.1'

resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${namePrefix}-logs'
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
    workspaceCapping: {
      dailyQuotaGb: json(dailyCapGb)
    }
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

resource ownerAlerts 'Microsoft.Insights/actionGroups@2023-01-01' = {
  name: '${namePrefix}-owner'
  location: 'global'
  properties: {
    groupShortName: 'gnomehome'
    enabled: true
    // Push to the Azure mobile app, signed in with this account. Payloads stay minimal:
    // alert rules carry a fixed message, never device names or addresses.
    azureAppPushReceivers: [
      {
        name: 'owner-iphone'
        emailAddress: alertEmail
      }
    ]
    emailReceivers: [
      {
        name: 'owner-email'
        emailAddress: alertEmail
        useCommonAlertSchema: true
      }
    ]
  }
}

output workspaceId string = logs.id
output workspaceCustomerId string = logs.properties.customerId
output actionGroupId string = ownerAlerts.id
