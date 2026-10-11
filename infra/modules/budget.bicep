// The day-one budget alert (NFR-11): $25 a month, emailed and pushed at 50%,
// 80%, and 100% of actual spend, and when the forecast passes 100%.

param namePrefix string
param amount int
param alertEmail string
param actionGroupId string

@description('First day of the budget period, YYYY-MM-01. Defaults to this month.')
param startDate string = '${utcNow('yyyy-MM')}-01'

resource budget 'Microsoft.Consumption/budgets@2023-11-01' = {
  name: '${namePrefix}-monthly'
  properties: {
    category: 'Cost'
    amount: amount
    timeGrain: 'Monthly'
    timePeriod: {
      startDate: startDate
    }
    notifications: {
      actual50: {
        enabled: true
        operator: 'GreaterThanOrEqualTo'
        threshold: 50
        thresholdType: 'Actual'
        contactEmails: [
          alertEmail
        ]
        contactGroups: [
          actionGroupId
        ]
      }
      actual80: {
        enabled: true
        operator: 'GreaterThanOrEqualTo'
        threshold: 80
        thresholdType: 'Actual'
        contactEmails: [
          alertEmail
        ]
        contactGroups: [
          actionGroupId
        ]
      }
      actual100: {
        enabled: true
        operator: 'GreaterThanOrEqualTo'
        threshold: 100
        thresholdType: 'Actual'
        contactEmails: [
          alertEmail
        ]
        contactGroups: [
          actionGroupId
        ]
      }
      forecast100: {
        enabled: true
        operator: 'GreaterThanOrEqualTo'
        threshold: 100
        thresholdType: 'Forecasted'
        contactEmails: [
          alertEmail
        ]
        contactGroups: [
          actionGroupId
        ]
      }
    }
  }
}
