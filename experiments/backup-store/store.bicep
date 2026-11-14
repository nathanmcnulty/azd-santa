param location string
param backupStoreName string
param tags object
param ownedSubnetResourceIds array

resource account 'Microsoft.Storage/storageAccounts@2025-06-01' = {
  name: backupStoreName
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    accessTier: 'Hot'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: true // Explicit service-SAS prerequisite; never change an existing policy to allow it.
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    isHnsEnabled: false
    publicNetworkAccess: 'Enabled' // Restricted public Storage endpoint, not Private Link or app ingress.
    networkAcls: {
      bypass: 'None'
      defaultAction: 'Deny'
      ipRules: []
      virtualNetworkRules: [for subnet in ownedSubnetResourceIds: {
        id: subnet
        action: 'Allow'
      }]
    }
  }
}

resource service 'Microsoft.Storage/storageAccounts/blobServices@2025-06-01' = {
  parent: account
  name: 'default'
  properties: {
    isVersioningEnabled: true
    deleteRetentionPolicy: { enabled: true, days: 7 }
    containerDeleteRetentionPolicy: { enabled: true, days: 7 }
  }
}

resource container 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-06-01' = {
  parent: service
  name: 'native-captures'
  properties: { publicAccess: 'None' }
}

output accountId string = account.id
output containerName string = container.name
