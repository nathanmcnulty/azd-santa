// Independent opt-in deployment. Never referenced by root or VM azure.yaml.
// Do not pass azd-env-name/azd-service-name tags or adopt an existing unrelated account.
targetScope = 'subscription'

param location string
param backupResourceGroupName string
@minLength(3)
@maxLength(24)
param backupStoreName string
param ownershipId string
@minLength(1)
@maxLength(2)
param ownedSubnetResourceIds array

var ownership = {
  'azd-santa-backup-store': 'independent-v1'
  'azd-santa-backup-owner': ownershipId
  purpose: 'encrypted-native-backup'
}

resource group 'Microsoft.Resources/resourceGroups@2025-04-01' = {
  name: backupResourceGroupName
  location: location
  tags: ownership
}

module store './store.bicep' = {
  name: 'santa-independent-backup-store'
  scope: group
  params: {
    location: location
    backupStoreName: backupStoreName
    tags: ownership
    ownedSubnetResourceIds: ownedSubnetResourceIds
  }
}

output BACKUP_STORAGE_ACCOUNT_RESOURCE_ID string = store.outputs.accountId
output BACKUP_CONTAINER_NAME string = store.outputs.containerName
