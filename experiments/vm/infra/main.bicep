targetScope = 'subscription'

@minLength(2)
@maxLength(32)
param environmentName string
param location string
@minLength(40)
param sshPublicKey string

var tags = {
  'azd-env-name': environmentName
  'azd-solution': 'azd-santa'
  purpose: 'synthetic-vm-lab'
}

resource group 'Microsoft.Resources/resourceGroups@2025-04-01' = {
  name: 'rg-azd-santa-vm-${environmentName}'
  location: location
  tags: tags
}

module host './host.bicep' = {
  name: 'santa-vm-host'
  scope: group
  params: {
    location: location
    sshPublicKey: sshPublicKey
    tags: tags
  }
}

output AZURE_RESOURCE_GROUP string = group.name
output SANTA_VM_NAME string = host.outputs.vmName
