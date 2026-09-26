targetScope = 'subscription'

@minLength(2)
param environmentName string

param location string

// AZD requires a resource-bearing template. Endpoint resources are deployed
// separately through guarded hooks, and no Azure compute is created here.
resource resourceGroup 'Microsoft.Resources/resourceGroups@2025-04-01' = {
  name: 'rg-azd-santa-${environmentName}'
  location: location
  tags: {
    'azd-env-name': environmentName
    'azd-solution': 'azd-santa'
  }
}

output AZURE_RESOURCE_GROUP string = resourceGroup.name
