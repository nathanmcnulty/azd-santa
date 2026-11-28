targetScope = 'resourceGroup'

param location string = resourceGroup().location

@description('Create the PostgreSQL job and its billable 100-GiB share after the kernel preflight.')
param includePostgresStorageProbe bool = false

// Deploy only into a fresh, dedicated lab resource group.
var suffix = uniqueString(resourceGroup().id)
var managedGroupName = '${resourceGroup().name}-managed'
var mountName = 'postgres-data'
var shareQuotaGiB = 100
var images = loadJsonContent('../server/dependency-images.lock.json')
var tags = {
  purpose: 'azd-santa-disposable-nfs-probe'
}

resource network 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: 'santa-nfs-probe'
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.207.58.0/27'
      ]
    }
  }
}

resource integrationSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' = {
  parent: network
  name: 'container-apps'
  properties: {
    addressPrefix: '10.207.58.0/27'
    delegations: [
      {
        name: 'container-apps'
        properties: {
          serviceName: 'Microsoft.App/environments'
        }
      }
    ]
    serviceEndpoints: [
      {
        service: 'Microsoft.Storage'
      }
    ]
  }
}

resource account 'Microsoft.Storage/storageAccounts@2025-06-01' = if (includePostgresStorageProbe) {
  name: 'santanfs${suffix}'
  location: location
  kind: 'FileStorage'
  sku: {
    name: 'Premium_LRS'
  }
  tags: tags
  properties: {
    allowSharedKeyAccess: false
    supportsHttpsTrafficOnly: true
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'None'
      virtualNetworkRules: [
        {
          id: integrationSubnet.id
          action: 'Allow'
        }
      ]
    }
  }
}

resource fileService 'Microsoft.Storage/storageAccounts/fileServices@2025-06-01' = if (includePostgresStorageProbe) {
  parent: account
  name: 'default'
  properties: {
    protocolSettings: {
      nfs: {
        encryptionInTransit: {
          required: false
        }
      }
    }
  }
}

resource share 'Microsoft.Storage/storageAccounts/fileServices/shares@2025-06-01' = if (includePostgresStorageProbe) {
  parent: fileService
  name: 'probe'
  properties: {
    enabledProtocols: 'NFS'
    shareQuota: shareQuotaGiB
    rootSquash: 'NoRootSquash'
  }
}

resource environment 'Microsoft.App/managedEnvironments@2025-07-01' = {
  name: 'santa-nfs-probe'
  location: location
  tags: tags
  properties: {
    infrastructureResourceGroup: managedGroupName
    publicNetworkAccess: 'Disabled'
    vnetConfiguration: {
      internal: true
      infrastructureSubnetId: integrationSubnet.id
    }
    appLogsConfiguration: {
      destination: 'none'
    }
    workloadProfiles: [
      {
        name: 'Consumption'
        workloadProfileType: 'Consumption'
      }
    ]
  }
}

resource storage 'Microsoft.App/managedEnvironments/storages@2025-07-01' = if (includePostgresStorageProbe) {
  parent: environment
  name: mountName
  properties: {
    nfsAzureFile: {
      server: split(replace(account!.properties.primaryEndpoints.file, 'https://', ''), '/')[0]
      shareName: '/${account.name}/${share.name}'
      accessMode: 'ReadWrite'
    }
  }
}

resource kernelProbe 'Microsoft.App/jobs@2025-07-01' = {
  name: 'santa-elasticsearch-kernel'
  location: location
  tags: tags
  properties: {
    environmentId: environment.id
    workloadProfileName: 'Consumption'
    configuration: {
      triggerType: 'Manual'
      replicaRetryLimit: 0
      replicaTimeout: 300
      manualTriggerConfig: {
        parallelism: 1
        replicaCompletionCount: 1
      }
    }
    template: {
      containers: [
        {
          name: 'probe'
          image: images.elasticsearch
          command: [
            '/bin/bash'
            '-c'
          ]
          args: [
            loadTextContent('probe-elasticsearch-kernel.sh')
          ]
          resources: {
            cpu: json('0.25')
            memory: '0.5Gi'
          }
        }
      ]
    }
  }
}

resource probe 'Microsoft.App/jobs@2025-07-01' = if (includePostgresStorageProbe) {
  name: 'santa-postgres-nfs'
  location: location
  tags: tags
  properties: {
    environmentId: environment.id
    workloadProfileName: 'Consumption'
    configuration: {
      triggerType: 'Manual'
      replicaRetryLimit: 0
      replicaTimeout: 300
      manualTriggerConfig: {
        parallelism: 1
        replicaCompletionCount: 1
      }
    }
    template: {
      containers: [
        {
          name: 'probe'
          image: images.postgres
          command: [
            '/bin/bash'
            '-c'
          ]
          args: [
            loadTextContent('probe-postgres.sh')
          ]
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          volumeMounts: [
            {
              mountPath: '/mnt/probe'
              volumeName: mountName
            }
          ]
        }
      ]
      volumes: [
        {
          name: mountName
          storageName: storage.name
          storageType: 'NfsAzureFile'
          mountOptions: 'hard,vers=4.1'
        }
      ]
    }
  }
}

output kernelJobName string = kernelProbe.name
output postgresJobName string = includePostgresStorageProbe ? probe.name : ''
output managedResourceGroupName string = managedGroupName
