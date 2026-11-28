# Container Apps PostgreSQL storage probe

This opt-in experiment is the first Container Apps dependency check for
[#46](https://github.com/nathanmcnulty/azd-santa/issues/46). It uses the exact
PostgreSQL image pinned for the VM backend. The manual job checks the mounted
filesystem and options, commits a synthetic row, stops PostgreSQL, starts it
against the same data directory, and checks the row. PostgreSQL only listens on
a local Unix socket. The job has one replica, a five-minute timeout, and zero
automatic retries. Concurrent starts would use independent directories and
would provide no evidence of single-writer safety.

## Resource and cost boundary

The template targets a fresh, dedicated resource group with a delegated /27
subnet, an internal Consumption environment, a manual job, and one classic
100-GiB Premium LRS NFS share. The share is billed for provisioned capacity
while it exists, including when the job is idle. Azure also creates a managed
resource group for the environment and may create an outbound public IP there.
The template adds no workspace or persistent log sink. Check current regional
pricing, quotas, and policy before considering a paid test.

The storage service endpoint routes over the Azure backbone to the Storage
public endpoint. Its firewall denies all sources except the dedicated subnet.
HTTPS remains required for FileREST. Azure Container Apps currently requires
NFS without transport encryption for this mount, so the explicit NFS exception
and unsquashed root are scoped to this disposable synthetic share. Use no
customer data or other workloads in this environment. Unsquashed root lets the
job assign ownership of its unique data directory to the image's PostgreSQL UID.

[Container Apps NFS mounts](https://learn.microsoft.com/en-us/azure/container-apps/storage-mounts?pivots=aca-arm) ·
[Managed environment resources](https://learn.microsoft.com/en-us/azure/container-apps/custom-virtual-networks#managed-resources) ·
[Azure Files encryption settings](https://learn.microsoft.com/en-us/azure/storage/files/files-encryption-in-transit) ·
[Classic file share provisioning](https://learn.microsoft.com/en-us/azure/storage/files/storage-how-to-create-file-share)

## Offline verification

From the repository root, compile with an installed Bicep CLI and check Bash
syntax on a machine with Bash. The commands require no Azure login.

```powershell
bicep build ./experiments/container-apps/main.bicep --stdout
bash -n ./experiments/container-apps/probe-postgres.sh
```

This experiment has no root AZD hook. The ARM compilation does not exercise
region support, the delegated subnet firewall rule, or the mount. A live probe
must reach a terminal successful execution in Azure before treating this mount
as a candidate. A genuine hard mount can outlast a client timeout on storage
failure, so the operator still has to verify Azure execution and cleanup.
A passed probe would cover one PostgreSQL restart in one job execution.
Separate executions, process loss, overlapping revisions and single-writer
fencing, backup/restore, the other dependencies, the actual Zentral stack,
ingress/authentication, real Santa sync, and like-for-like cost remain open.

## Cleanup for a future authorized run

Before any create, choose a fresh short lab group name and record the
subscription and both group names. The environment's managed group is the lab
group name with `-managed` appended. Confirm both are absent in the selected
subscription. Record the deployment and execution identity and terminal result
outside Azure. Capture the execution status and error details before deleting
the environment. This probe has no permanent logging workspace.

On success, failure, timeout, or cancellation, delete the exact lab job,
environment, and dedicated group during the same session. Delete the job
first, then the environment, then the group containing the provisioned share.
Allow the environment to remove its managed infrastructure and independently
verify that both group names are absent in the selected subscription. If the
managed group persists, inventory its resources by ID and resolve the
environment dependency before treating cleanup as complete. Include public IPs,
load-balancer infrastructure, and storage in the final readback. Never delete
a pre-existing group based on that name alone.
