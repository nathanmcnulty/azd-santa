# Santa hosting and cost review

2026-11-28 · West US 2 · USD retail rates

Keep the Intune-only deployment as the default. It adds no Azure compute and
uses Intune to deliver Santa and its profiles. A small organization that needs
centralized rule changes and event collection can evaluate the optional
self-hosted backend. Use one VM as the reference deployment for that backend.
Keep Container Apps as an experiment while it needs additional storage,
coordination, and recovery work.

## Monthly comparison

Use the same pinned Zentral workload, event retention, authenticated HTTPS
and off-host backup requirements for both backend options. The tested stack
has seven services and six volumes, including an Elasticsearch snapshot
volume. It used about 1.6 GiB in one post-probe VM sample. The seven configured
memory limits total 3,264 MiB. Neither that sample nor the limits establish
capacity under production load. [VM qualification](server-qualification.md)

Subtract no shared free allowances. The figures below use a 730-hour month.
The idle and mixed columns show sensitivity to time at each meter rate.
Container Apps meters can switch from idle to active as replicas start,
receive traffic, or cross CPU and bandwidth thresholds. A live replay with
representative traffic is needed to measure the mix.

| Deployment shape | Always active | All idle, allocated | One-third active | Compute off or scale to zero |
| --- | ---: | ---: | ---: | ---: |
| One B2als v2 Linux VM, 2 vCPU and 4 GiB | $27.45 | $27.45 | $27.45 | $0 |
| Container Apps, seven services in one replica, 1.75 vCPU and 3.5 GiB | $193.16 | $55.19 | $101.18 | $0 |
| Container Apps, one replica per service, 2.25 vCPU and 4.5 GiB total | $248.35 | $70.96 | $130.09 | $0 |

These are compute figures. The co-located Container Apps example rounds the
sum of the VM memory limits to a supported replica size. The separate example
rounds each service up to the next 0.5 GiB and assigns 0.25 vCPU per 0.5 GiB.
Both are unqualified allocations. The $0 column has no running service, and
storage and networking can continue to incur charges.

- **VM.** The 32-GiB Standard SSD OS disk is $2.40/month plus transactions,
  and the static Standard IPv4 address is about $3.65/month. The always-on
  reference starts at about $33.50/month. At idle or deallocated, the disk
  and IP are still present. The OS and backend data share disk capacity, so
  growth or recovery headroom could require a larger disk.
- **Container Apps.** One 100-GiB Classic Premium LRS NFS v1 share adds
  $16/month at every duty cycle, including scale-to-zero. The PostgreSQL
  trial used one such share. At the minimum 32 GiB and included baseline IOPS
  and throughput, Classic SSD LRS v2 capacity would be about $3.20/month per
  share. That is a candidate for a later test. The appropriate number of
  shares and their performance requirements depend on isolation, recovery,
  snapshots, and all six volumes.
- For a complete comparison, size both hosts for the same retained data and
  backup copies, and apply the same request volume, egress, log retention and
  recovery targets. Add the actual network, monitoring, storage operations,
  registry if needed, and backup costs to each. These figures exclude those
  lines and taxes.

Rates used were $0.0376/VM hour, $0.005/static IPv4 hour, $0.16/provisioned
GiB-month for SSD v1 and $0.000137/provisioned GiB-hour for SSD v2. Container
Apps rates were $0.000034 per active vCPU-second, $0.000004 per idle
vCPU-second, and $0.000004 per allocated GiB-second at either rate.
[Azure Retail Prices API](https://learn.microsoft.com/en-us/rest/api/cost-management/retail-prices/azure-retail-prices) ·
[Container Apps pricing](https://azure.microsoft.com/en-us/pricing/details/container-apps/) ·
[Consumption allocations](https://learn.microsoft.com/en-us/azure/container-apps/containers#vCPU-and-memory-allocation-requirements) ·
[Azure Files billing](https://learn.microsoft.com/en-us/azure/storage/files/understanding-billing)

## What the live tests change

One scheduled Container Apps worker met the Elasticsearch kernel threshold.
One PostgreSQL 18.6 job committed a row, stopped the process normally,
restarted it on hard NFSv4.1, and read the row back. Both trials were retired
and their resource groups verified absent. [Kernel trial](https://github.com/nathanmcnulty/azd-santa/pull/245#issuecomment-7237221711) ·
[PostgreSQL trial](https://github.com/nathanmcnulty/azd-santa/pull/245#issuecomment-7237530231)

Before investing in another live test, decide the monthly cost target and
which centralized features the optional backend needs. The next Container
Apps decision requires a credible storage and single-writer design, including
crash recovery and the security store's existing persistence semantics. A
supported storage substitution must pass the same protocol and recovery
requirements. Confirm licensing and image maintenance before recommending a
backend for production. [Open acceptance gates](https://github.com/nathanmcnulty/azd-santa/issues/46)

## First recurring savings

The three deallocated labs' disks and static addresses are about $18.15/month
at these rates before storage transactions and the independent backup account.
Retiring one equivalent old lab saves about $6.05/month in fixed disk and IP
charges. The independent backup account's firewall currently names the
`privatehook2-20261107` and `privatehook3-20261107` subnets. The first host holds
credential-rotation evidence, and the second was used for six-volume backup
qualification. Before retiring either, verify the required evidence is
preserved and that the planned recovery path can read the retained backup
without that subnet. Keep the pilot origin available for controlled native
validation. Verify disk, IP and resource-group absence after an approved
retirement.
