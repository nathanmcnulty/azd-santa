# Azure hostname and held-closed HTTPS preparation

This issue64 candidate adds an Azure-managed hostname to the existing Standard
IPv4 public IP and a read-only endpoint-facts producer. It adds no PIP, DNS zone,
paid DNS service, ingress rule, server startup, certificate order or azd hook.
**No actual ARM readback, DNS resolution or trusted TLS is qualified by these
offline tests.** All inbound remains denied and Caddy still responds503 before
its unreachable upstream handler.

The stable label is `santa-<first16-subscription-hex>-<environment>-vm` and fits
Azure's DNS label bounds for every accepted environment length. The same
subscription/environment uses the same label; a DNS allocation conflict fails
deployment rather than selecting another hostname. The template sets the label
on the existing `pip-santa-lab-egress`; it does not guess or publish a resulting
FQDN as successful deployment evidence. A later explicitly authorized provision
would be needed to update an existing PIP.

[Azure's public IP documentation](https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses#domain-name-label)
describes the Azure-managed `label.location.cloudapp.azure.com` mapping. The
2024-05-01 [resource API](https://learn.microsoft.com/en-us/azure/templates/microsoft.network/2024-05-01/publicipaddresses)
supports `dnsSettings.domainNameLabel`. We deliberately omit
`domainNameLabelScope`: Azure currently documents it as preview and creation-only,
so adding it to an existing PIP would not be a supported update. This candidate
makes no scoped-DNS reuse or post-deletion takeover-resistance claim.

After source review and separate permission to invoke the producer, the supported
preparation entry point is:

```powershell
./experiments/server/New-SantaHttpsCandidate.ps1 `
  -TenantId <selected-current-tenant> -SubscriptionId <selected-subscription> `
  -VmInstanceId <current-azd-SANTA_VM_INSTANCE_ID> `
  -EnvironmentName <selected-environment> -Destination <absolute-absent-path>
```

The IDs are existing deployment selection, not hand-built endpoint JSON or a
custom DNS prerequisite. The operator must supply the selected immutable VM
instance ID from accepted current deployment outputs; a replacement VM with the
same name must not be accepted automatically. This is not yet invoked by azd.

The module reuses only cached Azure CLI credentials. It neither runs login nor
changes active account nor grants roles. It requires the expected enabled
commercial-Azure subscription and tenant; reads the tagged resource group and VM;
then follows the exact single NIC/IP configuration to the public IP and subnet
NSG. It verifies both NIC/VM and public-IP/IP-configuration reverse references,
resource identities, provisioning, tags, locations, static Standard public IPv4,
the expected DNS label and authoritative ARM-returned FQDN/address. The subnet
must retain its expected NSG, outbound flag and sole priority100 wildcard inbound
deny. Multi-NIC/configuration, foreign resources, missing DNS, unsupported scope
and open/custom-rule NSGs fail closed. It rereads the full selected resource set
and rejects changes during observation. These are control-plane observations;
they are not effective-network or packet-flow proof or an atomic ARM snapshot.

The entry point writes exclusive nonsecret sibling `.arm-facts.json` and
`.arm-readback.json` files, including a facts digest and exact producer/renderer
source hashes, then passes the digest-checked facts directly to the offline
renderer. The eleven-field facts schema is unchanged. No manual JSON is needed.
The resulting local checksum establishes byte continuity from this reviewed
producer; a self-created JSON/checksum pair is not an alternative authoritative
producer. Keep failed preparation outputs; a subsequent attempt requires a new
absent destination. Unix files are0600; Windows outputs contain nonsecret facts
only and are not an ACME private-key storage mechanism.

The required ARM read operations are inventoried as existing operator rights;
metadata never grants them. Missing cached access stops preparation. Government,
China, scoped/hash DNS, multi-NIC and other resource naming/layout variants are
unsupported. Custom domains are not required for this Azure-hostname path.

Still separate: actual PIP DNS update/readback and resolution; controlled Linux
proxy delivery and resource limits; effective-network inspection; shared
admission/load/timeout/recovery acceptance; trusted certificate issuance and
renewal/restart; restricted administrator access; browser/MFA experience; native
Mac enrollment/profile delivery and retry. The renderer continues to use only
the staging ACME endpoint, with no enable switch past its unconditional503 hold.
The existing backend generator and private operator Origin remain unchanged:
`api.fqdn` is `localhost:8000` and `ALLOWED_HOSTS` contains only localhost and
127.0.0.1. Production hostname/CSRF/trusted-origin integration and real MFA
browser acceptance require separate reviewed changes and live tests. Producing
ARM endpoint facts does not make that private backend a public-host deployment.
