# Generating the local operator deployment binding

`New-SantaOperatorDeploymentBinding` in `experiments/server/SetupTransport.psm1`
turns the selected installer's nonsecret installation outputs into the exact
eleven-field file consumed by `Invoke-SantaOperatorSetup.ps1`. Administrators do
not assemble or edit that JSON. `Complete-SantaBackendInstallation` now produces
the source receipt through a bounded read-only runtime observer and calls this
consumer automatically. It is a finalization API for the future actual installer;
no build/provision lifecycle or automatic azd hook is added here.

The current VM-lab template outputs only its resource group and VM name. Those
facts do not establish a backend image, immutable VM instance, private Compose
bytes/path or HTTPS origin. Missing installation outputs deliberately produce
`Deployment is not ready for operator setup`; the generator does not discover or
guess runtime facts or obtain them from an operator setup mutation.

The finalizer accepts the selected installer's in-memory outputs, verifies the
selected VM and actual initialized runtime, then writes a bounded UTF-8 JSON
receipt in the local environment directory and retains the original SHA-256.
Its exact root fields are:

- `schemaVersion`: integer `1`.
- `scope`: `azd-santa-backend-installation`.
- `state`: `installed`.
- `deploymentId`: the selected subscription- or resource-group-scope ARM
  deployment resource ID.
- `outputs`: exactly eleven string fields: `TenantId`, `SubscriptionId`,
  `EnvironmentName`, `ResourceGroup`, `VmName`, `VmId`, `VmInstanceId`, `ImageId`,
  `ComposePath`, `ComposeSha256`, `Origin`.

Image ID, Compose path/hash and public HTTPS origin must be the installer's
actual selected deployment facts. `Origin` cannot contain credentials, a reset
path, query string or fragment. No passwords, tokens, private keys or setup links
belong in the receipt. Unknown fields, duplicates, wrong types, pending state,
missing facts, changed bytes and wrong selected identities are rejected.

The expected checksum must come from the trusted installation result; calculating
a new hash from an arbitrary edited receipt does not establish its authority.
The checksum detects changed bytes, not a malicious installer or local owner.
The receipt and absent output must share one trusted local environment directory.
The generator rejects remote/device/stream path substitution, link traversal and
existing output. Keep that directory protected against concurrent replacement.

A future hook calls finalization with values already held by its installation
context, without any customer JSON-editing step:

```powershell
Import-Module "$solutionRoot/experiments/server/SetupTransport.psm1"
$binding = Complete-SantaBackendInstallation `
    -InstallationOutputs $installation.Outputs -DeploymentId $installation.DeploymentId `
    -InstallationReceiptPath $installation.AbsentReceiptPath `
    -OperatorBindingPath $installation.AbsentOperatorBindingPath
```

The consumer reuses the same cached Azure CLI preflight as setup: exact enabled
subscription/tenant, tagged resource group, VM resource ID, immutable VM instance,
VM tags and successful provisioning. It performs three read-only calls, with the
selected subscription explicit each time. No login, account switching, grant,
Run Command, device-code flow or azd environment mutation occurs. A failed
preflight writes no binding. The output uses an exclusive flushed file create;
a local write failure may retain partial output and reports that state rather
than returning a ready binding or replacing an earlier file.
The written bytes are checked against the exact selected eleven-field
serialization before a successful binding receipt is returned.

Success returns a nonsecret path/hash/source-checksum receipt and explicitly says
runtime acceptance was not performed. Only the eleven facts are persisted; source
metadata and arbitrary fields are not copied through. This control-plane check
does not prove the backend is running, its modules match, HTTPS is reachable or
the operator completed password/MFA setup. The existing host attestor independently
checks actual runtime bindings before mutation. Trusted installer receipt
production, hook wiring and live qualification remain required; offline tests
mock Azure and do not establish those gates. See [installation finalization](backend-installation-finalization.md)
for the read-only observer and remaining lifecycle boundaries.
