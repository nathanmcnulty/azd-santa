# VM-first Santa backend lab

Opt-in **synthetic host qualification**, not a deployed Santa sync service.
Root `azure.yaml` remains Intune-only; this nested azd project runs no root hooks,
publishes no profiles/rules, installs no Santa package and enrolls no devices.
The user selected VM-first testing followed by a Container Apps comparison.

## Host and boundaries

- Ubuntu 24.04 LTS Gen2, immutable Marketplace image
  `Canonical:ubuntu-24_04-lts:server:24.04.202610160`.
- `Standard_B2als_v2`: two credit-based burstable vCPUs and 4 GiB RAM;
  32-GiB Standard SSD OS disk. Synthetic state lives on that persistent disk,
  not temporary storage. This does not prove Zentral fits in 4 GiB.
- Trusted Launch, Secure Boot/vTPM, password authentication disabled,
  platform-managed patching/assessment, managed boot diagnostics.
- Isolated VNet/subnet; priority-100 deny-all inbound, including VNet traffic.
  No inbound SSH, HTTP or HTTPS allowance, Santa listener, tunnel or public sync
  endpoint. Ubuntu's own SSH daemon may listen inside the guest but is blocked
  by the NSG.
- Standard IPv4 public IP for **explicit outbound** agent/update access, not
  ingress. No NAT gateway, Bastion, role assignment or managed identity.
- Run Command uses the existing operator's Azure authorization and executes as
  root. This is privileged execution, not an untrusted upload API.
- No real device identifiers, credentials, certificates or telemetry are sent.

## Reproduce

Prerequisites: authenticated Azure CLI/azd normal browser/broker session, PowerShell
7.6+, and existing deployment/Run Command permissions in the selected subscription.
Do not grant new roles automatically or use device-code authentication.

From the repository root, validate offline first:

```powershell
Import-Module Pester -RequiredVersion 6.2.0
./scripts/New-DeploymentPlan.ps1 -Organization Contoso
./scripts/Test-SantaTemplate.ps1
Invoke-Pester ./tests -CI
az bicep build --file experiments/vm/infra/main.bicep --stdout
```

Use a fresh dedicated lab environment. Generate an SSH key in the ignored local
`.azure` directory (or supply an existing public key). The private key is never
uploaded; no SSH ingress is opened. Preserve it outside Git for recovery.

```powershell
New-Item -ItemType Directory -Path .azure/vm-lab -Force
# Choose an absent key path; ssh-keygen must not overwrite existing material.
ssh-keygen -t rsa -b 3072 -f .azure/vm-lab/host -N '' -C santa-vm-lab
$publicKey = (Get-Content .azure/vm-lab/host.pub -Raw).Trim()
Set-Location experiments/vm
$subscription = '<explicit enabled subscription ID>'
az account show --subscription $subscription
azd env new '<unique-environment>' --subscription $subscription --location westus2 --no-prompt
azd env set SANTA_VM_SSH_PUBLIC_KEY $publicKey --no-prompt
azd provision --no-prompt
```

Check each native command's exit code before continuing. The `.Trim()` avoids
injecting a multiline public-key value into azd's JSON parameter interpolation.
Before reusing an environment, inspect ownership and resources rather than
overwriting another session's lab. Root and nested `.azure` state are ignored.

Then, from `experiments/vm`, run the automated guest tests. These upload only
the six explicitly listed original Python files and one synthetic JSON fixture
through Azure Run Command, retaining their repository-relative paths;
source SHA-256 values are checked in the guest. No package installation or
GitHub access from the VM is needed. Python 3 is provided by the Ubuntu image.

```powershell
$environment = '<same environment>'
$group = "rg-azd-santa-vm-$environment"
./Test-VmLab.ps1 -SubscriptionId $subscription -EnvironmentName $environment -Initialize
# Initialize is one-time and fails if receipt.db already exists.
az vm restart --subscription $subscription --resource-group $group --name vm-santa-lab
./Test-VmLab.ps1 -SubscriptionId $subscription -EnvironmentName $environment
# Optional -ReceiptPath writes a private JSON result to an absent path.
```

Compare both guest boot IDs and source hashes, and verify the same VM resource
ID. A same-boot re-read is not reboot evidence. Probe checks exact snapshot rule
bytes, reported revision and revocation fixture state after reopening SQLite.
Missing/corrupt/changed state fails rather than reinitializing it. The separate
durability suite tests process interruption/rollback; neither suite proves
durability across region/storage loss or restoration of an old valid database.

## Cost and stop controls

West US 2 retail compute is approximately $27.45/month at 730 hours, plus $2.40
for the 32-GiB Standard SSD and $3.65 for the Standard public IPv4 address:
**approximately $33.50/month**, before storage transactions, diagnostics and
traffic. This is not a $29.85 all-in deployment.
Recheck prices and subscription credit before longer runs. Burstable CPU credits
are not two dedicated sustained cores. No paid backup/monitoring service is enabled.

After tests, deallocate this exact VM and verify `PowerState/deallocated`:

```powershell
az vm deallocate --subscription $subscription --resource-group $group --name vm-santa-lab
az vm get-instance-view --subscription $subscription --resource-group $group --name vm-santa-lab
```

Deallocation stops compute billing, **not disk/public-IP charges**. Retain the
small lab artifacts for the next test or remove the exact tagged lab group after
exporting needed receipts; group deletion destroys its disk and synthetic state.
Do not run root `azd down` or delete the existing Intune anchor group.

## Remaining gates

This is a host acceptance scaffold stacked on the offline durability spike.
It does not ship a production server, admin UI, enrollment service, certificate
authority or device-auth ingress. The maintained-server versus custom-backend
decision and real-Mac Monitor qualification remain in #37/#33. Resolve these
before exposing a service or changing SyncBaseURL. A second Container Apps
experiment must use equivalent tests and explicit durable storage; never expose
the local model as a production server to make the comparison look complete.

Follow-ups: [server qualification #45](https://github.com/nathanmcnulty/azd-santa/issues/45),
[Container Apps comparison #46](https://github.com/nathanmcnulty/azd-santa/issues/46).

## Live receipt, 2026-10-22

- `sub-patriot-lab` was Disabled with spending limit On. `sub-mvp` was Enabled;
  selected subscription `a80941e8-c2b9-4bc9-83ad-117cc40d0bea`, West US 2.
- Separate group `rg-azd-santa-vm-lab-20261022`, VM `vm-santa-lab`.
  Existing `rg-azd-santa-pilot` and the real Mac configuration were unchanged.
- Bicep compiled; subscription validation succeeded with no nested-template
  short-circuit; `azd provision` succeeded. Image exactVersion and Trusted Launch
  settings were read back; NSG readback confirmed priority-100 deny-all inbound.
- First guest execution correctly failed on a missing JSON fixture; the helper
  did not confuse Azure command acceptance with test success. Upload layout was
  corrected to include that fixture at its repository-relative path.
- Subsequent guest runs passed 20 HTTP conformance, 12 durability and 3 probe
  tests **both before and after an actual Azure VM restart**. Private receipts
  bind the same VM ID and source bundle SHA-256
  `c8e859471b7698e96a9321bfff9d1c979d135fbead52f435e2eae588a5f166eb`
  to different guest boot IDs. Exact persistent snapshot and device fixture
  markers survived the reboot. No Mac interoperability is claimed.
- Private JSON receipts and generated SSH key stay under ignored `.azure/vm-lab/`.
  No credentials or real-device payloads were uploaded. State is synthetic only.
- VM was deallocated after the tests; fresh instance-view readback confirmed
  `PowerState/deallocated`. Retained disk and public IP cost approximately
  $6.05/month before usage extras; compute billing is stopped.
- Local PowerShell 7.6.6 / Pester 6.2.0 validation passed all 119 tests; the
  canonical permission schema passed. New VM permission evidence hashes are
  checked. Pre-existing baseline
  permission evidence hash drift is tracked separately in
  [#47](https://github.com/nathanmcnulty/azd-santa/issues/47); no claim that every
  historical entry's hash was already current.

References: [Azure explicit outbound](https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/default-outbound-access),
[Basv2 specifications](https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/general-purpose/basv2-series).
