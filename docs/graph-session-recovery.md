# Graph session validation and browser recovery

Santa reuses a compatible Graph context first. When no context exists, it calls
supported `Connect-MgGraph` automatically with the caller's original scopes,
selected tenant, Global environment and original session lifetime. The returned
identity and scopes are verified before the selected pilot-group read probe.
Dry-run publishers still require no authentication. Existing incompatible contexts
are refused with actionable errors rather than silently replaced.

Santa never explicitly requests device-code authentication. If the SDK falls back
to device code after another sign-in mechanism fails, that supported fallback is
accepted. An existing valid delegated DeviceCode context is also accepted. This
implements the operator's preference for automatic login, without claiming a
strict no-device-code guarantee. Santa does not read or change persisted SDK WAM
preferences. Publication/status receipts and exact-device checks are unchanged.

## Existing session contract

A context must match the selected tenant/account, Global Graph environment,
delegated `InteractiveBrowser` or `DeviceCode` credential type, existing scope set and lifetime.
A selected pilot-group GET checks request usability. Wrong tenant/account/client,
missing scopes, incompatible lifetime/type, failed authentication and forbidden
access produce distinct diagnostics; no probe failure triggers reconnect or more scopes. A failed automatic connection is reported without retry loops.
SDK metadata and a successful GET are not independent cryptographic token proof or
proof of every downstream permission. Only Global is supported; package/health
paths already use absolute Global URLs.

Unchanged scope/lifetime requirements:

| Caller | ContextScope | Required delegated scopes |
|---|---|---|
| Get-SantaIntuneProfileStatus.ps1 | CurrentUser | DeviceManagementConfiguration.Read.All, DeviceManagementManagedDevices.Read.All, Device.Read.All, Group.Read.All |
| Invoke-SantaIntuneProfiles.ps1 | CurrentUser | DeviceManagementConfiguration.ReadWrite.All, Group.Read.All |
| Get-SantaIntuneHealthStatus.ps1 | Process | DeviceManagementScripts.Read.All, DeviceManagementManagedDevices.Read.All, Group.Read.All, Device.Read.All |
| Publish-SantaIntuneHealthScript.ps1 | Process | DeviceManagementScripts.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, Group.Read.All, Device.Read.All |
| Invoke-SantaIntunePackage.ps1 | Process | DeviceManagementApps.ReadWrite.All, Group.Read.All, DeviceManagementManagedDevices.Read.All, Device.Read.All |

These are existing requests, not new consent or a minimal-permission guarantee.
Obtain any missing permission only through a separately approved operator process.

## User-run normal-browser route

1. Open a supported interactive PowerShell 7.6+ terminal. Run Santa normally for automatic SDK sign-in, selecting the intended account when
   prompted. An already established compatible session can also be reused.
2. If WAM reports a window-handle failure, the documented normal-browser route
   requires an **existing approved custom application** and Graph SDK 2.35.1 or
   later. The default Graph application cannot disable WAM this way. This change
   does not create an app, configure redirect URIs, grant consent, or choose one.
3. Follow Microsoft's [custom-client browser guidance](https://github.com/microsoftgraph/msgraph-sdk-powershell/blob/main/docs/authentication.md).
   `Set-MgGraphOption -DisableLoginByWAM` is a persisted user-wide preference, not
   process-local. Use a fresh host and no concurrent Graph sessions; record the
   actual prior preference. Keep the approved disabled-WAM setting through both
   sign-in and the Santa invocation, then restore it in the operator's cleanup;
   restore immediately if sign-in or validation fails. Be aware
   that `Get-MgGraphOption` is an in-memory projection loaded when the SDK session
   initializes, and can be stale after another process changes the file. Santa
   deliberately does not automate this global setting or claim exact restoration.
4. The SDK may internally fall back to device code after a browser-open failure.
   This is allowed as a last resort; Santa never passes `-UseDeviceCode` itself.
   Do not use Azure CLI or unrelated resource tokens as substitutes.
5. After a successful user-run browser sign-in, require explicit context validation
   by adding these parameters to the Santa script:

   ```powershell
   -AuthenticationMode NormalBrowser -GraphClientId '<existing approved custom app ID>'
   ```

   This validates the matching custom app, accepted delegated credential type and strict
   boolean `WamEnabled=false` metadata. That SDK property reflects the current
   preference, so it is not independent proof of the UI used to obtain a token.
   Restoring the preference before this check may invalidate the check. If no context exists it initiates the same supported connection using the selected
   custom app, but never changes any option. Missing/unknown metadata is rejected, rather than assuming browser use.

## Shared component and permission provenance

The [SANTA-006 assessment](graph-coordinator-assessment.md) remains applicable.
Its immutable 0.1.1 coordinator requires CurrentUser, so direct adoption would
change the package/health Process lifetime. It also does not solve the SDK's
internal fallback or stale persisted-option problem. This small solution adapter
reuses or establishes sessions while preserving caller lifetimes; it neither imports
nor forks the coordinator.
The fixture and immutable component lock stay unchanged.

No scope, role or consent feature changed. `azd-permissions.json` therefore remains
the partial inventory of its reviewed historical source evidence; metadata was
not expanded to imply new access. Solution-owned receipts are unchanged.

## Evidence and remaining gates

Offline Pester fixtures cover context reuse, automatic connection and returned
identity checks, identity/scope/lifetime refusal, accepted SDK device-code fallback,
normal-browser metadata validation, redacted WAM/probe errors and unchanged
nullable or stale persisted preference scenarios. Every SDK operation is mocked;
zero option reads/writes are asserted. Since no options are changed, restoration
is not needed on success or failure.

Actual Microsoft sign-in in the selected native host remains a separate human-run
validation gate. CI cannot prove host sign-in usability or Intune delivery. The
manual custom-app browser route remains necessary when this host cannot complete
normal SDK login; automatic global WAM preference changes are intentionally absent.
Issue #33 owns native endpoint qualification. This source fix does not claim that
native host or endpoint qualification is complete.

Primary references:

- [SDK authentication retries, including device-code fallback](https://github.com/microsoftgraph/msgraph-sdk-powershell/blob/main/src/Authentication/Authentication.Core/Utilities/AuthenticationHelpers.cs)
- [Get-MgGraphOption returns cached session state](https://github.com/microsoftgraph/msgraph-sdk-powershell/blob/main/src/Authentication/Authentication/Cmdlets/GetMgGraphOption.cs)
- [SDK option loading](https://github.com/microsoftgraph/msgraph-sdk-powershell/blob/main/src/Authentication/Authentication/Common/GraphSessionInitializer.cs)
- [Set-MgGraphOption custom-client and persistence limits](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.authentication/set-mggraphoption?view=graph-powershell-1.0)
- [SDK 2.35.1 browser-flow fix](https://github.com/microsoftgraph/msgraph-sdk-powershell/releases/tag/v2.35.1)
