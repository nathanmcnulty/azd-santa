# Graph session validation and browser recovery

This is a bounded partial fix for issue #34. Santa reuses a compatible existing
Graph context and gives actionable sign-in guidance. Automated browser bootstrap
remains blocked by the SDK limitations below; this does not claim to close #34.

All five Intune collectors/publishers now require the operator to establish the
session **before** running them, in the same PowerShell process. They no longer
call `Connect-MgGraph` or read/change SDK authentication preferences internally.
This is a behavioral/UX tradeoff requiring operator approval before adoption:
working automatic-login paths also become manual prerequisites. It is not an
unconditional usability improvement. Retaining automatic Connect would preserve
convenience but cannot satisfy a strict no-device-code guarantee with this SDK.
This deliberate change prevents automatic session replacement and the SDK's
implicit device-code fallback during connection. Dry-run publishers still require
no authentication. Publication/status receipts and exact-device checks are unchanged.

## Existing session contract

A context must match the selected tenant/account, Global Graph environment,
delegated `InteractiveBrowser` credential type, existing scope set and lifetime.
A selected pilot-group GET checks request usability. Wrong tenant/account/client,
missing scopes, incompatible lifetime/type, failed authentication and forbidden
access produce distinct diagnostics; no failure triggers reconnect or more scopes.
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

1. Open a supported interactive PowerShell 7.6+ terminal. For the ordinary broker
   route, establish the selected tenant/account, existing scopes and lifetime using
   the SDK's documented sign-in flow. Run Santa in that same process.
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
4. **Abort if the SDK presents a device-code prompt.** It can internally fall back
   after a browser-open failure even without `-UseDeviceCode`. Setting that switch
   to false is not a no-fallback guarantee. Do not use Azure CLI or unrelated
   resource tokens as substitutes. Investigate the host/browser failure instead.
5. After a successful user-run browser sign-in, require explicit context validation
   by adding these parameters to the Santa script:

   ```powershell
   -AuthenticationMode NormalBrowser -GraphClientId '<existing approved custom app ID>'
   ```

   This validates the matching custom app, InteractiveBrowser credential and strict
   boolean `WamEnabled=false` metadata. That SDK property reflects the current
   preference, so it is not independent proof of the UI used to obtain a token.
   Restoring the preference before this check may invalidate the check. It does
   not initiate login or change any
   option. Missing/unknown metadata is rejected, rather than assuming browser use.

## Shared component and permission provenance

The [SANTA-006 assessment](graph-coordinator-assessment.md) remains applicable.
Its immutable 0.1.1 coordinator requires CurrentUser, so direct adoption would
change the package/health Process lifetime. It also does not solve the SDK's
internal fallback or stale persisted-option problem. This small solution adapter
validates existing sessions only; it neither imports nor forks the coordinator.
The fixture and immutable component lock stay unchanged.

No scope, role or consent feature changed. `azd-permissions.json` therefore remains
the partial inventory of its reviewed historical source evidence; metadata was
not expanded to imply new access. Solution-owned receipts are unchanged.

## Evidence and remaining gates

Offline Pester fixtures cover context reuse, identity/scope/lifetime refusal,
DeviceCode rejection, normal-browser context validation, WAM/probe errors and
unchanged null/false/true or stale persisted preference scenarios. Every SDK
operation is mocked; zero connection and option calls are asserted on all paths.
Since no options are changed, restoration is not needed on success or failure.

Actual Microsoft sign-in in the selected native host remains a separate human-run
validation gate. Automated browser initialization requires a supported SDK contract
that can prohibit device-code fallback; none is used or claimed here. CI cannot
prove host sign-in usability or Intune delivery. Issue #33 owns native endpoint
qualification.

Primary references:

- [SDK authentication retries, including device-code fallback](https://github.com/microsoftgraph/msgraph-sdk-powershell/blob/main/src/Authentication/Authentication.Core/Utilities/AuthenticationHelpers.cs)
- [Get-MgGraphOption returns cached session state](https://github.com/microsoftgraph/msgraph-sdk-powershell/blob/main/src/Authentication/Authentication/Cmdlets/GetMgGraphOption.cs)
- [SDK option loading](https://github.com/microsoftgraph/msgraph-sdk-powershell/blob/main/src/Authentication/Authentication/Common/GraphSessionInitializer.cs)
- [Set-MgGraphOption custom-client and persistence limits](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.authentication/set-mggraphoption?view=graph-powershell-1.0)
- [SDK 2.35.1 browser-flow fix](https://github.com/microsoftgraph/msgraph-sdk-powershell/releases/tag/v2.35.1)
