# SANTA-006: delegated Graph coordinator assessment

Assessment base: [azd-santa 82c17ed961fad5f38499f8b212a2889ece249b97](https://github.com/nathanmcnulty/azd-santa/tree/82c17ed961fad5f38499f8b212a2889ece249b97).
Candidate: [graph-delegated-authentication 0.1.1](https://github.com/nathanmcnulty/azd-reference/blob/a29e222181ce8cdce5de148cf88e39bd3202cf91/components/powershell/graph-delegated-authentication/component.json),
at immutable Reference revision `a29e222181ce8cdce5de148cf88e39bd3202cf91`.
The implementation is unchanged through the Reference snapshot selected for this
assessment; this decision relies on the pinned bytes, not a moving branch.

The module LF-byte SHA-256 is
`F727F0680A6F11BE057D5A0993C6FEC9917D7DE8870685427A5EC8CA4D739B5E`;
the original manifest SHA-256 is
`624C237687850A27D748C0AF46ED09F289EBF3A5EF18C72761F5A9162C41F696`.

Defer adoption in both publishers. The package publisher's Process session cannot
be passed unchanged to a coordinator that requires CurrentUser. The profile
publisher can supply its existing scopes and a group read probe, but its implicit
connection/replacement behavior is not the coordinator's explicit opt-in contract.
This completes the assessment, not authentication refactoring or live acceptance.
No root component lock is added for an unused runtime dependency.

## Exact source comparison

All Santa links below refer to the assessment base. Coordinator references use
the immutable [module](https://github.com/nathanmcnulty/azd-reference/blob/a29e222181ce8cdce5de148cf88e39bd3202cf91/components/powershell/graph-delegated-authentication/Azd.GraphAuthentication.psm1)
and [manifest](https://github.com/nathanmcnulty/azd-reference/blob/a29e222181ce8cdce5de148cf88e39bd3202cf91/components/powershell/graph-delegated-authentication/Azd.GraphAuthentication.psd1).

| Boundary | Package publisher | Profile publisher | Coordinator 0.1.1 / decision |
|---|---|---|---|
| Tenant and account | [Connect and exact tenant/account checks, lines 158–160](https://github.com/nathanmcnulty/azd-santa/blob/82c17ed961fad5f38499f8b212a2889ece249b97/scripts/Invoke-SantaIntunePackage.ps1#L158-L160) | [Context reuse, connect and exact tenant/account checks, lines 91–99](https://github.com/nathanmcnulty/azd-santa/blob/82c17ed961fad5f38499f8b212a2889ece249b97/scripts/Invoke-SantaIntuneProfiles.ps1#L91-L99) | Requires exact tenant, expected nonempty UPN, delegated authentication, selected environment and CurrentUser context before and after connection. Do not replace these identity gates with a generic login. |
| Required scopes | `DeviceManagementApps.ReadWrite.All`, `Group.Read.All`, `DeviceManagementManagedDevices.Read.All`, `Device.Read.All`; no explicit returned-scope check at bootstrap | `DeviceManagementConfiguration.ReadWrite.All`, `Group.Read.All`; returned context scopes checked | Checks the supplied scope set without adding permissions. Keep each publisher's exact set. A context scope list is SDK metadata, not a new grant or independent cryptographic token verification. |
| Session lifetime | Explicit `Process`; connection on each apply invocation | Connect requests `CurrentUser`; reuse branch does not check ContextScope or AuthType | Requires `CurrentUser`, so package adoption needs a separately reviewed lifetime decision. Profile adoption needs explicit lifetime/auth-type assessment of inherited contexts. |
| Graph environment | [Absolute Global Graph URLs starting line 162](https://github.com/nathanmcnulty/azd-santa/blob/82c17ed961fad5f38499f8b212a2889ece249b97/scripts/Invoke-SantaIntunePackage.ps1#L162) | [Relative Graph URLs starting line 101](https://github.com/nathanmcnulty/azd-santa/blob/82c17ed961fad5f38499f8b212a2889ece249b97/scripts/Invoke-SantaIntuneProfiles.ps1#L101) use SDK environment | Validates the selected environment through Get-MgEnvironment and context metadata. Package URLs must remain consistent with a future explicit environment policy; sovereign-cloud support is not proven. |
| Token usability / read probe | First group GET occurs after bootstrap, inside solution preflight | First group GET occurs after bootstrap, inside solution preflight | Executes a caller-owned relative GET before reuse and after any authorized connection. A successful probe proves usability for that request; it does not prove every write permission, token lifetime, JWT signature, resource delivery or consent policy. |
| Interaction and replacement | Normal Connect-MgGraph inside apply/ShouldProcess boundary, without a separate interaction flag | Implicit connect when context is absent, wrong tenant or missing scopes; wrong account fails afterward | Default is no interaction and no replacement of an incompatible inherited context. AllowInteractive and AllowContextReplacement require an explicit caller policy. Authentication-only probe failures may reconnect with explicit interaction; 403/429/5xx do not start auth. No device-code fallback. |
| Mutation and receipts | [Preflight/dry-run boundary, lines 134–156](https://github.com/nathanmcnulty/azd-santa/blob/82c17ed961fad5f38499f8b212a2889ece249b97/scripts/Invoke-SantaIntunePackage.ps1#L134-L156), [solution-owned receipt, lines 38–53](https://github.com/nathanmcnulty/azd-santa/blob/82c17ed961fad5f38499f8b212a2889ece249b97/scripts/Invoke-SantaIntunePackage.ps1#L38-L53) | [Dry-run boundary, lines 75–89](https://github.com/nathanmcnulty/azd-santa/blob/82c17ed961fad5f38499f8b212a2889ece249b97/scripts/Invoke-SantaIntuneProfiles.ps1#L75-L89), [solution receipt and apply boundary](https://github.com/nathanmcnulty/azd-santa/blob/82c17ed961fad5f38499f8b212a2889ece249b97/scripts/Invoke-SantaIntuneProfiles.ps1#L145-L189) | Coordinator owns session assessment only. Preserve upload/commit polling, assignment identity, profile/package status schemas and receipt IDs in Santa. No coordinator result substitutes for these receipts. |
| Monitor / one Mac / compute | [Static one-device pilot preflight](https://github.com/nathanmcnulty/azd-santa/blob/82c17ed961fad5f38499f8b212a2889ece249b97/scripts/Invoke-SantaIntunePackage.ps1#L162-L168) | [Static one-device pilot preflight](https://github.com/nathanmcnulty/azd-santa/blob/82c17ed961fad5f38499f8b212a2889ece249b97/scripts/Invoke-SantaIntuneProfiles.ps1#L101-L111) | Preserve [Monitor profiles](https://github.com/nathanmcnulty/azd-santa/tree/82c17ed961fad5f38499f8b212a2889ece249b97/profiles), package lock and [resource-group-only infrastructure](https://github.com/nathanmcnulty/azd-santa/blob/82c17ed961fad5f38499f8b212a2889ece249b97/infra/main.bicep). No compute or deployment dependency on Reference. |

## Prerequisites for a future profile adapter

1. Select explicit interaction and inherited-context replacement policy with the
   operator. Assessment does not authorize either switch or change CurrentUser
   persistence. Keep authentication after the existing dry-run return.
2. Supply exact tenant, expected account and existing two scopes; explicitly bind
   Graph environment. Use a read-only selected pilot-group probe already covered
   by `Group.Read.All`, then retain Santa's static, exactly-one-Mac checks. The
   coordinator discards probe response content, so it cannot replace those checks.
3. Preserve ShouldProcess, assignment/receipt identity, update opt-in, readiness,
   cleanup and Monitor guards. A shared session must not broaden scope, introduce
   grants, or claim package/profile delivery.
4. Before actual adoption, vendor a reviewed immutable component with the canonical
   lock and permission provenance. Santa currently has neither a root component
   lock nor `azd-permissions.json`; absence is a provenance gap, not permission
   approval. Package adoption additionally requires a Process-versus-CurrentUser
   decision and consistent endpoint policy. No such decision is made here.

## Offline evidence and limits

`tests/Santa.GraphCompatibility.Tests.ps1` imports an unchanged, hash-bound
assessment-only source fixture. Actual coordinator calls with mocked SDK functions
prove matching profile-context reuse/one GET, Process and tenant/account/environment/
auth-type/scope mismatch refusals, missing-context refusal, simulated 401 refusal,
and no auth on 403/429/500. These are actual function tests, not live tokens or SDK
cache evidence. No interactive path is executed.

Both unchanged publisher scripts execute their actual no-Apply path with zero
context lookup, connection or Graph dispatch and no receipt. The package test runs
the actual pinned package hash and stored verification-receipt checks plus status
schema, freshness, identity and exact-device readiness checks against synthetic
status input. It does not perform new macOS signing verification. Existing tests cover Monitor,
one-device guards, generated profiles, solution receipts and compute-free planning.

For current development, run on PowerShell 7.6 or later with Pester 6.2 or later:

```powershell
Import-Module Pester -RequiredVersion 6.2.0 -Force
./scripts/New-DeploymentPlan.ps1 -Organization 'Contoso'
./scripts/Test-SantaTemplate.ps1
Invoke-Pester ./tests -CI
```

These results do not prove authentication on a real tenant, token cryptography,
permission grants, Intune delivery, endpoint health or a real-Mac pilot. Separate
authorization and real-device evidence remain required for those outcomes.

The assessment run on PowerShell 7.6.6 passed the registered offline validator and
all 55 Pester tests (39 existing and 16 compatibility tests), with zero failures,
skips or not-run tests. Generated profiles remained unchanged. Publication and
independent review are separate gates; this result does not claim component adoption.
