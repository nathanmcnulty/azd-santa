# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities through GitHub's private **Report a vulnerability** flow. Do not open a public issue or include credentials, tokens, tenant identifiers, device identifiers, package-signing material, or sensitive deployment output. If private reporting is unavailable, contact the repository owner privately through the public GitHub profile with only enough detail to establish contact.

Vulnerabilities in Santa itself should also follow North Pole Security's upstream security policy.

## Supported versions

The current `main` branch and latest published release receive security fixes. This implementation is still in pilot validation; older commits and releases are unsupported unless explicitly listed here.

## Response targets

The sole maintainer aims to acknowledge a private report within 7 calendar days and provide initial triage or next steps within 14 calendar days. These are targets, not a guarantee of emergency staffing or remediation time.

## Safe disclosure

Keep vulnerability details private until impact has been assessed and a fix, mitigation, or coordinated disclosure decision is available. Never commit credentials, signing keys, tenant-specific values, device identifiers, or production configuration.

## Operational boundaries

- Never use device-code authentication. Use cached broker/WAM/MSAL or a normal browser flow when a later authorized operation needs interactive Microsoft Graph access.
- Do not deploy a package until SHA-256, package signature, Team ID, Gatekeeper assessment, notarization staple, bundle identifiers, and expected version all pass.
- Treat profile content, package URLs, event paths, usernames, certificates, process trees, sync responses, and repository content as untrusted.
- Keep Intune deployer, telemetry collector, pull-request writer, reviewer, and rule publisher identities separate.
- Static MDM rules are bootstrap/failsafe controls, not fleet telemetry or a scalable policy plane.
- MONITOR is the only default. Lockdown requires explicit approval, representative coverage, counterfactual rule analysis, tested rollback, and deployment rings.
- AI output can explain evidence; it cannot approve or publish a rule.
