# Repository working agreements

## Lifecycle and authority

- This repository is a standalone pilot. Passing CI, public visibility, and
  successful catalog validation do not make it production-ready or authorize
  broader deployment.
- Keep catalog validation in `pilot`. The workflow runs on pull requests and
  `main`, but `azd catalog metadata / azd catalog metadata` must not be a
  required check without separate, explicit user approval naming this
  repository and that check.
- Required catalog enforcement also needs the canonical `azd-reference`
  portfolio mode changed to `required-enabled` and repository-specific approval
  evidence. Never infer or invent that approval.
- Use `nathanmcnulty` for commits, branches, pull requests, repository settings,
  and releases. `patriot-nmcnulty` may be used only for disposable public-fork
  tests and must not author commits in this repository.

## Source-of-truth boundaries

- `azd-reference` owns shared standards, schemas, components, and catalog
  governance. Consume reviewed immutable revisions; do not create local
  variants casually.
- `.azd/catalog.json` is display metadata only. It is not deployment input,
  permission configuration, or a runtime contract.
- The deployment-only path must remain independent of GitHub, Azure DevOps,
  `azd-reference`, `azd-website`, Azure compute, and any catalog service.

## Safe development process

- Preserve Monitor mode and the one-device pilot boundary unless the user
  separately authorizes broader Intune deployment or Lockdown promotion.
- Start with offline validation. Run `./scripts/Test-SantaTemplate.ps1` and
  `Invoke-Pester ./tests -CI` for repository changes.
- Do not upload the package, broaden assignments, publish rules, enable a sync
  service, or claim real-Mac health from fixtures or request acceptance.
- Inspect current Git state and hosted checks before merging. Keep automatic
  repository writes, approvals, and merges outside solution runtime behavior.
