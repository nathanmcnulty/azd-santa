# Third-party notices

Original work in this repository is released under the [Unlicense](LICENSE).
The following terms continue to apply to third-party material and artifacts.

## North Pole Security Santa

This project integrates with and derives configuration-profile details from
[North Pole Security Santa](https://github.com/northpolesec/santa), which is
licensed under the Apache License 2.0.

The pinned Santa 2026.8 license and dependency notices are preserved in
[`third_party/santa-2026.8`](third_party/santa-2026.8). The corresponding
upstream sources are the tagged [Apache 2.0 license](https://github.com/northpolesec/santa/blob/2026.8/LICENSE)
and [third-party licenses](https://github.com/northpolesec/santa/blob/2026.8/Source/gui/Resources/ThirdPartyLicenses.txt).
North Pole Security and Santa names are used only to identify compatibility and
origin. This project is not affiliated with or endorsed by North Pole Security.

The exact upstream Santa PKG is checked in under `package/vendor/` together with
its immutable lock and verification receipt, so deployment does not depend on
GitHub or CI. An explicitly authorized deployment may upload those unchanged
bytes to Intune. The PKG is not modified or repackaged by this project and is
not covered by the Unlicense for our original code. The upstream package embeds
`SantaLicense.txt` and `ThirdPartyLicenses.txt`; those notices must remain
available with every retained or redistributed copy.

## Zentral qualification material

The core-image derivation tool and its tests include exact snapshots of the
Apache-2.0 core realm registry and event-store registry/serializers from Zentral commit
[`88e67b3ce49033aab028029937a6e14f7c489073`](https://github.com/zentralopensource/zentral/tree/88e67b3ce49033aab028029937a6e14f7c489073).
That upstream material and its derived files remain subject to Apache-2.0,
not this project's Unlicense. A copy of the standard Apache-2.0 terms is already
retained in [the vendored license text](third_party/santa-2026.8/LICENSE.txt).
The modified files carry their own modification notices, and the derived
image retains the exact upstream LICENSE and source/build notices.

Zentral's [licensing scheme](https://github.com/zentralopensource/zentral/blob/88e67b3ce49033aab028029937a6e14f7c489073/LICENSE)
separately covers `ee/` and explicitly marked files with evaluation terms. Those
enterprise backends are omitted from the core experiment, not reimplemented or
license-bypassed. The experiment is private and unqualified for production or
redistribution; each dependency retains its own terms. Zentral's name identifies
the upstream candidate, not endorsement or an official Zentral distribution.
