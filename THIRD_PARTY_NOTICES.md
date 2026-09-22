# Third-party notices

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

The verification workflow may retain the exact upstream Santa PKG in a private,
short-lived CI artifact, and an explicitly authorized deployment may upload
those unchanged bytes to Intune. The PKG is not modified, repackaged, committed,
or publicly released by this project. The upstream package also embeds
`SantaLicense.txt` and `ThirdPartyLicenses.txt`; those notices must remain
available with every retained or redistributed copy.
