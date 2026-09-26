# Vendored Santa package

`santa-2026.8.pkg` is the unchanged upstream North Pole Security release asset.
Its size and SHA-256 are locked in `../santa.lock.json`. The macOS verification
receipt is `../verification/santa-2026.8.json`; it was produced by the pinned
verification workflow on commit `44fc14dab63fcb80413694f12c66d6448ec44c79`
([run 36271914240](https://github.com/nathanmcnulty/azd-santa/actions/runs/36271914240)).

The deployment path reads this checked-in package and receipt. It does not
download from GitHub or depend on CI at deployment time. For license terms and
dependency notices, see `../../third_party/santa-2026.8/` and
`../../THIRD_PARTY_NOTICES.md`. The package has an online notarization ticket;
offline installation is not asserted.
