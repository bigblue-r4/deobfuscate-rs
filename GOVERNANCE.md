# Governance

deobfuscate is maintained by SGAIL LLC. This file says who decides what, how a
release happens, and what happens if the maintainer is unavailable.

## Maintainers

| Role | Who | Can |
|---|---|---|
| Lead maintainer | Christopher Howard ([@bigblue-r4](https://github.com/bigblue-r4)) | Merge to `master`, cut releases, handle security reports, change these rules |

The project currently has one maintainer. A second maintainer is added by the
lead maintainer after at least three merged, non-trivial contributions, and is
listed here in the same PR that grants access.

## How decisions are made

- **Day-to-day changes** go through a pull request. `master` is branch-protected:
  every required CI check must pass, including the corpus gate (100% detection
  on `tests/corpus/adversarial.jsonl`, zero false positives on
  `tests/corpus/benign.jsonl`) and `cargo-semver-checks`. Nothing is merged
  around a failing check.
- **The rules in [CONTRIBUTING.md](CONTRIBUTING.md) are binding.** In particular,
  1.x is additive-only; breaking changes are proposed in
  [BREAKING-CANDIDATES.md](BREAKING-CANDIDATES.md), not merged.
- **Disagreements** are discussed in the issue or pull request. The lead
  maintainer makes the final call and writes down the reason in the thread.

## Releases

- A release is cut by pushing a `v*` tag on `master`. The release workflow runs
  tests and clippy first, then publishes to crates.io and attaches the WASM
  build to the GitHub release.
- **A crates.io publish cannot be undone** (only yanked), so only the lead
  maintainer pushes release tags.
- Every release has a `CHANGELOG.md` entry. Security fixes are listed under a
  **Security** heading.

## Security

Vulnerabilities are reported privately, as described in [SECURITY.md](SECURITY.md).
The lead maintainer triages reports, coordinates the fix and disclosure, and
publishes a GitHub security advisory for anything that affected a release.

## Continuity

If the lead maintainer is unreachable for 90 days with an open security report,
SGAIL LLC appoints a replacement maintainer. Until a second maintainer is named,
this is the project's single point of failure, and it is stated here on purpose.

## Changing this document

Changes to this file go through a pull request like any other change.
