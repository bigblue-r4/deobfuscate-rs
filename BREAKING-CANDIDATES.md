# Breaking-Change Candidates (deferred to v2.0)

This file collects API changes that are genuinely justified but would break 1.x
consumers. Per the project's semver policy, they are **not** implemented
piecemeal — they ship together in a single planned v2.0 with a migration guide,
or not at all. Nothing here is scheduled; adoption pressure decides.

## 1. `#[non_exhaustive]` on `PassKind`

**Problem.** `PassKind` is an exhaustive public enum. Every new detection pass
adds a variant, which breaks any downstream `match` without a wildcard arm.
Passes were added in v1.10, v1.11, v1.14 — each was technically a breaking
change for exhaustive matchers.

**1.x mitigation (in effect).** Documented policy: new `PassKind` variants may
be added in minor releases; downstream code must use a `_` arm. This matches
what large ecosystem crates do, but it is a semver caveat, not a fix.

**v2.0 fix.** Mark `PassKind` `#[non_exhaustive]`. Compiler then enforces the
wildcard arm. Migration: add `_ => {}` to matches (most users already have it).

## 2. `Config` struct-literal construction

**Problem.** `Config` exposes all fields as `pub` and the docs demonstrate
`Config { weight_homoglyph: 1.0, ..Config::default() }`. Adding a config field
(every new pass adds a weight) breaks exhaustive struct literals. FRU users
(`..Config::default()`) are safe; that is the documented pattern, but the
compiler doesn't enforce it.

**1.x mitigation (in effect).** Docs only ever show FRU construction; new
fields ship in minor releases.

**v2.0 fix.** Mark `Config` `#[non_exhaustive]` and add builder-style setters
(`Config::default().weight_homoglyph(1.0)`). Migration: mechanical rewrite of
struct literals to builder calls. `validate()` moves into the builder's
finalizer so invalid configs become unrepresentable.

## 3. `Detection` / `NormalizationResult` field additions

**Problem.** Same shape as #2: all-pub structs that grow fields over time
(e.g. per-detection byte offsets have been requested informally; a `lang` hint
would come with language expansion). Downstream constructors would break.

**v2.0 fix.** `#[non_exhaustive]` on both. Downstream code that only *reads*
fields (the overwhelming case for result types) is unaffected.

## 4. `Config::from_file` removal

Deprecated since v1.16.0 (silently swallowed read/parse errors). Kept through
1.x for compatibility; delete in v2.0. Migration: `try_from_file` + `?`.

## 5. `PassKind` ordering semantics

v1.18.0 adds `PartialOrd`/`Ord` to `PassKind` (needed for no_std `BTreeSet`).
The derived order is declaration order, which is *not* pipeline order (variants
were appended as passes shipped). If ordering is ever made meaningful, aligning
declaration order with pipeline order is a breaking change to `Ord` semantics —
do it in v2.0 or never document the order as meaningful.

## Explicitly rejected

- **Renaming the crate or splitting passes into sub-crates.** Adoption is the
  asset; the single-crate story ("one dependency, 19 passes") is a feature.
- **Changing default thresholds/weights.** Tuning defaults silently changes
  downstream flag/block behavior. Defaults are frozen on 1.x; deployments
  needing different behavior use `Config`.
