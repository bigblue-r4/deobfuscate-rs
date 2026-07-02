# Contributing

Thanks for looking at this. The bar for merging is deliberately mechanical:
if the checklists below pass, review is fast.

## Ground rules

- **Semver policy.** 1.x is additive-only. New capability goes behind a
  feature flag or an additive API. New `PassKind` variants and `Config`
  fields ship in minor releases (documented caveat — downstream `match`es
  need a `_` arm; `Config` construction uses `..Config::default()`).
  Genuinely-justified breaking changes go into `BREAKING-CANDIDATES.md`,
  not into a PR.
- **The corpus gate is load-bearing.** `tests/corpus_eval.rs` enforces 100%
  detection on `tests/corpus/adversarial.jsonl` and 0 false positives on
  `tests/corpus/benign.jsonl`. A change that degrades either fails CI —
  that's the design, not an obstacle. Fix the change, don't relax the gate.
- **Audit-chain properties never regress.** Payload-free records,
  hash-before-normalization, HMAC chain covering `prev_hmac` — the tests
  covering these (see SECURITY.md) must stay green and should be *extended*
  by any change touching `src/audit.rs`.
- **Default dependency tree stays small.** Heavy deps (OTel, ML, bindings)
  are feature-gated or separate crates. If your change adds a default
  dependency, expect pushback.

## Local check matrix (what CI runs)

```bash
cargo test --all-features
cargo test --no-default-features
cargo clippy --all-features -- -D warnings
cargo fmt --check
cargo check --target thumbv7em-none-eabi --no-default-features   # no_std
cargo check --target wasm32-unknown-unknown --features wasm --no-default-features
```

Plus `cargo-semver-checks` against the latest published release and a 60 s
fuzz smoke (`cargo +nightly fuzz run analyze`).

## Adding a detection pass

1. Open a **new-pass proposal** issue first (template asks for adversarial
   samples and the false-positive analysis — the FP analysis decides the
   weight, and weight decides whether the pass is worth having).
2. Implement in `src/passes.rs` as `pass_<name>(text, detections, [config])`,
   wire into the pipeline order in `src/normalizer.rs` (order matters:
   encoding decoders before statistical passes), add the `PassKind` variant
   (append — declaration order is `Ord`-visible), display name, weight
   constant + `Config` field + serde default + `validate()` entry, and the
   `compute_score` / `confidence()` arms.
3. Tests: unit tests for fire/no-fire boundaries, plus **both** corpus files —
   at least 1 adversarial sample and 1 benign hard case per pass.
4. Docs: README pass table + weight table, `examples/config.toml`,
   `PROGRESS.md` row.

## Contributing corpus samples

Corpus-only PRs are very welcome — especially benign hard cases from real
domains (they're what keeps the FP rate honest). Format is one JSON object
per line: `{"category":"...","text":"..."}`. Escape invisible characters as
`\uXXXX` so they survive review. Every adversarial sample must be detected
and every benign sample must stay below the flag threshold, or CI fails.

## Bigram tables / language coverage

Per-script tables live in `src/tables.rs` (`*_BIGRAMS`). To improve coverage
for a language: extend the table (top ~50–100 bigrams by corpus frequency,
uppercase where the script has case), add benign prose samples to the corpus,
and a fire/no-fire unit test pair. New scripts also need a range arm in
`bigram_table_for()` in `src/passes.rs` and an `extra_<script>_bigrams`
config field.

## Release process (maintainers)

1. Update `CHANGELOG.md`, bump `version` in `Cargo.toml` **and**
   `deobfuscate-py/Cargo.toml` (versions move in lockstep).
2. Regenerate BENCHMARKS.md numbers on a minor release.
3. Tag `vX.Y.Z`, push — `release.yml` publishes to crates.io + npm (WASM)
   and `python-wheels.yml` builds/publishes wheels. Both publish steps are
   gated on their tokens and skip gracefully when unset.
