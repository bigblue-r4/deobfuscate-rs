## What

<!-- One paragraph: what changes and why. Link the issue if one exists. -->

## Checklist

- [ ] `cargo test --all-features` and `cargo test --no-default-features` pass
- [ ] `cargo clippy --all-features -- -D warnings` is clean, `cargo fmt` applied
- [ ] No breaking change to the public 1.x API (new capability is feature-gated or additive; candidates for v2.0 go in BREAKING-CANDIDATES.md instead)
- [ ] New pass or detector change: adversarial **and** benign corpus samples added (`tests/corpus/`), corpus gate still 100% detection / 0 FP
- [ ] Audit-chain behavior untouched, or its property tests extended to cover the change
- [ ] Docs updated (README table/section, `examples/config.toml` for new config fields)
