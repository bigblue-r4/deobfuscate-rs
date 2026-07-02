# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities privately via
[GitHub security advisories](https://github.com/bigblue-r4/deobfuscate-rs/security/advisories/new)
— do **not** open a public issue for anything exploitable. You should receive
an acknowledgement within a few days. Coordinated disclosure preferred; we'll
credit reporters in the changelog unless you ask otherwise.

## Supported versions

| Version | Supported |
|---------|-----------|
| latest 1.x | ✅ security fixes as patch releases |
| older 1.x | upgrade — 1.x minors are semver-compatible (enforced in CI by cargo-semver-checks) |

## Threat model and scope

This library detects **structural/encoding evasion** in text destined for an
LLM: payloads hidden behind base64, homoglyphs, BiDi controls, escapes, Morse,
ROT13, and similar transforms. It runs *before* the model.

Explicitly out of scope (deploy a semantic layer behind it — see the
feature-gated `SemanticScorer` hook):

- semantic attacks in plain text (jailbreak framing, roleplay, multi-hop)
- attacks in non-text modalities (images, audio)
- model-side vulnerabilities

A bypass of a documented pass (an encoding within a pass's stated coverage
that evades it) **is** a security bug — report it. Corpus-level detection-rate
regressions are enforced in CI, so bypass fixes come with regression tests.

## Assurance

What is continuously verified, and where:

| Property | Mechanism |
|----------|-----------|
| No panics on arbitrary input | `cargo-fuzz` target `analyze` (UTF-8 arbitrary input, invariant checks on score range and halt behavior); 60 s smoke on every CI run |
| Config parsing robustness | fuzz target `config_toml` (arbitrary TOML round-trip) |
| Detection / false-positive rates | versioned corpora in `tests/corpus/` — 100% detection, 0 FP enforced by `tests/corpus_eval.rs`; a pass change that hurts either fails the build |
| No accidental API breakage | `cargo-semver-checks` CI job against the latest published release |
| no_std profile doesn't regress | `thumbv7em-none-eabi` check job |
| Score invariants | unit tests: score ∈ [0, 1], halt ⇒ block, threshold monotonicity |

## Audit-chain guarantees

The `audit` feature produces one record per `analyze()` call with these
invariants (all covered by tests in `src/tests.rs` / `tests/integration.rs`):

1. **Payload-free by construction.** The raw input is never stored — only its
   SHA-256 digest and char length. Detection records store lengths and pass
   names; the only free-text field is `detail`, which is redactable
   (`audit_redaction = "hash" | "elide"`) for deployments where decoded
   snippet fragments must not reach the log.
2. **Hash-before-normalization.** `input_hash` is computed over the raw bytes
   before any pass runs, so the digest commits to what was actually received.
3. **Tamper-evident chaining.** `sign(key)` computes HMAC-SHA256 over the
   record's canonical JSON with `signature` nulled; `prev_hmac` is inside the
   signed content, so reordering, dropping, or editing any chained record —
   including its link — fails `verify()`.
4. **Constant-time verification.** Signature comparison uses the `hmac`
   crate's `verify_slice` (constant-time), not string equality.

## Cryptography and FIPS posture

Primitives used, all in the `audit` feature (the core detector uses no
cryptography):

| Use | Algorithm | Implementation |
|-----|-----------|----------------|
| Input digest | SHA-256 (FIPS 180-4 approved) | [RustCrypto `sha2`](https://crates.io/crates/sha2) |
| Record signing | HMAC-SHA256 (FIPS 198-1 approved) | [RustCrypto `hmac`](https://crates.io/crates/hmac) |

The **algorithms** are FIPS-approved; the RustCrypto **implementations are not
FIPS-140-validated modules**. For deployments requiring a validated module:

- The audit chain's crypto surface is two calls (`Sha256` digest,
  `Hmac<Sha256>` sign/verify) isolated in `src/audit.rs` and
  `src/normalizer.rs`. Swapping in a validated provider (e.g. `aws-lc-rs`,
  which has FIPS-validated builds, or an OpenSSL FIPS module via FFI) is a
  small, mechanical patch — open an issue if you need this as a supported
  feature flag and it will be prioritized.
- Alternatively, disable the `audit` feature and sign the JSONL stream
  externally with your validated tooling; `hash`-mode redaction plus external
  HMAC reproduces the same guarantees.

## Dependencies

The default build's dependency policy: small, widely-audited crates only
(`base64`, `unicode-normalization`, `unicode-security`, `unicode_skeleton`,
`libm`, RustCrypto hashes, `serde`/`toml`). Heavy integrations (OpenTelemetry,
Python bindings) are feature-gated or separate crates and never enter the
default tree. Dependabot watches for advisories and updates.
