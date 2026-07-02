# Downstream integration outreach — DRAFTS ONLY, DO NOT SEND

Status: drafted 2026-07-01 for review. Each note is scoped to one concrete
integration point, not generic promotion. Before sending any of these:
verify the target project's current contribution norms (some prefer an issue
over email), personalize the maintainer greeting, and confirm the claimed
numbers against the shipped release.

---

## 1. LLM security / guardrails tools (e.g. llm-guard, NeMo Guardrails–style stacks, Rebuff-style detectors)

**Channel:** GitHub issue titled "Encoding-evasion pre-normalization stage" or
maintainer contact if the repo invites it.

> Hi — I maintain `deobfuscate` (Rust, MIT, crates.io + PyPI), a 19-pass
> encoding-evasion normalizer for LLM pipelines: homoglyphs (full TR39 +
> skeleton algorithm), BiDi/zero-width, base64/URL/HTML-entity/unicode-escape
> decoding, Morse/ROT13/leet, per-script entropy+bigram checks.
>
> The concrete fit: scanners that regex/classify raw text miss payloads the
> model will effectively see after Unicode confusable folding. Running a
> structural normalizer first closes that class — we catch 13/26 of the
> CyberEC false-negatives that evade a raw LLM classifier, with 0 FP on a
> versioned benign corpus (both rates CI-enforced).
>
> Integration points, pick your runtime:
> - **Python**: `pip install deobfuscate` — `scan_batch()` releases the GIL,
>   `Report.to_dict()` is DataFrame-ready.
> - **Config**: thresholds/weights/bigram tables are TOML-overridable, so
>   your users can tune without forking.
> - **Audit**: every call yields a payload-free, HMAC-chainable JSONL record
>   (redaction modes for regulated deployments) if you want detections to
>   land in your existing report format.
>
> ~0.5 ms per 1 KiB prompt single-threaded on 2014 hardware, so it fits in a
> pre-filter budget. Happy to write the adapter PR myself if there's interest
> — where would you want a normalization stage to hook in?

---

## 2. Red-team / adversarial testing frameworks (e.g. garak, PyRIT-style)

**Channel:** GitHub issue titled "Structural-evasion detector as a scoring
target / baseline".

> Hi — suggestion for the detector/scorer side of the framework. `deobfuscate`
> (MIT, Rust core with a `pip install deobfuscate` binding) is a structural
> encoding-evasion detector: 19 passes over homoglyph/BiDi/escape/base64/
> Morse/ROT13/entropy classes, with per-detection confidence scores.
>
> Two concrete uses in a red-team loop:
> 1. **Baseline defense to attack.** Probes that mutate payload encodings can
>    score against `deobfuscate.scan(x).should_block` — a reproducible,
>    versioned target with published detection rates (the corpus and CI gate
>    are public), so probe efficacy is measurable release-to-release.
> 2. **Mutation validity oracle.** After an encoding mutation, `normalized`
>    tells you what a defended pipeline would actually forward to the model —
>    useful for separating "bypassed the filter" from "broke the payload".
>
> The attack corpus format is one-line JSON and we take corpus PRs — any
> bypasses your probes find are exactly what we want in the gate. Want me to
> draft the detector plugin?

---

## 3. LLM proxy / gateway projects (e.g. LiteLLM, AI gateways on Envoy/Kong, Portkey-style)

**Channel:** GitHub discussion/issue titled "Pre-request prompt normalization
middleware".

> Hi — `deobfuscate` is a Rust normalizer for prompt-injection encoding
> evasion, built to sit exactly where a gateway sits: before the model, on
> every request.
>
> Why it fits a gateway specifically:
> - **Latency budget**: ~0.5 ms per 1 KiB prompt single-core (2014-CPU floor;
>   scales with cores, engine is Send+Sync). Numbers + methodology are in
>   BENCHMARKS.md, reproducible with `cargo bench`.
> - **Deployment shapes**: native Rust crate, `no_std`-capable minimal build
>   for edge, **WASM package on npm** (`@bigblue-r4/deobfuscate`) if your
>   filter chain runs Wasm (Envoy), and Python for middleware.
> - **Ops story**: per-tenant TOML config (thresholds, pass weights,
>   per-script bigram overrides), payload-free HMAC-chained audit records
>   (JSONL → SIEM) with redaction modes, optional OpenTelemetry spans per
>   scan with a payload-free event per detection.
>
> The API surface a middleware needs is three fields: `normalized` (forward
> this), `should_flag`, `should_block`. I'm glad to build the middleware/
> filter reference implementation against your extension API — what's the
> right shape for your project?

---

## Target list (verify before contact)

| Category | Projects to evaluate | Integration point |
|----------|---------------------|-------------------|
| Guardrails | protectai/llm-guard, NVIDIA/NeMo-Guardrails, guardrails-ai | Python scanner plugin |
| Red team | NVIDIA/garak, Azure/PyRIT | detector/scorer plugin |
| Gateway | BerriAI/litellm, Kong AI gateway, Envoy AI gateway, Portkey | middleware / Wasm filter |
| Rust-native | shuttle/rig-style agent frameworks, llm-chain | crate dependency, Stage-0 normalizer |
