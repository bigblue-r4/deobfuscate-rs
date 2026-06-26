# deobfuscate-rs — Development Progress

> Load this file at the start of a Claude session to get full project context.
> Path: `/home/evillab/Desktop/deobfuscate-rs/`

---

## Project Identity

| Field | Value |
|-------|-------|
| Crate name | `deobfuscate` |
| License | MIT |
| crates.io | https://crates.io/crates/deobfuscate |
| GitHub | https://github.com/bigblue-r4/deobfuscate-rs |
| Current version | **v1.9.0** |
| Test count | **86 unit tests + 2 doc tests** — all green |
| Source file | Single file: `src/lib.rs` (~4,100 lines) + `src/wasm.rs` |

---

## What It Is

A standalone Rust library crate that runs **before any LLM call** to detect and
neutralize encoding-evasion attacks in prompt text. Attackers encode injection
payloads (base64, Morse, homoglyphs, etc.) to bypass naive content classifiers;
this crate strips and reconstructs the payload, returning both cleaned text and
a structured detection report.

Originally extracted from `split-brain-harness` (Stage 0 normalizer), now a
standalone published crate used directly by Harborlight and available to the OSS
community.

---

## Version History

| Version | Date | What was added | Tests |
|---------|------|----------------|-------|
| v1.0.0 | 2026-06-25 | Initial publish — 7 passes (BiDi, Fullwidth, Backslash, Base64, Morse, Homoglyph, Leet, Script) | 26 |
| v1.1.0 | 2026-06-25 | CjkSuperposition HALT pass | +5 → 31 |
| v1.2.0 | 2026-06-25 | Layer 1: PreScanNfc + InvisibleStrip; HOMOGLYPHS 51 → 1,631 entries (full TR39) | +8 → 39 |
| v1.3.0 | 2026-06-25 | EntropyBigram pass | +6 → 45 |
| v1.4.0 | 2026-06-25 | UrlEncoding + HtmlEntities passes | +6 → 51 |
| v1.5.0 | 2026-06-25 | Config struct — all 28 thresholds/weights runtime-configurable via TOML | +7 → 58 |
| v1.6.0 | 2026-06-25 | SplitString pass; INJECTION_KEYWORDS expanded 15 → 30 | +7 → 65 |
| v1.7.0 | 2026-06-25 | WASM target (wasm feature); audit feature + sha2; cdylib+rlib; README overhaul; CI workflow | +0 → 65 |
| v1.8.0 | 2026-06-25 | UnicodeEscape pass — \xNN, \uNNNN, \u{N}, octal char escapes decoded | +10 → 75 |
| v1.9.0 | 2026-06-25 | Audit feature — SHA-256 hash, timestamp, payload-free JSONL per call | +11 → 86 |

---

## All 15 Passes — Current Status

### Pipeline order (top = runs first)

| # | Pass | Status | Weight | Notes |
|---|------|--------|--------|-------|
| 1 | `PreScanNfc` | ✅ Complete | 0.35 | Layer 1 pre-scan; NFC normalization |
| 2 | `InvisibleStrip` | ✅ Complete | 0.75 | Variation selectors + tag block (U+E0000–E007F) |
| 3 | `CjkSuperposition` | ✅ Complete | 1.00 | **HALT pass** — entropy spike detection; clears text |
| 4 | `BiDiControl` | ✅ Complete | 0.90 | RTL/LTR override + zero-width chars |
| 5 | `FullwidthChars` | ✅ Complete | 0.65 | U+FF01–FF5E fullwidth ASCII → ASCII |
| 6 | `BackslashEscape` | ✅ Complete | 0.80 | `\X` per-char prefix escaping (≥3 backslashes) |
| 7 | `UrlEncoding` | ✅ Complete | 0.80 | Percent-encoded runs ≥3 + keyword check |
| 8 | `HtmlEntities` | ✅ Complete | 0.80 | Decimal/hex/named entities ≥4 + keyword check |
| 9 | `Base64` | ✅ Complete | 0.85 | Explicit `b64.decode()` + bare blobs ≥12 chars |
| 10 | `MorseCode` | ✅ Complete | 0.80 | ITU Morse ≥10 chars, ≥60% Morse, ≥40% letter decode |
| 11 | `Homoglyph` | ✅ Complete | 0.55 | 1,631-entry TR39: Cyrillic, Greek, Hebrew, Arabic, Math |
| 12 | `ScriptIntrusion` | ✅ Complete | 0.40 | Non-Latin mid-word embedding (detection only) |
| 13 | `Leetspeak` | ✅ Complete | 0.30 | ≥35% leet substitution + ≥2 alpha chars |
| 14 | `EntropyBigram` | ✅ Complete | 0.50 | Shannon entropy >5.2 OR English bigram <0.15 |
| 15 | `SplitString` | ✅ Complete | 0.70 | Keyword fragmentation via alpha skeleton (detection only) |

**Not yet implemented:**

| Pass | What it would catch | Priority |
|------|---------------------|----------|
| `Rot13` | Caesar-13 substitution | Medium |
| `Punycode` | IDN `xn--` hostnames embedded in text | Low |

### Audit feature

`AuditRecord` and `DetectionRecord` attached to every `NormalizationResult` (feature = "audit", default on).
- SHA-256 hex of raw input computed BEFORE any normalization
- Manual RFC 3339 UTC timestamp (Howard Hinnant civil_from_days — no chrono dep)
- Empty timestamp on wasm32
- `append_jsonl(path)` helper for append-only SIEM logs
- 11 tests: hash stability, halt-path coverage, payload isolation, round-trip JSON, known-timestamp values

---

## Architecture

### Source layout

```
src/
  lib.rs        — all 15 passes, Config, Normalizer, types, 65 unit tests
  wasm.rs       — wasm-bindgen JS API (analyze_text, should_block, score)
wasm/
  README.md     — wasm-pack build instructions + JS/TS API docs
  example.html  — self-contained browser demo
examples/
  config.toml   — annotated TOML reference for all 28 Config fields
.github/
  workflows/
    ci.yml      — CI: cargo test, wasm32 check, clippy
```

### Key types

```rust
// Entry point (default config, all passes)
pub fn analyze(input: &str) -> NormalizationResult

// Builder (selective passes, custom config)
Normalizer::default()
    .disable(PassKind::Leetspeak)
    .with_config(Config { weight_homoglyph: 1.0, ..Config::default() })
    .analyze(input)

// Result
NormalizationResult {
    normalized: String,       // cleaned text — send to LLM
    detections: Vec<Detection>,
    obfuscation_score: f32,   // 0.0–1.0
    flag_threshold: f32,      // from active Config
    block_threshold: f32,     // from active Config
}
// Methods: .should_flag(), .should_block(), .is_obfuscated(), .summary(), .detection_kinds()

// Config — all 28 fields runtime-configurable
Config::default()                       // all defaults
Config::from_toml(s: &str)              // partial TOML string (serde feature)
Config::from_file(path: &Path)          // file, fallback to default (non-wasm32, serde feature)
```

### Feature flags

| Feature | Default | What it enables |
|---------|---------|-----------------|
| `serde` | yes | Config TOML deserialization; `from_toml()`, `from_file()` |
| `audit` | yes | `AuditRecord` + `DetectionRecord`; sha2 hash; serde_json JSONL methods |
| `wasm`  | no  | wasm-bindgen + js-sys; JS callable API in src/wasm.rs |

### WASM API (wasm feature)

```bash
wasm-pack build --target web --features wasm --no-default-features
```

```js
const result = analyze_text(input);
// → { normalized, obfuscation_score, is_obfuscated, should_flag,
//     should_block, was_halted, summary, passes_fired: string[] }
```

---

## Config — All 28 Configurable Fields

| Field | Default | What it controls |
|-------|---------|-----------------|
| `flag_threshold` | 0.25 | `should_flag()` cutoff |
| `block_threshold` | 0.60 | `should_block()` cutoff |
| `cjk_super_window` | 6 | CJK entropy window size |
| `cjk_super_threshold` | 0.55 | Entropy spike threshold |
| `cjk_super_min_cjk_frac` | 0.40 | Min CJK fraction to run the pass |
| `morse_min_span` | 10 | Min chars for Morse span |
| `morse_min_morse_pct` | 60 | Min % Morse chars |
| `base64_min_len` | 12 | Min chars for bare base64 blob |
| `leet_min_alpha` | 4 | Min alpha chars in leet token |
| `leet_min_pct` | 35 | Min % substitution rate |
| `entropy_high` | 5.2 | Shannon entropy high threshold (bits) |
| `entropy_min_english` | 0.15 | English bigram coverage low threshold |
| `url_min_run` | 3 | Min consecutive %XX bytes |
| `html_min_entities` | 4 | Min entities before HTML pass fires |
| `weight_bidi` | 0.90 | Score weight for BiDiControl |
| `weight_base64` | 0.85 | Score weight for Base64 |
| `weight_backslash` | 0.80 | Score weight for BackslashEscape |
| `weight_morse` | 0.80 | Score weight for MorseCode |
| `weight_url` | 0.80 | Score weight for UrlEncoding |
| `weight_html` | 0.80 | Score weight for HtmlEntities |
| `weight_invisible` | 0.75 | Score weight for InvisibleStrip |
| `weight_split_string` | 0.70 | Score weight for SplitString |
| `weight_fullwidth` | 0.65 | Score weight for FullwidthChars |
| `weight_homoglyph` | 0.55 | Score weight for Homoglyph |
| `weight_entropy` | 0.50 | Score weight for EntropyBigram |
| `weight_script` | 0.40 | Score weight for ScriptIntrusion |
| `weight_nfc` | 0.35 | Score weight for PreScanNfc |
| `weight_leet` | 0.30 | Score weight for Leetspeak |

---

## Injection Keywords (30 entries)

```
ignore, disregard, bypass, system prompt, instruction, pwned, whoami, exec, eval,
import, os.system, child_process, shell, bash, powershell, system, prompt, override,
jailbreak, forget, reset, sudo, admin, root, chmod, curl, wget, python, javascript, script
```

Used by: `UrlEncoding`, `HtmlEntities`, `Base64`, `SplitString`

---

## Benchmark Results

**CyberEC dataset** (141 rows, 26 encoding-evasion false negatives from a raw LLM classifier):

| Category | Count | Caught |
|----------|-------|--------|
| Unicode homoglyphs (Cyrillic/Greek) | 4 | ✅ all |
| Backslash-escaped text | 3 | ✅ all |
| Leetspeak | 3 | ✅ all |
| Morse code | 1 | ✅ |
| Base64 | 1 | ✅ |
| Fullwidth Unicode | 1 | ✅ |
| **Total** | **13 / 26** | **50%** |

Remaining 13 = semantic attacks (jailbreak framing, multi-hop reasoning) — require LLM reasoning, not structural normalization. **Zero false positives** on benign text (NIST references, code snippets, CLI flags, version numbers).

---

## Known Issues / Fails / Limitations

| Item | Status | Notes |
|------|--------|-------|
| `SplitString` greedy skeleton can false-positive on verbatim keywords | Fixed v1.6.0 | Verbatim pre-check (`lower_text.contains(keyword)`) prevents this |
| `Config::from_file` not available on wasm32 | By design | Gated `#[cfg(not(target_arch = "wasm32"))]` |
| No `no_std` support | Open | Would need to drop filesystem deps and embed base64 decoder |
| Audit detail strings may embed decoded snippets | By design | Truncated to 200 chars in DetectionRecord; raw input never stored |
| `SplitString` detection-only (does not normalize text) | By design | Keyword fragments can't be safely removed without semantic context |
| Semantic attacks (DAN jailbreaks, roleplay framing) | Out of scope | Require LLM-level reasoning; handled by Stage 1 in split-brain-harness |
| Rot13, Punycode passes | Not implemented | On roadmap |

---

## CI Status

`.github/workflows/ci.yml` — three jobs on every push/PR to master:

| Job | Command | Status |
|-----|---------|--------|
| Test (stable) | `cargo test --all-features` + `cargo test --no-default-features` | Added v1.7.0 |
| WASM check | `cargo check --target wasm32-unknown-unknown --features wasm --no-default-features` | Added v1.7.0 |
| Clippy | `cargo clippy --all-features -- -D warnings` | Added v1.7.0 |

---

## Relationship to Other Projects

| Project | Relationship |
|---------|-------------|
| `split-brain-harness` | Origin — this crate was extracted from its Stage 0 normalizer |
| `unicode-interference` | Sibling crate (separate repo) — homoglyph detection via forward/reverse interference patterns |
| Harborlight | Primary consumer — deobfuscate runs as Stage 0 in the LLM security pipeline |
| DHS SBIR Phase 1 | This crate is demo-able evidence of the normalizer capability (~$300K funding target) |

---

## Next Session Starting Points

1. **`Rot13` pass** — detect Caesar-13 in all-alpha tokens. Low complexity, adds coverage.
2. **Per-token confidence scores** — each Detection gets a `confidence: f32` based on decode success rate, match purity, and token length.
3. **`audit` HMAC signing** — add HMAC-SHA256 signature to AuditRecord for tamper-evident log chaining.
4. **Publish GitHub releases v1.1.0–v1.6.0** — only v1.0.0 and v1.7.0 have releases; the intermediate versions are missing.
