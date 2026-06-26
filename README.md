# deobfuscate

Multi-pass text deobfuscation and encoding-evasion detector for Rust.

Built for LLM security pipelines where attackers encode prompt-injection payloads
to evade content classifiers. Run this **before** any LLM call: it returns cleaned
text for the model and a structured detection report for your audit trail.

[![MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![crates.io](https://img.shields.io/crates/v/deobfuscate.svg)](https://crates.io/crates/deobfuscate)

---

## Quick start

```toml
[dependencies]
deobfuscate = "1"
```

```rust
use deobfuscate::analyze;

let result = analyze("Execute: .... .- -.-. -.-");
if result.should_block() {
    // score >= 0.60 — stop and ask / block
    eprintln!("blocked: {}", result.summary());
} else if result.should_flag() {
    // score >= 0.25 — flag for review, send normalized to model
    send_to_model(&result.normalized);
}
```

---

## Passes (v1)

Seven sequential passes. Each fires independently; all detections are cumulative.

| Pass | Detects | Example |
|------|---------|---------|
| `BiDiControl` | Invisible RTL/LTR override chars (U+202E, U+200B, …) | `"ignore\u{202E}all"` |
| `FullwidthChars` | East-Asian fullwidth ASCII block (U+FF01–U+FF5E) | `ＰＷＮＥＤ` → `PWNED` |
| `BackslashEscape` | `\X` prefix-escaping of runs of characters | `\i\g\n\o\r\e` → `ignore` |
| `Base64` | Explicit `b64.decode(…)` calls and bare base64 blobs | `SSBp…cw==` → `I ignore all…` |
| `MorseCode` | ITU Morse spans ≥ 10 chars (≥ 60% Morse chars) | `.... .- -.-. -.-` → `HACK` |
| `Homoglyph` | Cyrillic/Greek/Armenian/Hebrew/Math look-alike → ASCII (1,631 mappings, TR39) | `іgnοre` → `ignore` |
| `ScriptIntrusion` | Non-Latin char embedded mid-word (structural detection) | `sy​stem` (Meitei mid-word) |
| `Leetspeak` | Digit/symbol substitution in dense-leet tokens | `1337h4x0r` → `ieetaxor` |

---

## Scoring

`obfuscation_score` is a float in [0.0, 1.0], capped at 1.0.

| Kind | Weight |
|------|--------|
| BiDiControl | 0.90 |
| Base64 | 0.85 |
| BackslashEscape, MorseCode | 0.80 |
| FullwidthChars | 0.65 |
| Homoglyph | 0.55 |
| ScriptIntrusion | 0.40 |
| Leetspeak | 0.30 |

Default thresholds (configurable via [`Config`](#configuration)):
- `score >= 0.25` → **flag** (`should_flag()` — log alert, verification fail)
- `score >= 0.60` → **block** (`should_block()` — stop-and-ask, halt request)

---

## Builder API

By default all passes are enabled. Selectively enable or disable:

```rust
use deobfuscate::{Normalizer, PassKind};

// All passes except Morse:
let r = Normalizer::default()
    .disable(PassKind::MorseCode)
    .analyze(input);

// Only homoglyph + leet:
let r = Normalizer::new()
    .enable(PassKind::Homoglyph)
    .enable(PassKind::Leetspeak)
    .analyze(input);
```

---

## Configuration

All thresholds and pass weights are runtime-configurable via a `Config` struct. Load a partial TOML file — missing fields fall back to defaults.

```toml
# config.toml
flag_threshold  = 0.25
block_threshold = 0.60

# tighten homoglyph weight for high-sensitivity deployments
weight_homoglyph = 0.70

# relax leet for gaming contexts where 1337 is normal
weight_leet  = 0.10
leet_min_pct = 60
```

```rust
use deobfuscate::{Config, Normalizer};
use std::path::Path;

// From file (returns Config::default() if file missing)
let config = Config::from_file(Path::new("config.toml"));

// From inline TOML string
let config = Config::from_toml("block_threshold = 0.90").unwrap();

// Inline struct override
let config = Config { weight_homoglyph: 1.0, ..Config::default() };

let result = Normalizer::default()
    .with_config(config)
    .analyze(input);
```

`Config` requires the `serde` feature (enabled by default). Disable with `default-features = false` for a no-serde build.

See [`examples/config.toml`](examples/config.toml) for the full field list with comments.

---

## Result API

```rust
let r = deobfuscate::analyze(input);

r.normalized          // cleaned string — send this to your LLM
r.obfuscation_score   // f32 in [0.0, 1.0]
r.is_obfuscated()     // any detection fired?
r.should_flag()       // score >= 0.25
r.should_block()      // score >= 0.60
r.summary()           // "score=0.80  detections=[morse-code]"
r.detection_kinds()   // Vec<PassKind>, deduplicated
r.detections          // Vec<Detection> — full detail per event
    .kind             //   PassKind
    .original         //   obfuscated span
    .normalized       //   replacement
    .detail           //   human description
```

---

## Benchmark (CyberEC adversarial dataset, 141 rows)

Against the 26 false-negative cases from the CyberEC prompt-injection dataset
(attacks that evade a raw LLM classifier):

| Category | Count | Caught |
|----------|-------|--------|
| Unicode homoglyphs (Cyrillic/Greek) | 4 | ✓ all |
| Backslash-escaped text | 3 | ✓ all |
| Leetspeak (mixed alpha) | 3 | ✓ all |
| Morse code | 1 | ✓ |
| Base64 | 1 | ✓ |
| Fullwidth Unicode | 1 | ✓ |
| **Total** | **13 / 26** | **50%** |

Remaining 13 are semantic attacks (jailbreak framing, split-string, acronym
substitution) — these require LLM-level reasoning, not structural normalization.

Zero false positives on benign text (NIST references, code snippets, CLI flags,
version numbers).

---

## v2 Roadmap

Planned additions — contributions welcome:

### New passes
| Pass | Detects |
|------|---------|
| `UrlEncoding` | `%69%67%6E%6F%72%65` → `ignore` |
| `HtmlEntities` | `&#105;&#103;&#110;&#111;&#114;&#101;` → `ignore` |
| `ZeroWidth` | U+FEFF, U+200B, U+2060, U+E0000–U+E007F tag block |
| `Rot13` | Simple Caesar-13 substitution in all-alpha tokens |
| `UnicodeEscape` | `ignore`, `\x69gnore` JavaScript/Python escape sequences |
| `Punycode` | IDN punycode `xn--` encoded hostnames embedded in text |

### Improved math
- **Entropy scoring**: Shannon entropy spike detection for encoded spans
  (base64 and Morse both have distinctive entropy profiles)
- **Bigram language model**: English character bigram log-probability score;
  obfuscated text scores abnormally low even after decoding
- **Script mixing ratio**: fraction of non-dominant-script chars as a continuous
  feature rather than a binary intrusion flag
- **Per-token confidence**: each detection gets a confidence score based on
  purity, length, and decode success rate

### API improvements
- `serde` feature for `Detection` and `NormalizationResult`
- WASM target (`wasm32-unknown-unknown`) for in-browser use
- Async streaming API for large documents
- `no_std` mode (drop base64 dep, embed decoder)

---

## Origin

Extracted from [split-brain-harness](https://github.com/bigblue-r4/split-brain-harness),
an LLM security telemetry proxy built for DHS SBIR evaluation. The normalizer
runs as Stage 0 before a two-stage LLM propose+verify pipeline.

---

## License

MIT — see [LICENSE](LICENSE).
