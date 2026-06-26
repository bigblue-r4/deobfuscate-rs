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

## Passes

15 sequential passes in pipeline order. Each fires independently; detections accumulate.

| Pass | Detects | Example |
|------|---------|---------|
| `PreScanNfc` | Unicode NFD composed sequences | Ä (decomposed) → Ä (NFC) |
| `InvisibleStrip` | Variation selectors, tag block (U+E0000–E007F) | U+FE0F stripped |
| `CjkSuperposition` ⚠ | Forward/reverse CJK entropy spike — injection seam. **HALT**: text cleared. | Mixed CJK+Latin injection |
| `BiDiControl` | Invisible RTL/LTR override chars (U+202E, U+200B, …) | `"ignore\u{202E}all"` → `"ignoreall"` |
| `FullwidthChars` | East-Asian fullwidth ASCII (U+FF01–U+FF5E) | `ＰＷＮＥＤ` → `PWNED` |
| `BackslashEscape` | Per-character `\X` prefix-escaping | `\i\g\n\o\r\e` → `ignore` |
| `UrlEncoding` | Percent-encoded runs (≥ 3 consecutive `%XX`) with injection keyword | `%69%67%6e%6f%72%65` → `ignore` |
| `HtmlEntities` | Decimal, hex, named XML entities (≥ 4 entities + injection keyword) | `&#105;&#103;…` → `ignore` |
| `Base64` | Explicit `b64.decode("…")` and bare blobs (≥ 12 chars) | `aWdub3Jl` → `ignore` |
| `MorseCode` | ITU Morse spans ≥ 10 chars, ≥ 60% Morse, ≥ 40% letter decode | `.... .- -.-. -.-` → `HACK` |
| `Homoglyph` | 1,631-entry TR39 confusables: Cyrillic, Greek, Hebrew, Math/Script/Fraktur | `іgnοre` → `ignore` |
| `ScriptIntrusion` | Non-Latin char embedded inside a Latin word | `sy‌stem` (zero-width joiner) |
| `Leetspeak` | Digit/symbol substitutions in dense-leet tokens (≥ 35% leet) | `1337h4x0r` → `ieetaxor` |
| `EntropyBigram` | Shannon entropy > 5.2 bits OR English bigram coverage < 0.15 | High-entropy encoded blobs |
| `SplitString` | Injection keyword fragmented across separators — detection only | `ig.no.re` reconstructed as `ignore` |

> **⚠ HALT pass**: `CjkSuperposition` detects a forward/reverse Shannon entropy spike
> caused by embedding CJK characters to hide a Latin injection payload. When it fires,
> the text is **cleared** (not forwarded), and `was_halted` / `should_block()` are true.

---

## Scoring

`obfuscation_score` is a float in [0.0, 1.0], capped at 1.0.

| Pass | Weight |
|------|--------|
| CjkSuperposition | 1.00 (HALT) |
| BiDiControl | 0.90 |
| Base64 | 0.85 |
| BackslashEscape / MorseCode / UrlEncoding / HtmlEntities | 0.80 |
| InvisibleStrip | 0.75 |
| SplitString | 0.70 |
| FullwidthChars | 0.65 |
| Homoglyph | 0.55 |
| EntropyBigram | 0.50 |
| ScriptIntrusion | 0.40 |
| PreScanNfc | 0.35 |
| Leetspeak | 0.30 |

Default thresholds (configurable via [`Config`](#configuration)):
- `score >= 0.25` → **flag** (`should_flag()`)
- `score >= 0.60` → **block** (`should_block()`)

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

All thresholds and pass weights are runtime-configurable via `Config`. Load a partial
TOML — missing fields fall back to defaults.

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

// From file (returns Config::default() if file missing or unreadable)
let config = Config::from_file(Path::new("config.toml"));  // not available on wasm32

// From inline TOML string
let config = Config::from_toml("block_threshold = 0.90").unwrap();

// Struct literal with defaults
let config = Config { weight_homoglyph: 1.0, ..Config::default() };

let result = Normalizer::default()
    .with_config(config)
    .analyze(input);
```

Requires the `serde` feature (enabled by default). Disable with `default-features = false`
for a no-serde build. See [`examples/config.toml`](examples/config.toml) for the full
field reference.

---

## Result API

```rust
let r = deobfuscate::analyze(input);

r.normalized          // cleaned string — send this to your LLM
r.obfuscation_score   // f32 in [0.0, 1.0]
r.is_obfuscated()     // any detection fired?
r.should_flag()       // score >= flag_threshold (default 0.25)
r.should_block()      // score >= block_threshold (default 0.60)
r.summary()           // "score=0.80  detections=[morse-code]"
r.detection_kinds()   // Vec<PassKind>, deduplicated
r.detections          // Vec<Detection> — full detail per event
    .kind             //   PassKind
    .original         //   obfuscated span
    .normalized       //   replacement
    .detail           //   human description
```

---

## WebAssembly

The `wasm` feature exposes a thin JS-callable API for in-browser use.

```bash
wasm-pack build --target web --features wasm --no-default-features
```

```js
import init, { analyze_text, should_block, score } from './pkg/deobfuscate.js';
await init();

const result = analyze_text(userInput);
if (result.should_block) {
    console.error('blocked:', result.summary);
} else {
    sendToLLM(result.normalized);
}
```

See [`wasm/README.md`](wasm/README.md) and [`wasm/example.html`](wasm/example.html).

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

Remaining 13 are semantic attacks (jailbreak framing, acronym substitution,
multi-hop reasoning) — these require LLM-level reasoning, not structural normalization.

Zero false positives on benign text (NIST references, code snippets, CLI flags,
version numbers).

---

## Roadmap

| Pass | Detects |
|------|---------|
| `Rot13` | Caesar-13 substitution in all-alpha tokens |
| `UnicodeEscape` | `ignore`, `\x69gnore` JS/Python escape sequences |
| `Punycode` | IDN `xn--` encoded hostnames embedded in text |

API improvements planned:
- `no_std` mode (drop filesystem deps, embed decoder)
- Per-token confidence scores

---

## Origin

Extracted from [split-brain-harness](https://github.com/bigblue-r4/split-brain-harness),
an LLM security telemetry proxy built for DHS SBIR evaluation. The normalizer
runs as Stage 0 before a two-stage LLM propose+verify pipeline.

---

## License

MIT — see [LICENSE](LICENSE).
