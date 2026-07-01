# Changelog

All notable changes to `deobfuscate` are documented here.

---

## [1.15.0] — 2026-07-01

### Added
- Adversarial corpus benchmark — `tests/corpus/{adversarial,benign}.jsonl` (24 attack samples across all 19 pass categories, 21 benign hard cases: git SHAs, UUIDs, shell commands, Japanese/French/German prose, math notation, emoji). `cargo run --example corpus_eval` prints the per-category breakdown; `tests/corpus_eval.rs` enforces 100% detection / 0 false positives in CI
- `cargo-fuzz` harness — `fuzz/` with two targets: `analyze` (scoring invariants) and `config_toml` (TOML round-trip); 60s-per-target smoke job added to CI

### Fixed
- **UTF-8 boundary panic** (found by fuzzing) — `DetectionRecord` detail truncation sliced at byte 200 regardless of char boundaries, panicking on multi-byte UTF-8
- **`SplitString` flagged nearly all English prose** — the greedy subsequence matcher allowed arbitrary gaps between keyword letters, so keyword letters scattered across ordinary words always matched. Keywords must now be contiguous in the alpha skeleton (the actual `ig.no.re` attack shape). This was the dominant false-positive source (benign corpus went from 90% FP to 0%)
- **`CjkSuperposition` HALTed normal Japanese** — CJK punctuation (`。`, `、`, U+3000–303F) was classified as a foreign script zone, creating a fake injection seam in ordinary CJK prose
- **`Rot13` fired on plain English** — a keyword already present verbatim in the original text (e.g. "system") counted as evidence after unrelated tokens were rot13'd; the keyword must now appear *because of* decoding
- **`EntropyBigram` flagged normal English words** — the 30-entry bigram table scored words like "Thursday" below the English-coverage threshold; expanded to ~130 entries. Hex identifiers (git SHAs, UUIDs) and shell/path-shaped tokens are now skipped
- **`Leetspeak` de-leeted hex identifiers** — git SHAs and UUIDs met the leet-density threshold and were rewritten into garbage, cascading into downstream passes; pure hex/UUID tokens are now skipped
- **`Homoglyph`/`ScriptIntrusion` fired on standalone foreign letters** — a lone Greek `α` in math prose was "confusable" and `(α)` counted its parentheses as an ASCII word. Confusables now only count in attack-shaped tokens (mixed with ASCII alphanumerics, or entirely confusable); intrusion requires ≥2 ASCII alphanumerics in the word

---

## [1.14.0] — 2026-06-30

### Added
- `SkeletonMatch` pass (weight 0.75) — applies the Unicode TR39 skeleton algorithm via `unicode_skeleton` crate; fires when the skeleton of the input text reveals an injection keyword not present in the original, indicating cross-script confusable substitution
- `unicode-security` crate dependency — exposes `is_potential_mixed_script_confusable_char(c)` for per-character annotation in detection details
- `Config::weight_skeleton_match` — configurable weight for the new pass (default 0.75)
- Three-tier confusable defense: static HOMOGLYPHS table (Tier 1) → script-intrusion interference (Tier 2) → TR39 skeleton algorithm (Tier 3), addressing the 793 confusable-vision pairs that TR39 covers beyond the HOMOGLYPHS table
- 4 new unit tests for `SkeletonMatch` pass (Cyrillic/Greek confusables, Fraktur math chars, clean ASCII no-fire, disabled pass)

### Changed
- `Normalizer::default()` now includes `SkeletonMatch` in the enabled pass set (19 passes total)
- Integration test `analyze_clean_text_returns_zero_score` uses a keyword-free input to avoid SplitString false positives on text with scattered common letters

---

## [1.13.0] — 2026-06-26

### Added
- `AuditRecord::sign(key: &[u8])` — HMAC-SHA256 signs the record, storing the hex digest in `signature`
- `AuditRecord::verify(key: &[u8]) -> bool` — verifies the signature; returns `false` if tampered
- `AuditRecord::prev_hmac` field — include the previous record's signature before signing to create a verifiable chain; altering this field after signing is detected by `verify`
- `AuditRecord::signature` field — set by `sign`, included in serialized JSON

---

## [1.12.0] — 2026-06-26

### Added
- `Detection::confidence() -> f32` — blended base + structural confidence score in [0.0, 1.0]
  - Base score comes from the pass weight (e.g. 1.0 for CjkSuperposition HALT, 0.30 for Leetspeak)
  - Structural boost applied for decode success rate, change ratio, and keyword presence
  - HALT pass always returns 1.0; detection-only passes (ScriptIntrusion, SplitString) return base weight
- `DetectionRecord::confidence` field — confidence propagated into audit JSON output

---

## [1.11.0] — 2026-06-25

### Added
- `Punycode` pass (weight 0.85) — decodes IDN `xn--` labels via RFC 3492; fires when decoded text contains an injection keyword after confusable normalization

---

## [1.10.0] — 2026-06-25

### Added
- `Rot13` pass (weight 0.80) — detects Caesar-13 substitution in all-alpha tokens (≥ 4 chars); fires when decoded text contains an injection keyword

---

## [1.9.0] — 2026-06-25

### Added
- `audit` feature (enabled by default) — attaches a `AuditRecord` to every `NormalizationResult`
- `AuditRecord` — SHA-256 hex of raw input, char length, RFC 3339 UTC timestamp, score, blocked/halted flags, per-detection metadata; **no raw strings stored**
- `DetectionRecord` — lengths-only per-detection record (original_len, normalized_len, pass name, detail capped at 200 chars)
- `NormalizationResult::audit_jsonl()` — serializes audit record as a single JSONL line
- `NormalizationResult::audit_json_pretty()` — pretty-printed JSON for debugging
- `AuditRecord::append_jsonl(path)` — appends JSONL record to a file (non-wasm32 only)

---

## [1.8.0] — 2026-06-25

### Added
- `UnicodeEscape` pass (weight 0.80) — decodes `\xNN` hex bytes, `\uNNNN` BMP codepoints, `\u{N}` extended codepoints, and octal char escapes

---

## [1.7.0] — 2026-06-25

### Added
- `wasm` feature — thin wasm-bindgen JS-callable API (`analyze_text`, `should_block`, `score`)
- `src/wasm.rs` — WASM target entry points returning JS-compatible structs
- `wasm/example.html` — self-contained browser demo (no build step required)
- `wasm/README.md` — wasm-pack build instructions and JS/TS API reference
- CI workflow (`.github/workflows/ci.yml`) — test, wasm check, clippy on every push/PR

---

## [1.6.0] — 2026-06-25

### Added
- `SplitString` pass (weight 0.70) — detects injection keywords fragmented across separators via alpha skeleton reconstruction; detection only (does not normalize text)
- `INJECTION_KEYWORDS` expanded from 15 to 30 entries

---

## [1.5.0] — 2026-06-25

### Added
- `Config` struct — all 28 thresholds and pass weights are runtime-configurable
- `Config::from_toml(s: &str)` — partial TOML deserialization (missing fields fall back to defaults); requires `serde` feature
- `Config::from_file(path: &Path)` — loads from file, returns `Config::default()` if missing or unreadable; non-wasm32 only
- `Normalizer::with_config(config)` builder method
- `examples/config.toml` — annotated TOML reference for all 28 fields

---

## [1.4.0] — 2026-06-25

### Added
- `UrlEncoding` pass (weight 0.80) — detects and decodes percent-encoded runs (≥ 3 consecutive `%XX` bytes) containing an injection keyword
- `HtmlEntities` pass (weight 0.80) — detects and decodes decimal, hex, and named XML entities (≥ 4 entities) containing an injection keyword

---

## [1.3.0] — 2026-06-25

### Added
- `EntropyBigram` pass (weight 0.50) — flags high-entropy blobs via Shannon entropy (> 5.2 bits) or abnormally low English bigram coverage (< 0.15)

---

## [1.2.0] — 2026-06-25

### Added
- `PreScanNfc` pass (weight 0.35) — Layer 1 pre-scan; NFC normalization of composed Unicode sequences
- `InvisibleStrip` pass (weight 0.75) — Layer 1; removes variation selectors and tag block codepoints (U+E0000–E007F)
- `HOMOGLYPHS` table expanded from 51 to 1,631 entries — full TR39 ASCII-target confusables subset (Cyrillic, Greek, Hebrew, Arabic, Math/Script/Fraktur)

---

## [1.1.0] — 2026-06-25

### Added
- `CjkSuperposition` HALT pass (weight 1.0) — detects forward/reverse Shannon entropy spike caused by embedding CJK characters to hide a Latin injection payload; when fired, text is **cleared** and `was_halted` / `should_block()` are true

---

## [1.0.0] — 2026-06-24

### Added
- Initial release: 7-pass pipeline — `BiDiControl`, `FullwidthChars`, `BackslashEscape`, `Base64`, `MorseCode`, `Homoglyph`, `Leetspeak`, `ScriptIntrusion`
- `analyze(input: &str) -> NormalizationResult` — single-call entry point
- `Normalizer` builder API — `enable()` / `disable()` per pass, `new()` (empty) vs `default()` (all passes)
- `NormalizationResult` — `normalized`, `detections`, `obfuscation_score`, `should_flag()`, `should_block()`, `summary()`, `detection_kinds()`
- `Detection` — `kind`, `original`, `normalized`, `detail` per obfuscation event
- `PassKind` enum for all passes
