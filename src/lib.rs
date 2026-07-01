//! # deobfuscate
//!
//! Multi-pass text deobfuscation and encoding-evasion detector.
//!
//! Designed for LLM security pipelines where attackers encode or obfuscate
//! prompt-injection payloads to evade content classifiers. Run this before
//! any LLM call — the returned [`NormalizationResult`] gives you both a
//! cleaned string to send to the model and a structured report of what was
//! found.
//!
//! ## Quick start
//!
//! ```rust
//! use deobfuscate::{Normalizer, PassKind};
//!
//! // Default: all passes enabled
//! let result = Normalizer::default().analyze("Execute: .... .- -.-. -.-");
//! if result.is_obfuscated() {
//!     println!("score={:.2} — {}", result.obfuscation_score, result.summary());
//!     // Send result.normalized to your LLM
//! }
//! ```
//!
//! ## Passes (v1)
//!
//! | Pass | What it catches | Example |
//! |------|----------------|---------|
//! | `BiDiControl` | Invisible RTL/LTR override chars | U+202E hidden in command |
//! | `FullwidthChars` | East-Asian fullwidth ASCII | `ＰＷＮＥＤ` → `PWNED` |
//! | `BackslashEscape` | `\X` prefix-escaping of every char | `\i\g\n\o\r\e` → `ignore` |
//! | `Base64` | Explicit `b64.decode(…)` and bare base64 blobs | `SSBpZ25vcmU=` → `I ignore` |
//! | `MorseCode` | ITU Morse spans ≥ 10 chars | `.... .- -.-. -.-` → `HACK` |
//! | `Homoglyph` | Cyrillic/Greek look-alikes | `іgnοre` → `ignore` |
//! | `ScriptIntrusion` | Non-Latin char embedded inside Latin word | detected, not replaced |
//! | `Leetspeak` | Digit/symbol substitutions in dense-leet tokens | `1337h4x0r` → `ieetaxor` |
//!
//! ## Scoring
//!
//! Each detection kind contributes a fixed weight to `obfuscation_score` (capped at 1.0):
//!
//! | Kind | Weight |
//! |------|--------|
//! | BiDiControl | 0.90 |
//! | Base64 | 0.85 |
//! | BackslashEscape / MorseCode | 0.80 |
//! | FullwidthChars | 0.65 |
//! | Homoglyph | 0.55 |
//! | ScriptIntrusion | 0.40 |
//! | Leetspeak | 0.30 |
//!
//! Thresholds: `score >= 0.25` → flag for review; `score >= 0.60` → block / stop-and-ask.

mod audit;
mod config;
mod normalizer;
mod passes;
mod tables;
#[cfg(test)]
mod tests;
mod types;

#[cfg(feature = "audit")]
pub use audit::{AuditRecord, DetectionRecord};
pub use config::Config;
pub use normalizer::{analyze, Normalizer};
pub use types::{Detection, NormalizationResult, PassKind};

#[cfg(feature = "wasm")]
pub mod wasm;
