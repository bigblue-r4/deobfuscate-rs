//! Runtime-configurable thresholds and pass weights.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

// ─────────────────────────────────────────────────────────────────────────────
// Config — runtime-configurable thresholds and weights
// ─────────────────────────────────────────────────────────────────────────────

// Default values — used by Config::default() and as named constants throughout.
pub(crate) const DEFAULT_FLAG_THRESHOLD: f32 = 0.25;
pub(crate) const DEFAULT_BLOCK_THRESHOLD: f32 = 0.60;
pub(crate) const DEFAULT_CJK_SUPER_WINDOW: usize = 6;
pub(crate) const DEFAULT_CJK_SUPER_THRESHOLD: f32 = 0.55;
pub(crate) const DEFAULT_CJK_SUPER_MIN_CJK_FRAC: f32 = 0.40;
pub(crate) const DEFAULT_MORSE_MIN_SPAN: usize = 10;
pub(crate) const DEFAULT_MORSE_MIN_MORSE_PCT: usize = 60;
pub(crate) const DEFAULT_BASE64_MIN_LEN: usize = 12;
pub(crate) const DEFAULT_LEET_MIN_ALPHA: usize = 4;
pub(crate) const DEFAULT_LEET_MIN_PCT: usize = 35;
pub(crate) const DEFAULT_ENTROPY_HIGH: f32 = 5.2;
pub(crate) const DEFAULT_ENTROPY_MIN_ENGLISH: f32 = 0.15;
pub(crate) const DEFAULT_URL_MIN_RUN: usize = 3;
pub(crate) const DEFAULT_HTML_MIN_ENTITIES: usize = 4;
pub(crate) const DEFAULT_WEIGHT_BIDI: f32 = 0.90;
pub(crate) const DEFAULT_WEIGHT_BASE64: f32 = 0.85;
pub(crate) const DEFAULT_WEIGHT_BACKSLASH: f32 = 0.80;
pub(crate) const DEFAULT_WEIGHT_MORSE: f32 = 0.80;
pub(crate) const DEFAULT_WEIGHT_URL: f32 = 0.80;
pub(crate) const DEFAULT_WEIGHT_HTML: f32 = 0.80;
pub(crate) const DEFAULT_WEIGHT_INVISIBLE: f32 = 0.75;
pub(crate) const DEFAULT_WEIGHT_FULLWIDTH: f32 = 0.65;
pub(crate) const DEFAULT_WEIGHT_HOMOGLYPH: f32 = 0.55;
pub(crate) const DEFAULT_WEIGHT_ENTROPY: f32 = 0.50;
pub(crate) const DEFAULT_WEIGHT_SCRIPT: f32 = 0.40;
pub(crate) const DEFAULT_WEIGHT_NFC: f32 = 0.35;
pub(crate) const DEFAULT_WEIGHT_LEET: f32 = 0.30;
pub(crate) const DEFAULT_WEIGHT_SPLIT_STRING: f32 = 0.70;
pub(crate) const DEFAULT_WEIGHT_UNICODE_ESCAPE: f32 = 0.80;
pub(crate) const DEFAULT_WEIGHT_ROT13: f32 = 0.80;
pub(crate) const DEFAULT_WEIGHT_PUNYCODE: f32 = 0.85;
pub(crate) const DEFAULT_WEIGHT_SKELETON_MATCH: f32 = 0.75;

// Serde per-field default functions — only compiled with the `serde` feature.
#[cfg(feature = "serde")]
pub(crate) fn serde_flag_threshold() -> f32 {
    DEFAULT_FLAG_THRESHOLD
}
#[cfg(feature = "serde")]
pub(crate) fn serde_block_threshold() -> f32 {
    DEFAULT_BLOCK_THRESHOLD
}
#[cfg(feature = "serde")]
pub(crate) fn serde_cjk_super_window() -> usize {
    DEFAULT_CJK_SUPER_WINDOW
}
#[cfg(feature = "serde")]
pub(crate) fn serde_cjk_super_threshold() -> f32 {
    DEFAULT_CJK_SUPER_THRESHOLD
}
#[cfg(feature = "serde")]
pub(crate) fn serde_cjk_super_min_cjk_frac() -> f32 {
    DEFAULT_CJK_SUPER_MIN_CJK_FRAC
}
#[cfg(feature = "serde")]
pub(crate) fn serde_morse_min_span() -> usize {
    DEFAULT_MORSE_MIN_SPAN
}
#[cfg(feature = "serde")]
pub(crate) fn serde_morse_min_morse_pct() -> usize {
    DEFAULT_MORSE_MIN_MORSE_PCT
}
#[cfg(feature = "serde")]
pub(crate) fn serde_base64_min_len() -> usize {
    DEFAULT_BASE64_MIN_LEN
}
#[cfg(feature = "serde")]
pub(crate) fn serde_leet_min_alpha() -> usize {
    DEFAULT_LEET_MIN_ALPHA
}
#[cfg(feature = "serde")]
pub(crate) fn serde_leet_min_pct() -> usize {
    DEFAULT_LEET_MIN_PCT
}
#[cfg(feature = "serde")]
pub(crate) fn serde_entropy_high() -> f32 {
    DEFAULT_ENTROPY_HIGH
}
#[cfg(feature = "serde")]
pub(crate) fn serde_entropy_min_english() -> f32 {
    DEFAULT_ENTROPY_MIN_ENGLISH
}
#[cfg(feature = "serde")]
pub(crate) fn serde_url_min_run() -> usize {
    DEFAULT_URL_MIN_RUN
}
#[cfg(feature = "serde")]
pub(crate) fn serde_html_min_entities() -> usize {
    DEFAULT_HTML_MIN_ENTITIES
}
#[cfg(feature = "serde")]
pub(crate) fn serde_weight_bidi() -> f32 {
    DEFAULT_WEIGHT_BIDI
}
#[cfg(feature = "serde")]
pub(crate) fn serde_weight_base64() -> f32 {
    DEFAULT_WEIGHT_BASE64
}
#[cfg(feature = "serde")]
pub(crate) fn serde_weight_backslash() -> f32 {
    DEFAULT_WEIGHT_BACKSLASH
}
#[cfg(feature = "serde")]
pub(crate) fn serde_weight_morse() -> f32 {
    DEFAULT_WEIGHT_MORSE
}
#[cfg(feature = "serde")]
pub(crate) fn serde_weight_url() -> f32 {
    DEFAULT_WEIGHT_URL
}
#[cfg(feature = "serde")]
pub(crate) fn serde_weight_html() -> f32 {
    DEFAULT_WEIGHT_HTML
}
#[cfg(feature = "serde")]
pub(crate) fn serde_weight_invisible() -> f32 {
    DEFAULT_WEIGHT_INVISIBLE
}
#[cfg(feature = "serde")]
pub(crate) fn serde_weight_fullwidth() -> f32 {
    DEFAULT_WEIGHT_FULLWIDTH
}
#[cfg(feature = "serde")]
pub(crate) fn serde_weight_homoglyph() -> f32 {
    DEFAULT_WEIGHT_HOMOGLYPH
}
#[cfg(feature = "serde")]
pub(crate) fn serde_weight_entropy() -> f32 {
    DEFAULT_WEIGHT_ENTROPY
}
#[cfg(feature = "serde")]
pub(crate) fn serde_weight_script() -> f32 {
    DEFAULT_WEIGHT_SCRIPT
}
#[cfg(feature = "serde")]
pub(crate) fn serde_weight_nfc() -> f32 {
    DEFAULT_WEIGHT_NFC
}
#[cfg(feature = "serde")]
pub(crate) fn serde_weight_leet() -> f32 {
    DEFAULT_WEIGHT_LEET
}
#[cfg(feature = "serde")]
pub(crate) fn serde_weight_split_string() -> f32 {
    DEFAULT_WEIGHT_SPLIT_STRING
}
#[cfg(feature = "serde")]
pub(crate) fn serde_weight_unicode_escape() -> f32 {
    DEFAULT_WEIGHT_UNICODE_ESCAPE
}
#[cfg(feature = "serde")]
pub(crate) fn serde_weight_rot13() -> f32 {
    DEFAULT_WEIGHT_ROT13
}
#[cfg(feature = "serde")]
pub(crate) fn serde_weight_punycode() -> f32 {
    DEFAULT_WEIGHT_PUNYCODE
}
#[cfg(feature = "serde")]
pub(crate) fn serde_weight_skeleton_match() -> f32 {
    DEFAULT_WEIGHT_SKELETON_MATCH
}

/// Runtime configuration for all pass thresholds and weights.
///
/// Construct via [`Config::default()`] or load a partial TOML override with
/// [`Config::from_toml`] / [`Config::from_file`] (requires the `serde` feature,
/// which is enabled by default).
#[cfg_attr(feature = "serde", derive(serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
#[derive(Debug, Clone)]
pub struct Config {
    // ── Decision thresholds ──────────────────────────────────────────────────
    /// Score at or above which [`NormalizationResult::should_flag`] returns `true`. Default 0.25.
    #[cfg_attr(feature = "serde", serde(default = "serde_flag_threshold"))]
    pub flag_threshold: f32,
    /// Score at or above which [`NormalizationResult::should_block`] returns `true`. Default 0.60.
    #[cfg_attr(feature = "serde", serde(default = "serde_block_threshold"))]
    pub block_threshold: f32,

    // ── CjkSuperposition ────────────────────────────────────────────────────
    /// Sliding window width for CJK entropy spike detection. Default 6.
    #[cfg_attr(feature = "serde", serde(default = "serde_cjk_super_window"))]
    pub cjk_super_window: usize,
    /// Entropy threshold for CJK spike to fire. Default 0.55.
    #[cfg_attr(feature = "serde", serde(default = "serde_cjk_super_threshold"))]
    pub cjk_super_threshold: f32,
    /// Minimum fraction of CJK chars required before running superposition check. Default 0.40.
    #[cfg_attr(feature = "serde", serde(default = "serde_cjk_super_min_cjk_frac"))]
    pub cjk_super_min_cjk_frac: f32,

    // ── MorseCode ────────────────────────────────────────────────────────────
    /// Minimum span length (chars) for a Morse run to be considered. Default 10.
    #[cfg_attr(feature = "serde", serde(default = "serde_morse_min_span"))]
    pub morse_min_span: usize,
    /// Minimum percentage of Morse chars (`.`, `-`, `/`, ` `) in the span. Default 60.
    #[cfg_attr(feature = "serde", serde(default = "serde_morse_min_morse_pct"))]
    pub morse_min_morse_pct: usize,

    // ── Base64 ───────────────────────────────────────────────────────────────
    /// Minimum bare-blob length for Base64 detection. Default 12.
    #[cfg_attr(feature = "serde", serde(default = "serde_base64_min_len"))]
    pub base64_min_len: usize,

    // ── Leetspeak ────────────────────────────────────────────────────────────
    /// Minimum alphanumeric chars in a token before leet analysis runs. Default 4.
    #[cfg_attr(feature = "serde", serde(default = "serde_leet_min_alpha"))]
    pub leet_min_alpha: usize,
    /// Minimum leet-substitution percentage (integer, 0–100) to flag a token. Default 35.
    #[cfg_attr(feature = "serde", serde(default = "serde_leet_min_pct"))]
    pub leet_min_pct: usize,

    // ── EntropyBigram ────────────────────────────────────────────────────────
    /// Shannon entropy (bits/char) above which a token is suspicious. Default 5.2.
    #[cfg_attr(feature = "serde", serde(default = "serde_entropy_high"))]
    pub entropy_high: f32,
    /// English bigram coverage fraction below which a token is suspicious. Default 0.15.
    #[cfg_attr(feature = "serde", serde(default = "serde_entropy_min_english"))]
    pub entropy_min_english: f32,

    // ── UrlEncoding ──────────────────────────────────────────────────────────
    /// Minimum consecutive decoded bytes in a `%XX` run to trigger detection. Default 3.
    #[cfg_attr(feature = "serde", serde(default = "serde_url_min_run"))]
    pub url_min_run: usize,

    // ── HtmlEntities ─────────────────────────────────────────────────────────
    /// Minimum entity count in input before HTML entity detection fires. Default 4.
    #[cfg_attr(feature = "serde", serde(default = "serde_html_min_entities"))]
    pub html_min_entities: usize,

    // ── Per-pass weights (used in compute_score) ─────────────────────────────
    /// Weight for BiDiControl detections. Default 0.90.
    #[cfg_attr(feature = "serde", serde(default = "serde_weight_bidi"))]
    pub weight_bidi: f32,
    /// Weight for Base64 detections. Default 0.85.
    #[cfg_attr(feature = "serde", serde(default = "serde_weight_base64"))]
    pub weight_base64: f32,
    /// Weight for BackslashEscape detections. Default 0.80.
    #[cfg_attr(feature = "serde", serde(default = "serde_weight_backslash"))]
    pub weight_backslash: f32,
    /// Weight for MorseCode detections. Default 0.80.
    #[cfg_attr(feature = "serde", serde(default = "serde_weight_morse"))]
    pub weight_morse: f32,
    /// Weight for UrlEncoding detections. Default 0.80.
    #[cfg_attr(feature = "serde", serde(default = "serde_weight_url"))]
    pub weight_url: f32,
    /// Weight for HtmlEntities detections. Default 0.80.
    #[cfg_attr(feature = "serde", serde(default = "serde_weight_html"))]
    pub weight_html: f32,
    /// Weight for InvisibleStrip detections. Default 0.75.
    #[cfg_attr(feature = "serde", serde(default = "serde_weight_invisible"))]
    pub weight_invisible: f32,
    /// Weight for FullwidthChars detections. Default 0.65.
    #[cfg_attr(feature = "serde", serde(default = "serde_weight_fullwidth"))]
    pub weight_fullwidth: f32,
    /// Weight for Homoglyph detections. Default 0.55.
    #[cfg_attr(feature = "serde", serde(default = "serde_weight_homoglyph"))]
    pub weight_homoglyph: f32,
    /// Weight for EntropyBigram detections. Default 0.50.
    #[cfg_attr(feature = "serde", serde(default = "serde_weight_entropy"))]
    pub weight_entropy: f32,
    /// Weight for ScriptIntrusion detections. Default 0.40.
    #[cfg_attr(feature = "serde", serde(default = "serde_weight_script"))]
    pub weight_script: f32,
    /// Weight for PreScanNfc detections. Default 0.35.
    #[cfg_attr(feature = "serde", serde(default = "serde_weight_nfc"))]
    pub weight_nfc: f32,
    /// Weight for Leetspeak detections. Default 0.30.
    #[cfg_attr(feature = "serde", serde(default = "serde_weight_leet"))]
    pub weight_leet: f32,
    /// Weight for SplitString detections. Default 0.70.
    #[cfg_attr(feature = "serde", serde(default = "serde_weight_split_string"))]
    pub weight_split_string: f32,
    /// Weight for UnicodeEscape detections. Default 0.80.
    #[cfg_attr(feature = "serde", serde(default = "serde_weight_unicode_escape"))]
    pub weight_unicode_escape: f32,
    /// Weight for Rot13 detections. Default 0.80.
    #[cfg_attr(feature = "serde", serde(default = "serde_weight_rot13"))]
    pub weight_rot13: f32,
    /// Weight for Punycode detections. Default 0.85.
    #[cfg_attr(feature = "serde", serde(default = "serde_weight_punycode"))]
    pub weight_punycode: f32,
    /// Weight for SkeletonMatch detections. Default 0.75.
    #[cfg_attr(feature = "serde", serde(default = "serde_weight_skeleton_match"))]
    pub weight_skeleton_match: f32,

    // ── EntropyBigram vocabulary override ────────────────────────────────────
    /// Additional English bigrams merged with the built-in ~130-entry frequency
    /// table for the EntropyBigram coverage check. Each entry must be exactly two
    /// ASCII letters (case-insensitive). Use for domain vocabularies (genomics,
    /// legal acronyms, …) whose tokens trip low-coverage false positives.
    /// Default empty.
    #[cfg_attr(feature = "serde", serde(default))]
    pub extra_english_bigrams: Vec<String>,
    /// Additional Cyrillic bigrams merged with the built-in Russian/Ukrainian
    /// frequency table. Each entry must be exactly two alphabetic chars.
    /// Default empty.
    #[cfg_attr(feature = "serde", serde(default))]
    pub extra_cyrillic_bigrams: Vec<String>,
    /// Additional Greek bigrams merged with the built-in frequency table.
    /// Each entry must be exactly two alphabetic chars. Default empty.
    #[cfg_attr(feature = "serde", serde(default))]
    pub extra_greek_bigrams: Vec<String>,
    /// Additional Arabic bigrams merged with the built-in frequency table.
    /// Each entry must be exactly two alphabetic chars. Default empty.
    #[cfg_attr(feature = "serde", serde(default))]
    pub extra_arabic_bigrams: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            flag_threshold: DEFAULT_FLAG_THRESHOLD,
            block_threshold: DEFAULT_BLOCK_THRESHOLD,
            cjk_super_window: DEFAULT_CJK_SUPER_WINDOW,
            cjk_super_threshold: DEFAULT_CJK_SUPER_THRESHOLD,
            cjk_super_min_cjk_frac: DEFAULT_CJK_SUPER_MIN_CJK_FRAC,
            morse_min_span: DEFAULT_MORSE_MIN_SPAN,
            morse_min_morse_pct: DEFAULT_MORSE_MIN_MORSE_PCT,
            base64_min_len: DEFAULT_BASE64_MIN_LEN,
            leet_min_alpha: DEFAULT_LEET_MIN_ALPHA,
            leet_min_pct: DEFAULT_LEET_MIN_PCT,
            entropy_high: DEFAULT_ENTROPY_HIGH,
            entropy_min_english: DEFAULT_ENTROPY_MIN_ENGLISH,
            url_min_run: DEFAULT_URL_MIN_RUN,
            html_min_entities: DEFAULT_HTML_MIN_ENTITIES,
            weight_bidi: DEFAULT_WEIGHT_BIDI,
            weight_base64: DEFAULT_WEIGHT_BASE64,
            weight_backslash: DEFAULT_WEIGHT_BACKSLASH,
            weight_morse: DEFAULT_WEIGHT_MORSE,
            weight_url: DEFAULT_WEIGHT_URL,
            weight_html: DEFAULT_WEIGHT_HTML,
            weight_invisible: DEFAULT_WEIGHT_INVISIBLE,
            weight_fullwidth: DEFAULT_WEIGHT_FULLWIDTH,
            weight_homoglyph: DEFAULT_WEIGHT_HOMOGLYPH,
            weight_entropy: DEFAULT_WEIGHT_ENTROPY,
            weight_script: DEFAULT_WEIGHT_SCRIPT,
            weight_nfc: DEFAULT_WEIGHT_NFC,
            weight_leet: DEFAULT_WEIGHT_LEET,
            weight_split_string: DEFAULT_WEIGHT_SPLIT_STRING,
            weight_unicode_escape: DEFAULT_WEIGHT_UNICODE_ESCAPE,
            weight_rot13: DEFAULT_WEIGHT_ROT13,
            weight_punycode: DEFAULT_WEIGHT_PUNYCODE,
            weight_skeleton_match: DEFAULT_WEIGHT_SKELETON_MATCH,
            extra_english_bigrams: Vec::new(),
            extra_cyrillic_bigrams: Vec::new(),
            extra_greek_bigrams: Vec::new(),
            extra_arabic_bigrams: Vec::new(),
        }
    }
}

/// Error returned by [`Config::try_from_file`].
#[cfg(all(feature = "serde", not(target_arch = "wasm32")))]
#[derive(Debug)]
pub enum ConfigError {
    /// The file could not be read (missing, permission denied, …).
    Io(std::io::Error),
    /// The file was read but is not valid TOML for [`Config`]
    /// (syntax error, wrong field type, unknown field).
    Parse(toml::de::Error),
    /// The file parsed but a value is out of its documented range
    /// (see [`Config::validate`]).
    Invalid(String),
}

#[cfg(all(feature = "serde", not(target_arch = "wasm32")))]
impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "failed to read config file: {e}"),
            Self::Parse(e) => write!(f, "failed to parse config file: {e}"),
            Self::Invalid(msg) => write!(f, "invalid config value: {msg}"),
        }
    }
}

#[cfg(all(feature = "serde", not(target_arch = "wasm32")))]
impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Parse(e) => Some(e),
            Self::Invalid(_) => None,
        }
    }
}

#[cfg(all(feature = "serde", not(target_arch = "wasm32")))]
impl From<std::io::Error> for ConfigError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

#[cfg(all(feature = "serde", not(target_arch = "wasm32")))]
impl From<toml::de::Error> for ConfigError {
    fn from(e: toml::de::Error) -> Self {
        Self::Parse(e)
    }
}

impl Config {
    /// Check that every value is inside its documented range.
    ///
    /// Rules enforced:
    /// - all `weight_*`, `flag_threshold`, `block_threshold`, `cjk_super_threshold`,
    ///   `cjk_super_min_cjk_frac`, `entropy_min_english` must be in `0.0..=1.0`
    ///   (out-of-range weights are silently flattened by the 1.0 score cap, losing
    ///   the relative weighting between passes)
    /// - `entropy_high` must be finite and non-negative
    /// - `morse_min_morse_pct` and `leet_min_pct` are percentages: at most 100
    /// - `cjk_super_window` must be at least 1
    /// - each `extra_english_bigrams` entry must be exactly two ASCII letters
    ///
    /// [`Config::from_toml`] and [`Config::try_from_file`] enforce this
    /// automatically; call it directly when building `Config` as a struct literal.
    /// The error message lists every violation, `; `-separated.
    pub fn validate(&self) -> Result<(), String> {
        let unit_ranged = [
            ("flag_threshold", self.flag_threshold),
            ("block_threshold", self.block_threshold),
            ("cjk_super_threshold", self.cjk_super_threshold),
            ("cjk_super_min_cjk_frac", self.cjk_super_min_cjk_frac),
            ("entropy_min_english", self.entropy_min_english),
            ("weight_bidi", self.weight_bidi),
            ("weight_base64", self.weight_base64),
            ("weight_backslash", self.weight_backslash),
            ("weight_morse", self.weight_morse),
            ("weight_url", self.weight_url),
            ("weight_html", self.weight_html),
            ("weight_invisible", self.weight_invisible),
            ("weight_fullwidth", self.weight_fullwidth),
            ("weight_homoglyph", self.weight_homoglyph),
            ("weight_entropy", self.weight_entropy),
            ("weight_script", self.weight_script),
            ("weight_nfc", self.weight_nfc),
            ("weight_leet", self.weight_leet),
            ("weight_split_string", self.weight_split_string),
            ("weight_unicode_escape", self.weight_unicode_escape),
            ("weight_rot13", self.weight_rot13),
            ("weight_punycode", self.weight_punycode),
            ("weight_skeleton_match", self.weight_skeleton_match),
        ];
        let mut problems: Vec<String> = Vec::new();
        for (name, v) in unit_ranged {
            if !(0.0..=1.0).contains(&v) {
                problems.push(format!("{name} must be in 0.0..=1.0, got {v}"));
            }
        }
        if !self.entropy_high.is_finite() || self.entropy_high < 0.0 {
            problems.push(format!(
                "entropy_high must be finite and >= 0.0, got {}",
                self.entropy_high
            ));
        }
        if self.morse_min_morse_pct > 100 {
            problems.push(format!(
                "morse_min_morse_pct is a percentage, must be <= 100, got {}",
                self.morse_min_morse_pct
            ));
        }
        if self.leet_min_pct > 100 {
            problems.push(format!(
                "leet_min_pct is a percentage, must be <= 100, got {}",
                self.leet_min_pct
            ));
        }
        if self.cjk_super_window == 0 {
            problems.push("cjk_super_window must be >= 1, got 0".to_string());
        }
        for bg in &self.extra_english_bigrams {
            if bg.len() != 2 || !bg.bytes().all(|b| b.is_ascii_alphabetic()) {
                problems.push(format!(
                    "extra_english_bigrams entries must be exactly two ASCII letters, got {bg:?}"
                ));
            }
        }
        for (field, list) in [
            ("extra_cyrillic_bigrams", &self.extra_cyrillic_bigrams),
            ("extra_greek_bigrams", &self.extra_greek_bigrams),
            ("extra_arabic_bigrams", &self.extra_arabic_bigrams),
        ] {
            for bg in list {
                if bg.chars().count() != 2 || !bg.chars().all(|c| c.is_alphabetic()) {
                    problems.push(format!(
                        "{field} entries must be exactly two alphabetic characters, got {bg:?}"
                    ));
                }
            }
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems.join("; "))
        }
    }

    /// Load from a TOML string. Missing fields fall back to documented defaults.
    /// Values outside their documented range (see [`Config::validate`]) are an error.
    #[cfg(feature = "serde")]
    pub fn from_toml(s: &str) -> Result<Self, toml::de::Error> {
        let cfg: Self = toml::from_str(s)?;
        cfg.validate().map_err(serde::de::Error::custom)?;
        Ok(cfg)
    }

    /// Load from a file path, surfacing read and parse errors.
    ///
    /// Missing fields in the TOML fall back to documented defaults, but an
    /// unreadable file, invalid TOML (syntax error, wrong field type, unknown
    /// field), or an out-of-range value (see [`Config::validate`]) is reported
    /// as [`ConfigError`] rather than silently replaced with defaults.
    /// Not available on wasm32 targets (no filesystem).
    #[cfg(all(feature = "serde", not(target_arch = "wasm32")))]
    pub fn try_from_file(path: &std::path::Path) -> Result<Self, ConfigError> {
        let s = std::fs::read_to_string(path)?;
        let cfg: Self = toml::from_str(&s)?;
        cfg.validate().map_err(ConfigError::Invalid)?;
        Ok(cfg)
    }

    /// Load from a file path. Returns [`Config::default`] if the file is missing or unparseable.
    /// Not available on wasm32 targets (no filesystem).
    #[cfg(all(feature = "serde", not(target_arch = "wasm32")))]
    #[deprecated(
        since = "1.16.0",
        note = "silently falls back to defaults on read/parse errors, which can mask a \
                misconfigured deployment; use `Config::try_from_file` instead"
    )]
    pub fn from_file(path: &std::path::Path) -> Self {
        Self::try_from_file(path).unwrap_or_default()
    }
}
