//! Runtime-configurable thresholds and pass weights.

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
        }
    }
}

impl Config {
    /// Load from a TOML string. Missing fields fall back to documented defaults.
    #[cfg(feature = "serde")]
    pub fn from_toml(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }

    /// Load from a file path. Returns [`Config::default`] if the file is missing or unparseable.
    /// Not available on wasm32 targets (no filesystem).
    #[cfg(all(feature = "serde", not(target_arch = "wasm32")))]
    pub fn from_file(path: &std::path::Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(s) => toml::from_str(&s).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }
}
