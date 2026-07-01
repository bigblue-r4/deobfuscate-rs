//! Public result types: [`PassKind`], [`Detection`], [`NormalizationResult`].

#[cfg(feature = "audit")]
use crate::audit::AuditRecord;
// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

/// Which deobfuscation pass fired.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PassKind {
    /// Invisible BiDi / zero-width control characters stripped.
    BiDiControl,
    /// East-Asian fullwidth ASCII normalized to standard ASCII.
    FullwidthChars,
    /// Per-character backslash-prefix escaping removed.
    BackslashEscape,
    /// Base64-encoded payload decoded.
    Base64,
    /// Morse code span decoded.
    MorseCode,
    /// Cyrillic/Greek confusable character replaced with ASCII look-alike.
    Homoglyph,
    /// Non-Latin character embedded inside a Latin word (structural detection only).
    ScriptIntrusion,
    /// Leet-speak digit/symbol substitutions normalized within dense tokens.
    Leetspeak,
    /// Forward-reverse script-zone entropy spike — injection seam detected.
    /// HALT: text cleared, never forwarded.
    CjkSuperposition,
    /// Unicode NFC normalization collapsed composed sequences.
    PreScanNfc,
    /// Variation selectors or Unicode tag-block characters stripped. Strong injection signal.
    InvisibleStrip,
    /// High character-level entropy or low English bigram coverage — encoded/random payload signal.
    EntropyBigram,
    /// Percent-encoded (%XX) payload decoded. Run of ≥3 encoded bytes containing injection keyword.
    UrlEncoding,
    /// HTML entity sequences decoded. ≥4 entities whose decoded text contains injection keyword.
    HtmlEntities,
    /// Injection keyword reconstructed from fragments split across non-alpha separators.
    /// Detection only — does not modify text.
    SplitString,
    /// JS/Python/Rust char escape sequences (\xNN, \uNNNN, \u{N}, octal) decoded.
    /// Encoding evasion via source-code-style character escaping.
    UnicodeEscape,
    /// ROT13 substitution cipher decoded in all-alpha tokens containing injection keywords.
    Rot13,
    /// Internationalized domain name `xn--` label decoded via Punycode (RFC 3492),
    /// containing injection keyword after Unicode confusable normalization.
    Punycode,
    /// TR39 skeleton algorithm detects cross-script confusable that reduces to an injection
    /// keyword; catches homoglyphs outside the static HOMOGLYPHS table and mixed-script attacks.
    SkeletonMatch,
}

impl std::fmt::Display for PassKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PassKind::BiDiControl => "bidi-control",
            PassKind::FullwidthChars => "fullwidth-chars",
            PassKind::BackslashEscape => "backslash-escape",
            PassKind::Base64 => "base64",
            PassKind::MorseCode => "morse-code",
            PassKind::Homoglyph => "homoglyph",
            PassKind::ScriptIntrusion => "script-intrusion",
            PassKind::Leetspeak => "leetspeak",
            PassKind::CjkSuperposition => "cjk-superposition",
            PassKind::PreScanNfc => "pre-scan-nfc",
            PassKind::InvisibleStrip => "invisible-strip",
            PassKind::EntropyBigram => "entropy-bigram",
            PassKind::UrlEncoding => "url-encoding",
            PassKind::HtmlEntities => "html-entities",
            PassKind::SplitString => "split-string",
            PassKind::UnicodeEscape => "unicode-escape",
            PassKind::Rot13 => "rot13",
            PassKind::Punycode => "punycode",
            PassKind::SkeletonMatch => "skeleton-match",
        })
    }
}

/// A single obfuscation event found in the input.
#[derive(Debug, Clone)]
pub struct Detection {
    /// Which pass produced this detection.
    pub kind: PassKind,
    /// The original (obfuscated) text span.
    pub original: String,
    /// The normalized (deobfuscated) replacement.
    pub normalized: String,
    /// Human-readable description of what was found.
    pub detail: String,
}

impl Detection {
    /// Confidence that this detection represents a real attack, in [0.0, 1.0].
    ///
    /// Blends a pass-specific base (derived from false-positive risk) with a structural
    /// boost proportional to how much the text changed (encoding density). Passes that
    /// require an explicit injection keyword match always have base 1.0. Statistical
    /// passes (entropy, bigram) have lower bases. Change density can boost the base by
    /// up to 0.20 for passes where heavy encoding leaves a large footprint.
    pub fn confidence(&self) -> f32 {
        let base: f32 = match self.kind {
            // Keyword-gated or halt — definitively intentional
            PassKind::CjkSuperposition
            | PassKind::Rot13
            | PassKind::Punycode
            | PassKind::UrlEncoding
            | PassKind::HtmlEntities
            | PassKind::Base64
            | PassKind::MorseCode => 1.00,
            // Structural encoding with very low FP rate
            PassKind::BackslashEscape
            | PassKind::UnicodeEscape
            | PassKind::BiDiControl
            | PassKind::InvisibleStrip => 0.90,
            // Confusable normalization — occasional loanword FP
            PassKind::Homoglyph | PassKind::FullwidthChars => 0.80,
            // Structural signals with moderate FP risk
            PassKind::ScriptIntrusion | PassKind::SplitString => 0.65,
            // Statistical — higher FP rates
            PassKind::Leetspeak => 0.55,
            PassKind::EntropyBigram => 0.50,
            // NFC is very frequently benign (precomposed vs decomposed equivalents)
            PassKind::PreScanNfc => 0.30,
            // Skeleton match: keyword-gated, comparable confidence to Homoglyph
            PassKind::SkeletonMatch => 0.80,
        };
        // Structural boost: large encoding footprint (big length change) raises confidence.
        let orig = self.original.chars().count();
        let norm = self.normalized.chars().count();
        let change_ratio = if orig > 0 {
            ((orig as f32 - norm as f32).abs() / orig as f32).min(1.0)
        } else {
            0.0
        };
        (base + change_ratio * 0.20).min(1.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────

/// Result of running the normalizer over an input string.
#[derive(Debug, Clone)]
pub struct NormalizationResult {
    /// Cleaned text — pass this to your LLM instead of the raw input.
    pub normalized: String,
    /// Every obfuscation event found, in pass order.
    pub detections: Vec<Detection>,
    /// Composite obfuscation score in [0.0, 1.0]. 0.0 = clean. 1.0 = heavily obfuscated.
    pub obfuscation_score: f32,
    /// Score threshold for [`should_flag`][Self::should_flag] — from the active [`Config`].
    pub flag_threshold: f32,
    /// Score threshold for [`should_block`][Self::should_block] — from the active [`Config`].
    pub block_threshold: f32,
    /// Forensic audit record for this call (feature = "audit").
    #[cfg(feature = "audit")]
    pub audit: AuditRecord,
}

impl NormalizationResult {
    /// Returns `true` if any obfuscation was detected.
    pub fn is_obfuscated(&self) -> bool {
        !self.detections.is_empty()
    }

    /// Returns `true` if the score meets the flag-for-review threshold.
    pub fn should_flag(&self) -> bool {
        self.obfuscation_score >= self.flag_threshold
    }

    /// Returns `true` if the score meets the block/stop-and-ask threshold.
    pub fn should_block(&self) -> bool {
        self.obfuscation_score >= self.block_threshold
    }

    /// Returns the unique detection kinds found, deduplicated.
    pub fn detection_kinds(&self) -> Vec<PassKind> {
        let mut seen = std::collections::HashSet::new();
        self.detections
            .iter()
            .filter(|d| seen.insert(d.kind.clone()))
            .map(|d| d.kind.clone())
            .collect()
    }

    /// Serialize the audit record as a single JSONL line (feature = "audit" + "serde").
    #[cfg(all(feature = "audit", feature = "serde"))]
    pub fn audit_jsonl(&self) -> String {
        serde_json::to_string(&self.audit).unwrap_or_default()
    }

    /// Serialize the audit record as pretty-printed JSON (feature = "audit" + "serde").
    #[cfg(all(feature = "audit", feature = "serde"))]
    pub fn audit_json_pretty(&self) -> String {
        serde_json::to_string_pretty(&self.audit).unwrap_or_default()
    }

    /// One-line summary suitable for logs and traces.
    pub fn summary(&self) -> String {
        if self.detections.is_empty() {
            return "clean".to_string();
        }
        let kinds: Vec<String> = self
            .detection_kinds()
            .iter()
            .map(|k| k.to_string())
            .collect();
        format!(
            "score={:.2}  detections=[{}]",
            self.obfuscation_score,
            kinds.join(", ")
        )
    }
}
