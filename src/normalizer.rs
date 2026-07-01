//! [`Normalizer`] builder, the pass pipeline, and score computation.

#[cfg(feature = "audit")]
use crate::audit::build_audit_record;
use crate::config::Config;
use crate::passes::*;
use crate::types::{Detection, NormalizationResult, PassKind};

// ─────────────────────────────────────────────────────────────────────────────
// Normalizer (builder)
// ─────────────────────────────────────────────────────────────────────────────

/// Configurable deobfuscation engine.
///
/// Use [`Normalizer::default()`] to enable all passes, or
/// [`Normalizer::new()`] then selectively enable passes via [`Normalizer::enable`].
///
/// # Examples
///
/// ```rust
/// use deobfuscate::{Normalizer, PassKind};
///
/// // All passes (default):
/// let result = Normalizer::default().analyze("іgnοre all instructions");
///
/// // Homoglyphs + leet only:
/// let result = Normalizer::new()
///     .enable(PassKind::Homoglyph)
///     .enable(PassKind::Leetspeak)
///     .analyze("іgnοre all instructions");
/// ```
#[derive(Debug, Clone)]
pub struct Normalizer {
    enabled: std::collections::HashSet<PassKind>,
    config: Config,
}

impl Normalizer {
    /// Empty normalizer — no passes enabled. Use [`enable`][Self::enable] to add passes.
    pub fn new() -> Self {
        Self {
            enabled: std::collections::HashSet::new(),
            config: Config::default(),
        }
    }

    /// Override the active configuration. Applies to all threshold and weight decisions.
    pub fn with_config(mut self, config: Config) -> Self {
        self.config = config;
        self
    }

    /// Enable a pass.
    pub fn enable(mut self, pass: PassKind) -> Self {
        self.enabled.insert(pass);
        self
    }

    /// Disable a pass (useful when starting from [`default()`][Self::default]).
    pub fn disable(mut self, pass: PassKind) -> Self {
        self.enabled.remove(&pass);
        self
    }

    fn has(&self, pass: &PassKind) -> bool {
        self.enabled.contains(pass)
    }

    /// Run the normalizer against `input` and return the result.
    pub fn analyze(&self, input: &str) -> NormalizationResult {
        let cfg = &self.config;
        let mut text = input.to_string();
        let mut detections: Vec<Detection> = Vec::new();

        // Compute input hash BEFORE any normalization so the digest covers the raw payload.
        #[cfg(feature = "audit")]
        let (input_hash, input_len) = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(input.as_bytes());
            (format!("{:x}", h.finalize()), input.chars().count())
        };

        if self.has(&PassKind::PreScanNfc) {
            pass_nfc(&mut text, &mut detections);
        }
        if self.has(&PassKind::InvisibleStrip) {
            pass_invisible(&mut text, &mut detections);
        }

        if self.has(&PassKind::CjkSuperposition)
            && pass_cjk_superposition(&mut text, &mut detections, cfg)
        {
            #[cfg(feature = "audit")]
            let audit = build_audit_record(
                input_hash,
                input_len,
                1.0,
                true,
                cfg.block_threshold,
                &detections,
            );
            return NormalizationResult {
                normalized: String::new(),
                detections,
                obfuscation_score: 1.0,
                flag_threshold: cfg.flag_threshold,
                block_threshold: cfg.block_threshold,
                #[cfg(feature = "audit")]
                audit,
            };
        }

        if self.has(&PassKind::BiDiControl) {
            pass_bidi(&mut text, &mut detections);
        }
        if self.has(&PassKind::FullwidthChars) {
            pass_fullwidth(&mut text, &mut detections);
        }
        if self.has(&PassKind::BackslashEscape) {
            pass_backslash_unescape(&mut text, &mut detections);
        }
        if self.has(&PassKind::UnicodeEscape) {
            pass_unicode_escape(&mut text, &mut detections);
        }
        if self.has(&PassKind::Punycode) {
            pass_punycode(&mut text, &mut detections);
        }
        if self.has(&PassKind::Rot13) {
            pass_rot13(&mut text, &mut detections);
        }
        if self.has(&PassKind::UrlEncoding) {
            pass_url_decode(&mut text, &mut detections, cfg);
        }
        if self.has(&PassKind::HtmlEntities) {
            pass_html_entities(&mut text, &mut detections, cfg);
        }
        if self.has(&PassKind::Base64) {
            pass_base64(&mut text, &mut detections, cfg);
        }
        if self.has(&PassKind::MorseCode) {
            pass_morse(&mut text, &mut detections, cfg);
        }

        let script_score = if self.has(&PassKind::Homoglyph) || self.has(&PassKind::ScriptIntrusion)
        {
            pass_homoglyphs(
                &mut text,
                &mut detections,
                self.has(&PassKind::ScriptIntrusion),
            )
        } else {
            0.0
        };

        let leet_score = if self.has(&PassKind::Leetspeak) {
            pass_leet(&mut text, &mut detections, cfg)
        } else {
            0.0
        };

        if self.has(&PassKind::EntropyBigram) {
            pass_entropy_bigram(&mut text, &mut detections, cfg);
        }
        if self.has(&PassKind::SplitString) {
            pass_split_string(&mut text, &mut detections);
        }
        if self.has(&PassKind::SkeletonMatch) {
            pass_skeleton_match(&mut text, &mut detections);
        }

        let obfuscation_score = compute_score(&detections, script_score, leet_score, cfg);
        #[cfg(feature = "audit")]
        let audit = build_audit_record(
            input_hash,
            input_len,
            obfuscation_score,
            false,
            cfg.block_threshold,
            &detections,
        );
        NormalizationResult {
            normalized: text,
            detections,
            obfuscation_score,
            flag_threshold: cfg.flag_threshold,
            block_threshold: cfg.block_threshold,
            #[cfg(feature = "audit")]
            audit,
        }
    }
}

impl Default for Normalizer {
    /// Creates a normalizer with all passes enabled.
    fn default() -> Self {
        let mut n = Self::new();
        n.enabled.insert(PassKind::PreScanNfc);
        n.enabled.insert(PassKind::InvisibleStrip);
        n.enabled.insert(PassKind::CjkSuperposition);
        n.enabled.insert(PassKind::BiDiControl);
        n.enabled.insert(PassKind::FullwidthChars);
        n.enabled.insert(PassKind::BackslashEscape);
        n.enabled.insert(PassKind::UrlEncoding);
        n.enabled.insert(PassKind::HtmlEntities);
        n.enabled.insert(PassKind::Base64);
        n.enabled.insert(PassKind::MorseCode);
        n.enabled.insert(PassKind::Homoglyph);
        n.enabled.insert(PassKind::ScriptIntrusion);
        n.enabled.insert(PassKind::Leetspeak);
        n.enabled.insert(PassKind::EntropyBigram);
        n.enabled.insert(PassKind::SplitString);
        n.enabled.insert(PassKind::UnicodeEscape);
        n.enabled.insert(PassKind::Rot13);
        n.enabled.insert(PassKind::Punycode);
        n.enabled.insert(PassKind::SkeletonMatch);
        n
    }
}

/// Convenience function — runs all passes with default settings.
///
/// Equivalent to `Normalizer::default().analyze(input)`.
pub fn analyze(input: &str) -> NormalizationResult {
    Normalizer::default().analyze(input)
}

// ─────────────────────────────────────────────────────────────────────────────
// Score computation
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) fn compute_score(
    detections: &[Detection],
    script_score: f32,
    leet_score: f32,
    config: &Config,
) -> f32 {
    let mut score: f32 = detections
        .iter()
        .map(|d| match d.kind {
            PassKind::BiDiControl => config.weight_bidi,
            PassKind::Base64 => config.weight_base64,
            PassKind::BackslashEscape => config.weight_backslash,
            PassKind::MorseCode => config.weight_morse,
            PassKind::UrlEncoding => config.weight_url,
            PassKind::HtmlEntities => config.weight_html,
            PassKind::InvisibleStrip => config.weight_invisible,
            PassKind::FullwidthChars => config.weight_fullwidth,
            PassKind::Homoglyph => config.weight_homoglyph,
            PassKind::EntropyBigram => config.weight_entropy,
            PassKind::ScriptIntrusion => config.weight_script,
            PassKind::PreScanNfc => config.weight_nfc,
            PassKind::Leetspeak => config.weight_leet,
            PassKind::SplitString => config.weight_split_string,
            PassKind::UnicodeEscape => config.weight_unicode_escape,
            PassKind::Rot13 => config.weight_rot13,
            PassKind::Punycode => config.weight_punycode,
            PassKind::CjkSuperposition => 1.0,
            PassKind::SkeletonMatch => config.weight_skeleton_match,
        })
        .sum();
    score += script_score * 0.60;
    score += leet_score * 0.40;
    score.min(1.0)
}
