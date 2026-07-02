//! Optional semantic anomaly scoring (feature = "semantic").
//!
//! The structural passes deliberately do not judge *meaning* — a plain-text
//! "ignore all previous instructions" contains no encoding evasion and scores
//! 0.0. This module is the opt-in hook for that layer: implement
//! [`SemanticScorer`] with your own model (embedding distance, perplexity,
//! an LLM judge, …) and install it with
//! [`Normalizer::with_semantic_scorer`][crate::Normalizer::with_semantic_scorer].
//!
//! The scorer runs once per `analyze()` call, after all structural passes,
//! against the **normalized** text — so an attacker cannot hide the phrasing
//! from your scorer behind an encoding this crate strips. When the returned
//! score meets `Config::semantic_threshold`, a
//! [`PassKind::SemanticAnomaly`][crate::PassKind::SemanticAnomaly] detection
//! is recorded and `Config::weight_semantic` contributes to the composite
//! score.
//!
//! A dependency-free reference implementation, [`PhraseOverrideScorer`],
//! ships with the feature. It is a phrase-pattern heuristic, not a model —
//! treat it as a starting point and a demonstration of the trait boundary,
//! not as a semantic defense on its own.

use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec::Vec;

/// Pluggable semantic anomaly scorer.
///
/// `Send + Sync` so a configured [`Normalizer`][crate::Normalizer] can be
/// shared across threads (the Python binding's batch API relies on this).
pub trait SemanticScorer: Send + Sync {
    /// Score the (already normalized) text in `[0.0, 1.0]`, where 1.0 means
    /// "certainly an instruction-override / semantic injection attempt".
    /// Values outside the range are clamped by the pipeline.
    fn score(&self, normalized: &str) -> f32;

    /// Short name recorded in the detection detail and audit trail.
    fn name(&self) -> &str {
        "semantic"
    }
}

/// Reference [`SemanticScorer`]: instruction-override phrase heuristic.
///
/// Counts case-insensitive occurrences of phrasing patterns typical of
/// plain-text prompt injection ("ignore all previous instructions",
/// "you are now", "reveal your system prompt", …). One hit scores 0.60,
/// two 0.85, three or more 1.0 — tune the phrase list per deployment with
/// [`PhraseOverrideScorer::with_phrases`].
pub struct PhraseOverrideScorer {
    phrases: Vec<String>,
}

/// Default phrase patterns. All lowercase; matching is case-insensitive.
const DEFAULT_PHRASES: &[&str] = &[
    "ignore all previous",
    "ignore previous instructions",
    "ignore the above",
    "ignore your instructions",
    "disregard all previous",
    "disregard the above",
    "disregard your instructions",
    "forget all previous",
    "forget your instructions",
    "forget everything above",
    "new instructions:",
    "your new instructions",
    "override your instructions",
    "you are now",
    "you must now",
    "from now on you",
    "act as if you",
    "pretend you are",
    "pretend to be",
    "reveal your system prompt",
    "print your system prompt",
    "repeat your system prompt",
    "show me your instructions",
    "what are your instructions",
    "do anything now",
    "developer mode enabled",
    "no longer bound by",
    "without any restrictions",
];

impl PhraseOverrideScorer {
    /// Scorer with the built-in phrase list.
    pub fn new() -> Self {
        Self {
            phrases: DEFAULT_PHRASES.iter().map(|p| (*p).to_owned()).collect(),
        }
    }

    /// Scorer with a custom phrase list (lowercase patterns; matched
    /// case-insensitively as substrings of the normalized text).
    pub fn with_phrases<I, S>(phrases: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            phrases: phrases.into_iter().map(Into::into).collect(),
        }
    }
}

impl Default for PhraseOverrideScorer {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticScorer for PhraseOverrideScorer {
    fn score(&self, normalized: &str) -> f32 {
        let lower = normalized.to_lowercase();
        let hits = self
            .phrases
            .iter()
            .filter(|p| !p.is_empty() && lower.contains(p.as_str()))
            .count();
        match hits {
            0 => 0.0,
            1 => 0.60,
            2 => 0.85,
            _ => 1.0,
        }
    }

    fn name(&self) -> &str {
        "phrase-override"
    }
}
