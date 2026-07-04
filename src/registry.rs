//! Pass registry — the ordered set of detection passes the pipeline runs.
//!
//! Each built-in pass is a zero-sized type implementing [`DetectionPass`] and
//! wrapping its detection function in `passes.rs`. The registry is a `static`
//! slice of `&dyn DetectionPass`, so iterating it allocates nothing on the hot
//! path (the crate is designed to run on every request).
//!
//! ## Adding a pass
//!
//! 1. Add a `PassKind` variant (minor-compatible; see `BREAKING-CANDIDATES.md`).
//! 2. Write the detection function in `passes.rs`.
//! 3. Add a ZST here implementing [`DetectionPass`] (use the `simple_pass!`
//!    macro for the common shape) and register it in [`CORE`] at the correct
//!    pipeline position.
//!
//! The pipeline is intentionally **sequential and mutating**: each pass may
//! rewrite the working text in place so downstream passes see the decoded
//! output (this is why e.g. Base64 → Morse-on-the-result works). A pass that
//! only wants to *detect* simply pushes detections and leaves the text alone.

use crate::config::Config;
use crate::passes::*;
use crate::types::{Detection, PassKind};
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

/// Read-only context handed to every pass on each run.
pub(crate) struct PassCtx<'a> {
    pub config: &'a Config,
    /// Whether `ScriptIntrusion` detection is enabled (the homoglyph pass emits
    /// structural intrusion detections only when this is set).
    pub script_intrusion_enabled: bool,
}

/// What a pass reports back to the pipeline runner.
pub(crate) enum PassOutcome {
    /// Normal completion. `score` is an extra intensity signal blended into the
    /// aggregate beyond per-detection weights — non-zero only for the homoglyph
    /// and leet passes; `0.0` for every other pass.
    Continue { score: f32 },
    /// Hard halt — the CJK-superposition injection seam. The runner clears the
    /// working text and returns immediately with score `1.0`.
    Halt,
}

/// A detection pass. Implement this and register in [`CORE`] to add a pass.
///
/// `Sync` is required so instances can live in the `static` registry.
pub(crate) trait DetectionPass: Sync {
    /// Stable identity of this pass.
    fn kind(&self) -> PassKind;

    /// Whether this pass runs given the enabled-pass set. Defaults to "the
    /// pass's own kind is enabled"; overridden where one pass serves several
    /// kinds (the homoglyph pass also runs for `ScriptIntrusion`).
    fn enabled(&self, set: &BTreeSet<PassKind>) -> bool {
        set.contains(&self.kind())
    }

    /// Run against the working text, pushing any detections found.
    fn run(&self, text: &mut String, detections: &mut Vec<Detection>, ctx: &PassCtx) -> PassOutcome;
}

/// Define a ZST pass that wraps a detection function with the common shape
/// (mutates text, pushes detections, contributes no intensity score).
macro_rules! simple_pass {
    ($ty:ident => $kind:ident : $func:ident) => {
        pub(crate) struct $ty;
        impl DetectionPass for $ty {
            fn kind(&self) -> PassKind {
                PassKind::$kind
            }
            fn run(
                &self,
                text: &mut String,
                det: &mut Vec<Detection>,
                _ctx: &PassCtx,
            ) -> PassOutcome {
                $func(text, det);
                PassOutcome::Continue { score: 0.0 }
            }
        }
    };
    ($ty:ident => $kind:ident : $func:ident, cfg) => {
        pub(crate) struct $ty;
        impl DetectionPass for $ty {
            fn kind(&self) -> PassKind {
                PassKind::$kind
            }
            fn run(
                &self,
                text: &mut String,
                det: &mut Vec<Detection>,
                ctx: &PassCtx,
            ) -> PassOutcome {
                $func(text, det, ctx.config);
                PassOutcome::Continue { score: 0.0 }
            }
        }
    };
}

simple_pass!(NfcPass           => PreScanNfc      : pass_nfc);
simple_pass!(InvisiblePass     => InvisibleStrip  : pass_invisible);
simple_pass!(BiDiPass          => BiDiControl     : pass_bidi);
simple_pass!(FullwidthPass     => FullwidthChars  : pass_fullwidth);
simple_pass!(BackslashPass     => BackslashEscape : pass_backslash_unescape);
simple_pass!(UnicodeEscapePass => UnicodeEscape   : pass_unicode_escape);
simple_pass!(PunycodePass      => Punycode        : pass_punycode);
simple_pass!(Rot13Pass         => Rot13           : pass_rot13);
simple_pass!(UrlPass           => UrlEncoding     : pass_url_decode, cfg);
simple_pass!(HtmlPass          => HtmlEntities    : pass_html_entities, cfg);
simple_pass!(Base64Pass        => Base64          : pass_base64, cfg);
simple_pass!(MorsePass         => MorseCode       : pass_morse, cfg);
simple_pass!(EntropyPass       => EntropyBigram   : pass_entropy_bigram, cfg);
simple_pass!(SplitStringPass   => SplitString     : pass_split_string);
#[cfg(feature = "std")]
simple_pass!(SkeletonMatchPass => SkeletonMatch   : pass_skeleton_match);

/// CJK forward/reverse entropy seam. Returns [`PassOutcome::Halt`] when the
/// seam is found so the runner can clear the text and stop.
pub(crate) struct CjkSuperpositionPass;
impl DetectionPass for CjkSuperpositionPass {
    fn kind(&self) -> PassKind {
        PassKind::CjkSuperposition
    }
    fn run(&self, text: &mut String, det: &mut Vec<Detection>, ctx: &PassCtx) -> PassOutcome {
        if pass_cjk_superposition(text, det, ctx.config) {
            PassOutcome::Halt
        } else {
            PassOutcome::Continue { score: 0.0 }
        }
    }
}

/// Homoglyph normalization + optional structural script-intrusion detection.
/// Runs when either `Homoglyph` or `ScriptIntrusion` is enabled, and surfaces
/// the script-intensity score the aggregate blends at 0.60.
pub(crate) struct HomoglyphPass;
impl DetectionPass for HomoglyphPass {
    fn kind(&self) -> PassKind {
        PassKind::Homoglyph
    }
    fn enabled(&self, set: &BTreeSet<PassKind>) -> bool {
        set.contains(&PassKind::Homoglyph) || set.contains(&PassKind::ScriptIntrusion)
    }
    fn run(&self, text: &mut String, det: &mut Vec<Detection>, ctx: &PassCtx) -> PassOutcome {
        let score = pass_homoglyphs(text, det, ctx.script_intrusion_enabled);
        PassOutcome::Continue { score }
    }
}

/// Leetspeak normalization. Surfaces the leet-intensity score the aggregate
/// blends at 0.40.
pub(crate) struct LeetPass;
impl DetectionPass for LeetPass {
    fn kind(&self) -> PassKind {
        PassKind::Leetspeak
    }
    fn run(&self, text: &mut String, det: &mut Vec<Detection>, ctx: &PassCtx) -> PassOutcome {
        let score = pass_leet(text, det, ctx.config);
        PassOutcome::Continue { score }
    }
}

/// The core pipeline, in execution order. This order is behavior-significant:
/// decoders that feed each other run before the statistical/structural passes.
static CORE: &[&dyn DetectionPass] = &[
    &NfcPass,
    &InvisiblePass,
    &CjkSuperpositionPass,
    &BiDiPass,
    &FullwidthPass,
    &BackslashPass,
    &UnicodeEscapePass,
    &PunycodePass,
    &Rot13Pass,
    &UrlPass,
    &HtmlPass,
    &Base64Pass,
    &MorsePass,
    &HomoglyphPass,
    &LeetPass,
    &EntropyPass,
    &SplitStringPass,
];

/// Std-only tail (the `SkeletonMatch` pass needs the std-only
/// `unicode_skeleton` crate). Runs after the core, matching the original order.
#[cfg(feature = "std")]
static STD_TAIL: &[&dyn DetectionPass] = &[&SkeletonMatchPass];
#[cfg(not(feature = "std"))]
static STD_TAIL: &[&dyn DetectionPass] = &[];

/// The full ordered pass registry. Allocation-free: yields references into the
/// two `static` slices.
pub(crate) fn registry() -> impl Iterator<Item = &'static dyn DetectionPass> {
    CORE.iter().chain(STD_TAIL.iter()).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registry order must match the historical hardcoded pipeline order —
    /// a reordering would silently change decode-chaining behavior.
    #[test]
    fn registry_order_is_stable() {
        let kinds: Vec<PassKind> = registry().map(|p| p.kind()).collect();
        let mut expected = alloc::vec![
            PassKind::PreScanNfc,
            PassKind::InvisibleStrip,
            PassKind::CjkSuperposition,
            PassKind::BiDiControl,
            PassKind::FullwidthChars,
            PassKind::BackslashEscape,
            PassKind::UnicodeEscape,
            PassKind::Punycode,
            PassKind::Rot13,
            PassKind::UrlEncoding,
            PassKind::HtmlEntities,
            PassKind::Base64,
            PassKind::MorseCode,
            PassKind::Homoglyph,
            PassKind::Leetspeak,
            PassKind::EntropyBigram,
            PassKind::SplitString,
        ];
        #[cfg(feature = "std")]
        expected.push(PassKind::SkeletonMatch);
        assert_eq!(kinds, expected);
    }

    /// The homoglyph pass must also run when only ScriptIntrusion is enabled.
    #[test]
    fn homoglyph_pass_gates_on_either_kind() {
        let mut only_intrusion = BTreeSet::new();
        only_intrusion.insert(PassKind::ScriptIntrusion);
        assert!(HomoglyphPass.enabled(&only_intrusion));

        let mut only_homoglyph = BTreeSet::new();
        only_homoglyph.insert(PassKind::Homoglyph);
        assert!(HomoglyphPass.enabled(&only_homoglyph));

        let empty = BTreeSet::new();
        assert!(!HomoglyphPass.enabled(&empty));
    }
}
