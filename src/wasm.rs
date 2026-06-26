//! JavaScript-callable API for in-browser use via wasm-pack.
//!
//! # Build
//!
//! ```text
//! wasm-pack build --target web --features wasm --no-default-features
//! ```
//!
//! This emits a `pkg/` directory containing `deobfuscate.js`,
//! `deobfuscate_bg.wasm`, and a TypeScript `.d.ts` declaration file.
//!
//! # Minimal example (ESM)
//!
//! ```js
//! import init, { analyze_text, should_block, score } from './pkg/deobfuscate.js';
//! await init();
//!
//! const result = analyze_text(userInput);
//! if (result.should_block) {
//!     console.error('blocked:', result.summary);
//! } else {
//!     sendToLLM(result.normalized);
//! }
//! ```

use wasm_bindgen::prelude::*;

/// Analyze `input` and return a plain JavaScript object with the full result.
///
/// Returned object fields:
///
/// | Field              | Type     | Description                                      |
/// |--------------------|----------|--------------------------------------------------|
/// | `normalized`       | string   | Cleaned text — send this to your LLM             |
/// | `obfuscation_score`| number   | 0.0 – 1.0                                        |
/// | `is_obfuscated`    | boolean  | Any detection fired                              |
/// | `should_flag`      | boolean  | Score ≥ flag threshold (default 0.25)            |
/// | `should_block`     | boolean  | Score ≥ block threshold (default 0.60)           |
/// | `was_halted`       | boolean  | CjkSuperposition HALT triggered; text cleared   |
/// | `summary`          | string   | Human-readable one-line summary                  |
/// | `passes_fired`     | string[] | PassKind names for each detection                |
#[wasm_bindgen]
pub fn analyze_text(input: &str) -> JsValue {
    let result = crate::analyze(input);
    let obj = js_sys::Object::new();

    macro_rules! set {
        ($key:expr, $val:expr) => {
            js_sys::Reflect::set(&obj, &JsValue::from_str($key), &$val).unwrap();
        };
    }

    set!("normalized",         JsValue::from_str(&result.normalized));
    set!("obfuscation_score",  JsValue::from_f64(result.obfuscation_score as f64));
    set!("is_obfuscated",      JsValue::from_bool(result.is_obfuscated()));
    set!("should_flag",        JsValue::from_bool(result.should_flag()));
    set!("should_block",       JsValue::from_bool(result.should_block()));

    let was_halted = result.detections.iter()
        .any(|d| d.kind == crate::PassKind::CjkSuperposition);
    set!("was_halted", JsValue::from_bool(was_halted));
    set!("summary",    JsValue::from_str(&result.summary()));

    let passes = js_sys::Array::new();
    for kind in result.detection_kinds() {
        passes.push(&JsValue::from_str(&format!("{:?}", kind)));
    }
    set!("passes_fired", passes.into());

    obj.into()
}

/// Returns `true` if the input should be blocked (score ≥ block threshold).
///
/// Faster than [`analyze_text`] when only a pass/block decision is needed.
#[wasm_bindgen]
pub fn should_block(input: &str) -> bool {
    crate::analyze(input).should_block()
}

/// Returns the obfuscation score for `input` in [0.0, 1.0].
#[wasm_bindgen]
pub fn score(input: &str) -> f32 {
    crate::analyze(input).obfuscation_score
}
