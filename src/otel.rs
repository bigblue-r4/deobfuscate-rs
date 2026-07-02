//! OpenTelemetry export (feature = "otel").
//!
//! Emits one span per analyzed input through the global tracer provider, with
//! score/decision attributes and one payload-free event per detection —
//! mirroring what the audit trail records, in a shape OTel collectors and
//! SIEMs already ingest. Depends only on the `opentelemetry` API crate; you
//! bring your own SDK/exporter and install it with
//! `opentelemetry::global::set_tracer_provider`.
//!
//! ```no_run
//! let result = deobfuscate::analyze("user input");
//! deobfuscate::otel::emit(&result);
//! ```

use crate::NormalizationResult;
use alloc::borrow::ToOwned;
use alloc::string::ToString;
use alloc::vec::Vec;
use opentelemetry::trace::{Span, Status, Tracer};
use opentelemetry::{global, KeyValue};

/// Instrumentation scope name used for the tracer.
pub const SCOPE: &str = "deobfuscate";

/// Emit one `deobfuscate.analyze` span for `result` via the global tracer.
///
/// Span attributes: `deobfuscate.score`, `.flagged`, `.blocked`, `.halted`,
/// `.detection_count`, and (with the `audit` feature) `.input_hash` /
/// `.input_len`. One `deobfuscate.detection` event per detection carries the
/// pass name, confidence, and span lengths — never the matched content.
///
/// Blocked results set span status to [`Status::error`].
pub fn emit(result: &NormalizationResult) {
    let tracer = global::tracer(SCOPE);
    let mut span = tracer.start("deobfuscate.analyze");

    let mut attrs: Vec<KeyValue> = alloc::vec![
        KeyValue::new("deobfuscate.score", f64::from(result.obfuscation_score)),
        KeyValue::new("deobfuscate.flagged", result.should_flag()),
        KeyValue::new("deobfuscate.blocked", result.should_block()),
        KeyValue::new(
            "deobfuscate.detection_count",
            result.detections.len() as i64
        ),
    ];
    #[cfg(feature = "audit")]
    {
        attrs.push(KeyValue::new(
            "deobfuscate.input_hash",
            result.audit.input_hash.clone(),
        ));
        attrs.push(KeyValue::new(
            "deobfuscate.input_len",
            result.audit.input_len as i64,
        ));
        attrs.push(KeyValue::new("deobfuscate.halted", result.audit.halted));
    }
    span.set_attributes(attrs);

    for d in &result.detections {
        span.add_event(
            "deobfuscate.detection".to_owned(),
            alloc::vec![
                KeyValue::new("pass", d.kind.to_string()),
                KeyValue::new("confidence", f64::from(d.confidence())),
                KeyValue::new("original_len", d.original.chars().count() as i64),
                KeyValue::new("normalized_len", d.normalized.chars().count() as i64),
            ],
        );
    }

    if result.should_block() {
        span.set_status(Status::error("input blocked by deobfuscate"));
    }
    span.end();
}
