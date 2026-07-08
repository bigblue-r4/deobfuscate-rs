//! Python bindings for the `deobfuscate` crate.
//!
//! Exposes a small, pandas-friendly API:
//! - `scan(text) -> Report`
//! - `scan_batch(texts) -> list[Report]` (releases the GIL)
//! - `Scanner(config_toml=None, disable=None)` for configured/repeated use

use deobfuscate::{Config, NormalizationResult, Normalizer, PassKind};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;

/// One obfuscation event found in the input.
// skip_from_py_object: Detection is only returned to Python, never accepted as an
// argument, so it needs no FromPyObject derive (opt-out required since pyo3 0.29).
#[pyclass(frozen, name = "Detection", module = "deobfuscate", skip_from_py_object)]
#[derive(Clone)]
struct PyDetection {
    /// Pass display name, e.g. "base64", "homoglyph".
    #[pyo3(get)]
    kind: String,
    /// The original (obfuscated) span.
    #[pyo3(get)]
    original: String,
    /// The normalized replacement.
    #[pyo3(get)]
    normalized: String,
    /// Human-readable description of what was found.
    #[pyo3(get)]
    detail: String,
    /// Confidence this is a real attack, in [0.0, 1.0].
    #[pyo3(get)]
    confidence: f32,
}

#[pymethods]
impl PyDetection {
    fn __repr__(&self) -> String {
        format!(
            "Detection(kind={:?}, confidence={:.2}, detail={:?})",
            self.kind, self.confidence, self.detail
        )
    }
}

/// Result of scanning one input string.
#[pyclass(frozen, name = "Report", module = "deobfuscate")]
struct PyReport {
    /// Cleaned text — send this to your LLM instead of the raw input.
    #[pyo3(get)]
    normalized: String,
    /// Composite obfuscation score in [0.0, 1.0].
    #[pyo3(get)]
    score: f32,
    /// score >= flag threshold (default 0.25).
    #[pyo3(get)]
    should_flag: bool,
    /// score >= block threshold (default 0.60).
    #[pyo3(get)]
    should_block: bool,
    /// Any detection fired.
    #[pyo3(get)]
    is_obfuscated: bool,
    /// One-line summary suitable for logs.
    #[pyo3(get)]
    summary: String,
    /// Payload-free tamper-evident audit record as a JSONL line.
    #[pyo3(get)]
    audit_jsonl: String,
    detections: Vec<PyDetection>,
}

#[pymethods]
impl PyReport {
    /// Detection events, in pass order.
    #[getter]
    fn detections(&self) -> Vec<PyDetection> {
        self.detections.clone()
    }

    /// Flat dict for DataFrame construction:
    /// `pd.DataFrame(r.to_dict() for r in scan_batch(texts))`.
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("normalized", &self.normalized)?;
        d.set_item("score", self.score)?;
        d.set_item("should_flag", self.should_flag)?;
        d.set_item("should_block", self.should_block)?;
        d.set_item("is_obfuscated", self.is_obfuscated)?;
        let kinds: Vec<&str> = self.detections.iter().map(|x| x.kind.as_str()).collect();
        d.set_item("kinds", kinds)?;
        Ok(d)
    }

    fn __repr__(&self) -> String {
        format!(
            "Report(score={:.2}, should_flag={}, should_block={}, detections={})",
            self.score,
            if self.should_flag { "True" } else { "False" },
            if self.should_block { "True" } else { "False" },
            self.detections.len()
        )
    }
}

fn to_report(r: NormalizationResult) -> PyReport {
    PyReport {
        should_flag: r.should_flag(),
        should_block: r.should_block(),
        is_obfuscated: r.is_obfuscated(),
        summary: r.summary(),
        audit_jsonl: r.audit_jsonl(),
        detections: r
            .detections
            .iter()
            .map(|d| PyDetection {
                kind: d.kind.to_string(),
                original: d.original.clone(),
                normalized: d.normalized.clone(),
                detail: d.detail.clone(),
                confidence: d.confidence(),
            })
            .collect(),
        normalized: r.normalized,
        score: r.obfuscation_score,
    }
}

fn pass_kind_from_name(name: &str) -> PyResult<PassKind> {
    // Accept the same display names the library emits (Report.detections[].kind).
    const ALL: &[PassKind] = &[
        PassKind::PreScanNfc,
        PassKind::InvisibleStrip,
        PassKind::CjkSuperposition,
        PassKind::BiDiControl,
        PassKind::FullwidthChars,
        PassKind::BackslashEscape,
        PassKind::UnicodeEscape,
        PassKind::UrlEncoding,
        PassKind::HtmlEntities,
        PassKind::Base64,
        PassKind::MorseCode,
        PassKind::Homoglyph,
        PassKind::ScriptIntrusion,
        PassKind::Leetspeak,
        PassKind::EntropyBigram,
        PassKind::SplitString,
        PassKind::Rot13,
        PassKind::Punycode,
        PassKind::SkeletonMatch,
    ];
    ALL.iter()
        .find(|k| k.to_string() == name)
        .cloned()
        .ok_or_else(|| {
            let known: Vec<String> = ALL.iter().map(|k| k.to_string()).collect();
            PyValueError::new_err(format!(
                "unknown pass name {name:?}; known passes: {}",
                known.join(", ")
            ))
        })
}

/// Reusable, configurable scanner.
///
/// `config_toml` accepts the same TOML the Rust crate does (partial overrides
/// of thresholds/weights/bigram tables). `disable` lists pass names to turn
/// off, e.g. `["leetspeak", "morse-code"]`.
#[pyclass(name = "Scanner", module = "deobfuscate")]
struct PyScanner {
    normalizer: Normalizer,
}

#[pymethods]
impl PyScanner {
    #[new]
    #[pyo3(signature = (config_toml=None, disable=None))]
    fn new(config_toml: Option<&str>, disable: Option<Vec<String>>) -> PyResult<Self> {
        let mut normalizer = Normalizer::default();
        if let Some(toml) = config_toml {
            let config =
                Config::from_toml(toml).map_err(|e| PyValueError::new_err(e.to_string()))?;
            normalizer = normalizer.with_config(config);
        }
        for name in disable.unwrap_or_default() {
            normalizer = normalizer.disable(pass_kind_from_name(&name)?);
        }
        Ok(Self { normalizer })
    }

    /// Scan one string.
    fn scan(&self, text: &str) -> PyReport {
        to_report(self.normalizer.analyze(text))
    }

    /// Scan many strings, releasing the GIL while scanning.
    fn scan_batch(&self, py: Python<'_>, texts: Vec<String>) -> Vec<PyReport> {
        py.detach(|| {
            texts
                .iter()
                .map(|t| to_report(self.normalizer.analyze(t)))
                .collect()
        })
    }
}

/// Scan one string with the default configuration (all 19 passes).
#[pyfunction]
fn scan(text: &str) -> PyReport {
    to_report(deobfuscate::analyze(text))
}

/// Scan many strings with the default configuration, releasing the GIL.
#[pyfunction]
fn scan_batch(py: Python<'_>, texts: Vec<String>) -> Vec<PyReport> {
    py.detach(|| {
        let normalizer = Normalizer::default();
        texts
            .iter()
            .map(|t| to_report(normalizer.analyze(t)))
            .collect()
    })
}

#[pymodule(name = "deobfuscate")]
fn deobfuscate_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyReport>()?;
    m.add_class::<PyDetection>()?;
    m.add_class::<PyScanner>()?;
    m.add_function(wrap_pyfunction!(scan, m)?)?;
    m.add_function(wrap_pyfunction!(scan_batch, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
