//! Audit trail (feature = "audit"): payload-free records, timestamps, HMAC chains.

#[cfg(feature = "audit")]
use crate::types::Detection;

// ─────────────────────────────────────────────────────────────────────────────
// Audit types (feature = "audit")
// ─────────────────────────────────────────────────────────────────────────────

/// Per-detection entry in an [`AuditRecord`]. Contains no raw payload — only lengths.
#[cfg(feature = "audit")]
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DetectionRecord {
    /// Pass display name (e.g. "base64").
    pub pass: String,
    /// Char count of the original (obfuscated) span.
    pub original_len: usize,
    /// Char count of the normalized replacement.
    pub normalized_len: usize,
    /// Structural detail from the pass — truncated to 200 chars to prevent payload leakage.
    pub detail: String,
    /// Confidence this detection is a real attack, in [0.0, 1.0]. See [`Detection::confidence`].
    #[cfg_attr(feature = "serde", serde(default))]
    pub confidence: f32,
}

/// Tamper-evident, payload-free forensic record for a single `analyze()` call.
///
/// The raw input is never stored — only its SHA-256 hash and char length. No decoded
/// strings appear in any field. Wire this to your SIEM / append it to a JSONL log.
#[cfg(feature = "audit")]
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AuditRecord {
    /// SHA-256 hex digest of the raw (pre-normalization) input.
    pub input_hash: String,
    /// Char count of the raw input.
    pub input_len: usize,
    /// RFC 3339 UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`). Empty string on wasm32.
    pub timestamp: String,
    /// Composite obfuscation score in [0.0, 1.0].
    pub obfuscation_score: f32,
    /// `true` if the CjkSuperposition HALT pass fired (text was cleared, pipeline stopped).
    pub halted: bool,
    /// `true` if `obfuscation_score >= block_threshold`.
    pub blocked: bool,
    /// Deduplicated list of pass names that produced at least one detection.
    pub passes_fired: Vec<String>,
    /// One entry per [`Detection`] — lengths only, no raw payload.
    pub detections: Vec<DetectionRecord>,
    /// HMAC-SHA256 of the previous record in the chain (hex). `None` for the first record.
    /// Include before calling [`sign`](AuditRecord::sign) to create a verifiable chain.
    #[cfg_attr(feature = "serde", serde(default))]
    pub prev_hmac: Option<String>,
    /// HMAC-SHA256 signature over this record's canonical form (with `signature` = null).
    /// Set by [`sign`](AuditRecord::sign); verified by [`verify`](AuditRecord::verify).
    #[cfg_attr(feature = "serde", serde(default))]
    pub signature: Option<String>,
}

#[cfg(feature = "audit")]
impl AuditRecord {
    /// Append this record as a single JSONL line to `path` (creates the file if absent).
    #[cfg(all(feature = "serde", not(target_arch = "wasm32")))]
    pub fn append_jsonl(&self, path: &std::path::Path) -> std::io::Result<()> {
        use std::io::Write;
        let line = serde_json::to_string(self).map_err(std::io::Error::other)?;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        writeln!(f, "{}", line)
    }

    /// Signs this record with HMAC-SHA256 and stores the hex digest in `self.signature`.
    ///
    /// The signature covers all fields **except** `signature` itself (which is set to null
    /// before serialization). If `prev_hmac` is set, it is included in the signed content,
    /// creating a tamper-evident chain: altering `prev_hmac` after signing will fail `verify`.
    pub fn sign(&mut self, key: &[u8]) {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let bytes = self.canonical_bytes();
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(&bytes);
        let result = mac.finalize().into_bytes();
        self.signature = Some(result.iter().map(|b| format!("{:02x}", b)).collect());
    }

    /// Verifies this record's HMAC-SHA256 signature against `key`.
    ///
    /// Returns `false` if the record is unsigned, if the hex is malformed, or if the
    /// signature does not match. Uses constant-time comparison to prevent timing attacks.
    pub fn verify(&self, key: &[u8]) -> bool {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let Some(ref sig) = self.signature else {
            return false;
        };
        let Some(sig_bytes) = audit_decode_hex(sig) else {
            return false;
        };
        let bytes = self.canonical_bytes();
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(&bytes);
        mac.verify_slice(&sig_bytes).is_ok()
    }

    /// Canonical serialization for signing: all fields with `signature` set to `None`.
    #[cfg(feature = "serde")]
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut tmp = self.clone();
        tmp.signature = None;
        serde_json::to_vec(&tmp).unwrap_or_default()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit helpers
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "audit")]
pub(crate) fn audit_decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Howard Hinnant's civil_from_days: days-since-epoch → (year, month, day).
#[cfg(all(feature = "audit", not(target_arch = "wasm32")))]
pub(crate) fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

/// Convert unix seconds to `YYYY-MM-DDTHH:MM:SSZ` without chrono.
#[cfg(all(feature = "audit", not(target_arch = "wasm32")))]
pub(crate) fn unix_secs_to_iso8601(secs: i64) -> String {
    let days = secs.div_euclid(86400);
    let tod = secs.rem_euclid(86400);
    let h = tod / 3600;
    let m = (tod % 3600) / 60;
    let s = tod % 60;
    let (y, mo, d) = civil_from_days(days);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, m, s)
}

#[cfg(all(feature = "audit", not(target_arch = "wasm32")))]
pub(crate) fn audit_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    unix_secs_to_iso8601(secs)
}

#[cfg(all(feature = "audit", target_arch = "wasm32"))]
pub(crate) fn audit_timestamp() -> String {
    String::new()
}

#[cfg(feature = "audit")]
pub(crate) fn build_audit_record(
    input_hash: String,
    input_len: usize,
    score: f32,
    halted: bool,
    block_threshold: f32,
    detections: &[Detection],
) -> AuditRecord {
    let blocked = score >= block_threshold;
    let mut seen = std::collections::HashSet::new();
    let passes_fired: Vec<String> = detections
        .iter()
        .filter_map(|d| {
            let name = d.kind.to_string();
            if seen.insert(name.clone()) {
                Some(name)
            } else {
                None
            }
        })
        .collect();
    let detection_records = detections
        .iter()
        .map(|d| DetectionRecord {
            pass: d.kind.to_string(),
            original_len: d.original.chars().count(),
            normalized_len: d.normalized.chars().count(),
            detail: {
                let s = &d.detail;
                if s.len() > 200 {
                    // Byte-index truncation must land on a char boundary or
                    // slicing panics on multi-byte UTF-8.
                    let mut end = 200;
                    while !s.is_char_boundary(end) {
                        end -= 1;
                    }
                    format!("{}...", &s[..end])
                } else {
                    s.clone()
                }
            },
            confidence: d.confidence(),
        })
        .collect();
    AuditRecord {
        input_hash,
        input_len,
        timestamp: audit_timestamp(),
        obfuscation_score: score,
        halted,
        blocked,
        passes_fired,
        detections: detection_records,
        prev_hmac: None,
        signature: None,
    }
}
