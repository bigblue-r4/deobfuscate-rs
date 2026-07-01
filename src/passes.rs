//! The 19 detection/normalization passes, in pipeline order.

use crate::config::Config;
use crate::tables::*;
use crate::types::{Detection, PassKind};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use std::collections::HashMap;
use unicode_normalization::UnicodeNormalization as _;

// ─────────────────────────────────────────────────────────────────────────────
// Script ID helper
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) fn script_id(c: char) -> u8 {
    let n = c as u32;
    if n < 0x0080 {
        return 0;
    }
    if (0x0400..=0x052F).contains(&n) {
        return 1;
    }
    if (0x0370..=0x03FF).contains(&n) || (0x1F00..=0x1FFF).contains(&n) {
        return 2;
    }
    if (0x4E00..=0x9FFF).contains(&n) || (0x3040..=0x30FF).contains(&n) {
        return 3;
    }
    4
}

pub(crate) fn cjk_script_zone(c: char) -> u8 {
    let n = c as u32;
    if n < 0x0080 {
        return 0;
    } // ASCII/Latin
    if (0xFF01..=0xFF5E).contains(&n) {
        return 0;
    } // Fullwidth ASCII — treat as Latin
    if (0x0400..=0x052F).contains(&n) {
        return 1;
    } // Cyrillic
    if (0x0370..=0x03FF).contains(&n) {
        return 2;
    } // Greek
    if (0x4E00..=0x9FFF).contains(&n)
        || (0x3400..=0x4DBF).contains(&n)
        || (0x20000..=0x2A6DF).contains(&n)
        || (0x3040..=0x30FF).contains(&n)  // Hiragana + Katakana
        || (0x3000..=0x303F).contains(&n)  // CJK punctuation (。、「」) — normal in CJK prose
        || (0xAC00..=0xD7AF).contains(&n)  // Hangul syllables
        || (0x1100..=0x11FF).contains(&n)  // Hangul Jamo
        || (0xFF65..=0xFF9F).contains(&n)  // Halfwidth Katakana
        || (0xFFA0..=0xFFBE).contains(&n)
    // Halfwidth Hangul
    {
        return 3;
    } // CJK + Kana + Hangul
    4 // Other
}

// ─────────────────────────────────────────────────────────────────────────────
// Pass implementations
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) fn pass_cjk_superposition(
    text: &mut String,
    detections: &mut Vec<Detection>,
    config: &Config,
) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();

    if n < config.cjk_super_window * 2 {
        return false;
    }

    let zones: Vec<u8> = chars.iter().map(|&c| cjk_script_zone(c)).collect();
    let cjk_count = zones.iter().filter(|&&z| z == 3).count();
    let cjk_frac = cjk_count as f32 / n as f32;
    if cjk_frac < config.cjk_super_min_cjk_frac {
        return false;
    }

    let pair_keys: Vec<u8> = (0..n).map(|i| zones[i] * 5 + zones[n - 1 - i]).collect();

    let mut fired = false;
    let mut spike_pos: usize = 0;
    let mut spike_entropy: f32 = 0.0;

    for i in 0..=(n - config.cjk_super_window) {
        let window = &pair_keys[i..i + config.cjk_super_window];
        let mut freq = [0u32; 25];
        for &k in window {
            freq[k as usize] += 1;
        }
        let mut h: f32 = 0.0;
        for &f in &freq {
            if f > 0 {
                let p = f as f32 / config.cjk_super_window as f32;
                h -= p * p.ln();
            }
        }
        if !fired && h > config.cjk_super_threshold {
            fired = true;
            spike_pos = i;
            spike_entropy = h;
        }
    }

    if !fired {
        return false;
    }

    let seam_end = (spike_pos + config.cjk_super_window).min(n);
    let seam_chars: String = chars[spike_pos..seam_end].iter().collect();
    let mirror_start = n.saturating_sub(spike_pos + config.cjk_super_window);
    let mirror_end = n.saturating_sub(spike_pos);
    let mirror_chars: String = chars[mirror_start..mirror_end].iter().collect();

    detections.push(Detection {
        kind: PassKind::CjkSuperposition,
        original: text.clone(),
        normalized: String::new(),
        detail: format!(
            "script-zone entropy spike {spike_entropy:.2} nats at window {spike_pos} \
             (seam={seam_chars:?} mirror={mirror_chars:?} cjk_frac={cjk_frac:.2})"
        ),
    });
    *text = String::new();
    true
}

pub(crate) fn pass_nfc(text: &mut String, detections: &mut Vec<Detection>) {
    let before_len = text.chars().count();
    let normalized: String = text.nfc().collect();
    if normalized != *text {
        let after_len = normalized.chars().count();
        let collapsed = before_len.saturating_sub(after_len);
        detections.push(Detection {
            kind: PassKind::PreScanNfc,
            original: text.clone(),
            normalized: normalized.clone(),
            detail: format!("NFC collapsed {} composed sequence(s)", collapsed),
        });
        *text = normalized;
    }
}

pub(crate) fn pass_invisible(text: &mut String, detections: &mut Vec<Detection>) {
    let original = text.clone();
    let mut stripped_cps: Vec<u32> = Vec::new();
    let cleaned: String = text
        .chars()
        .filter(|&c| {
            let n = c as u32;
            let invisible =
                VS_RANGE_A.contains(&n) || VS_RANGE_B.contains(&n) || TAG_BLOCK.contains(&n);
            if invisible {
                stripped_cps.push(n);
            }
            !invisible
        })
        .collect();

    if !stripped_cps.is_empty() {
        let count = stripped_cps.len();
        let display: Vec<String> = stripped_cps
            .iter()
            .take(12)
            .map(|&n| format!("U+{:05X}", n))
            .collect();
        let suffix = if count > 12 { "..." } else { "" };
        detections.push(Detection {
            kind: PassKind::InvisibleStrip,
            original,
            normalized: cleaned.clone(),
            detail: format!(
                "stripped {} invisible codepoint(s): [{}{}]",
                count,
                display.join(", "),
                suffix,
            ),
        });
        *text = cleaned;
    }
}

pub(crate) fn pass_bidi(text: &mut String, detections: &mut Vec<Detection>) {
    let original = text.clone();
    let cleaned: String = text
        .chars()
        .filter(|c| !BIDI_CONTROLS.contains(c))
        .collect();
    if cleaned != original {
        let stripped: Vec<String> = original
            .chars()
            .filter(|c| BIDI_CONTROLS.contains(c))
            .map(|c| format!("U+{:04X}", c as u32))
            .collect();
        detections.push(Detection {
            kind: PassKind::BiDiControl,
            original,
            normalized: cleaned.clone(),
            detail: format!("stripped: {}", stripped.join(", ")),
        });
        *text = cleaned;
    }
}

pub(crate) fn pass_fullwidth(text: &mut String, detections: &mut Vec<Detection>) {
    let mut changed = false;
    let normalized: String = text
        .chars()
        .map(|c| {
            let n = c as u32;
            if (0xFF01..=0xFF5E).contains(&n) {
                changed = true;
                char::from_u32(n - 0xFEE0).unwrap_or(c)
            } else if c == '\u{3000}' {
                changed = true;
                ' '
            } else {
                c
            }
        })
        .collect();

    if changed {
        let sample: String = text
            .chars()
            .filter(|c| {
                let n = *c as u32;
                (0xFF01..=0xFF5E).contains(&n) || *c == '\u{3000}'
            })
            .take(8)
            .collect();
        detections.push(Detection {
            kind: PassKind::FullwidthChars,
            original: text.clone(),
            normalized: normalized.clone(),
            detail: format!("fullwidth chars normalized (sample: {:?})", sample),
        });
        *text = normalized;
    }
}

pub(crate) fn pass_backslash_unescape(text: &mut String, detections: &mut Vec<Detection>) {
    let chars: Vec<char> = text.chars().collect();
    let mut result = String::with_capacity(chars.len());
    let mut i = 0;
    let mut stripped = 0usize;
    let mut run_start: Option<usize> = None;

    while i < chars.len() {
        if chars[i] == '\\'
            && i + 1 < chars.len()
            && chars[i + 1].is_ascii()
            && chars[i + 1] != '\n'
            && chars[i + 1] != '\r'
        {
            let is_run = i + 3 < chars.len() && chars[i + 2] == '\\' && chars[i + 3].is_ascii();
            let in_run = run_start.is_some();
            if is_run || in_run {
                if run_start.is_none() {
                    run_start = Some(result.len());
                }
                result.push(chars[i + 1]);
                stripped += 1;
                i += 2;
                continue;
            }
        }
        if run_start.is_some() {
            run_start = None;
        }
        result.push(chars[i]);
        i += 1;
    }

    if stripped >= 3 {
        detections.push(Detection {
            kind: PassKind::BackslashEscape,
            original: text.clone(),
            normalized: result.clone(),
            detail: format!("stripped {stripped} backslash prefixes"),
        });
        *text = result;
    }
}

pub(crate) fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

pub(crate) fn pass_url_decode(text: &mut String, detections: &mut Vec<Detection>, config: &Config) {
    let input = text.clone();
    let bytes = input.as_bytes();
    let n = bytes.len();
    let mut i = 0;
    let mut out = String::with_capacity(n);
    let mut any_fired = false;

    while i < n {
        if bytes[i] == b'%'
            && i + 2 < n
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            let run_start = i;
            let mut raw_bytes: Vec<u8> = Vec::new();

            while i + 2 < n
                && bytes[i] == b'%'
                && bytes[i + 1].is_ascii_hexdigit()
                && bytes[i + 2].is_ascii_hexdigit()
            {
                raw_bytes.push((hex_nibble(bytes[i + 1]) << 4) | hex_nibble(bytes[i + 2]));
                i += 3;
            }

            let raw_span = &input[run_start..i];

            if raw_bytes.len() >= config.url_min_run {
                if let Ok(decoded) = String::from_utf8(raw_bytes) {
                    if is_suspicious_decoded(&decoded) {
                        let orig_d = &raw_span[..raw_span.len().min(60)];
                        let dec_d = &decoded[..decoded.len().min(60)];
                        detections.push(Detection {
                            kind: PassKind::UrlEncoding,
                            original: raw_span.to_string(),
                            normalized: decoded.clone(),
                            detail: format!("url-decoded {:?} → {:?}", orig_d, dec_d),
                        });
                        out.push_str(&decoded);
                        any_fired = true;
                        continue;
                    }
                }
            }
            out.push_str(raw_span);
        } else {
            let c = input[i..].chars().next().unwrap();
            out.push(c);
            i += c.len_utf8();
        }
    }

    if any_fired {
        *text = out;
    }
}

pub(crate) fn try_parse_html_entity(chars: &[char], start: usize) -> Option<(usize, char)> {
    let n = chars.len();
    // Named entities — try semicolon form first (longer match wins)
    const NAMED: &[(&str, char)] = &[
        ("amp;", '&'),
        ("lt;", '<'),
        ("gt;", '>'),
        ("quot;", '"'),
        ("apos;", '\''),
        ("amp", '&'),
        ("lt", '<'),
        ("gt", '>'),
        ("quot", '"'),
        ("apos", '\''),
    ];
    for (name, ch) in NAMED {
        let nc: Vec<char> = name.chars().collect();
        let end = start + 1 + nc.len();
        if end <= n && chars[start + 1..end] == *nc {
            return Some((1 + nc.len(), *ch));
        }
    }
    // Numeric: &#... or &#x...
    if start + 2 < n && chars[start + 1] == '#' {
        let mut j = start + 2;
        if j < n && (chars[j] == 'x' || chars[j] == 'X') {
            j += 1;
            let hex_start = j;
            while j < n && chars[j].is_ascii_hexdigit() {
                j += 1;
            }
            if j > hex_start {
                let hex_str: String = chars[hex_start..j].iter().collect();
                let cp = u32::from_str_radix(&hex_str, 16).ok()?;
                let ch = char::from_u32(cp)?;
                let semi = j < n && chars[j] == ';';
                return Some((j - start + usize::from(semi), ch));
            }
        } else {
            let dec_start = j;
            while j < n && chars[j].is_ascii_digit() {
                j += 1;
            }
            if j > dec_start {
                let dec_str: String = chars[dec_start..j].iter().collect();
                let cp: u32 = dec_str.parse().ok()?;
                let ch = char::from_u32(cp)?;
                let semi = j < n && chars[j] == ';';
                return Some((j - start + usize::from(semi), ch));
            }
        }
    }
    None
}

pub(crate) fn pass_html_entities(
    text: &mut String,
    detections: &mut Vec<Detection>,
    config: &Config,
) {
    let input = text.clone();
    let chars: Vec<char> = input.chars().collect();
    let n = chars.len();
    let mut i = 0;
    let mut out = String::with_capacity(n);
    let mut entity_count = 0usize;

    while i < n {
        if chars[i] == '&' {
            if let Some((len, ch)) = try_parse_html_entity(&chars, i) {
                out.push(ch);
                i += len;
                entity_count += 1;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }

    if entity_count < config.html_min_entities {
        return;
    }

    let lower = out.to_lowercase();
    if let Some(kw) = INJECTION_KEYWORDS.iter().find(|kw| lower.contains(**kw)) {
        detections.push(Detection {
            kind: PassKind::HtmlEntities,
            original: input,
            normalized: out.clone(),
            detail: format!(
                "html-entity decoded {} sequences, result contains {:?}",
                entity_count, kw
            ),
        });
        *text = out;
    }
}

pub(crate) fn pass_base64(text: &mut String, detections: &mut Vec<Detection>, config: &Config) {
    let mut result = text.clone();

    for prefix in &[
        "b64.decode(\"",
        "base64.decode(\"",
        "atob(\"",
        "b64decode(\"",
        "base64decode(\"",
    ] {
        while let Some(start) = result.find(prefix) {
            let after = start + prefix.len();
            if let Some(end) = result[after..].find('"') {
                let b64_str = &result[after..after + end];
                if let Some(decoded) = try_decode_b64(b64_str) {
                    let original_chunk = result[start..after + end + 1].to_string();
                    detections.push(Detection {
                        kind: PassKind::Base64,
                        original: original_chunk,
                        normalized: decoded.clone(),
                        detail: format!("explicit b64 → {:?}", &decoded[..decoded.len().min(60)]),
                    });
                    result.replace_range(start..after + end + 1, &decoded);
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    }

    let words: Vec<&str> = result.split_whitespace().collect();
    let mut new_result = result.clone();
    for word in &words {
        let candidate =
            word.trim_matches(|c: char| !c.is_alphanumeric() && c != '+' && c != '/' && c != '=');
        if candidate.len() < config.base64_min_len {
            continue;
        }
        if !candidate
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        {
            continue;
        }
        if let Some(decoded) = try_decode_b64(candidate) {
            if decoded.len() >= 8 && is_suspicious_decoded(&decoded) {
                detections.push(Detection {
                    kind: PassKind::Base64,
                    original: candidate.to_string(),
                    normalized: decoded.clone(),
                    detail: format!("bare base64 → {:?}", &decoded[..decoded.len().min(60)]),
                });
                new_result = new_result.replacen(candidate, &decoded, 1);
            }
        }
    }

    if new_result != *text {
        *text = new_result;
    }
}

pub(crate) fn try_decode_b64(s: &str) -> Option<String> {
    let stripped = s.trim_end_matches('=');
    let padded = match stripped.len() % 4 {
        0 => stripped.to_string(),
        2 => format!("{stripped}=="),
        3 => format!("{stripped}="),
        _ => return None,
    };
    B64.decode(padded.as_bytes())
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .filter(|s| {
            s.chars()
                .all(|c| c.is_ascii() && (c.is_ascii_graphic() || c == ' ' || c == '\n'))
        })
}

pub(crate) fn is_suspicious_decoded(decoded: &str) -> bool {
    let lower = decoded.to_lowercase();
    INJECTION_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

#[inline]
pub(crate) fn is_morse_char(c: char) -> bool {
    matches!(c, '.' | '-' | '/' | ' ')
}

pub(crate) fn decode_morse_str(morse: &str) -> Option<String> {
    let lookup: HashMap<&str, char> = MORSE_TABLE.iter().map(|(c, p)| (*p, *c)).collect();
    let words: Vec<&str> = morse.split(" / ").collect();
    let mut result = String::new();
    let mut total = 0usize;
    let mut decoded = 0usize;

    for (wi, word) in words.iter().enumerate() {
        if wi > 0 {
            result.push(' ');
        }
        for token in word.split(' ') {
            let token = token.trim_matches(|c: char| !c.is_ascii() || c == ',');
            if token.is_empty() {
                continue;
            }
            total += 1;
            let ch = if token == ".-..-" {
                decoded += 1;
                '/'
            } else if let Some(&c) = lookup.get(token) {
                decoded += 1;
                c
            } else {
                '?'
            };
            result.push(ch);
        }
    }

    if total == 0 {
        return None;
    }
    if decoded * 100 / total < 40 {
        return None;
    }
    if result.trim_matches('?').trim().len() < 2 {
        return None;
    }
    Some(result)
}

pub(crate) fn pass_morse(text: &mut String, detections: &mut Vec<Detection>, config: &Config) {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut result = String::new();
    let mut i = 0;
    let mut any = false;

    while i < n {
        if !is_morse_char(chars[i]) {
            result.push(chars[i]);
            i += 1;
            continue;
        }

        let span_start = i;
        let mut j = i;
        while j < n {
            let c = chars[j];
            if is_morse_char(c) || matches!(c, ',' | ';' | ':' | '!') {
                j += 1;
            } else {
                break;
            }
        }

        let span_len = j - span_start;
        let morse_count = chars[span_start..j]
            .iter()
            .filter(|&&c| is_morse_char(c))
            .count();

        if span_len >= config.morse_min_span
            && morse_count * 100 / span_len >= config.morse_min_morse_pct
        {
            let cleaned: String = chars[span_start..j]
                .iter()
                .filter(|&&c| is_morse_char(c))
                .collect();
            if let Some(decoded_str) = decode_morse_str(&cleaned) {
                let original: String = chars[span_start..j].iter().collect();
                detections.push(Detection {
                    kind: PassKind::MorseCode,
                    original: original.clone(),
                    normalized: decoded_str.clone(),
                    detail: format!(
                        "Morse {:?} → {:?}",
                        &original[..original.len().min(40)],
                        &decoded_str[..decoded_str.len().min(40)]
                    ),
                });
                result.push_str(&decoded_str);
                any = true;
                i = j;
                continue;
            }
        }

        result.push(chars[i]);
        i += 1;
    }

    if any {
        *text = result;
    }
}

pub(crate) fn pass_homoglyphs(
    text: &mut String,
    detections: &mut Vec<Detection>,
    detect_script_intrusion: bool,
) -> f32 {
    let table: HashMap<char, char> = HOMOGLYPHS.iter().copied().collect();
    let chars_before: Vec<char> = text.chars().collect();
    let mut replacements: Vec<(char, char, usize)> = Vec::new();

    // A confusable only counts when its whitespace token is attack-shaped:
    // either mixed with ASCII alphanumerics ("іgnοre") or made up entirely of
    // confusable chars ("𝐢𝐠𝐧𝐨𝐫𝐞", "١٣٣٧"). A confusable letter next to plain
    // punctuation ("the angle (α) is") is legitimate foreign/math text.
    let n_chars = chars_before.len();
    let mut token_replaceable = vec![false; n_chars];
    let mut i = 0;
    while i < n_chars {
        if chars_before[i].is_whitespace() {
            i += 1;
            continue;
        }
        let start = i;
        while i < n_chars && !chars_before[i].is_whitespace() {
            i += 1;
        }
        let token = &chars_before[start..i];
        let has_ascii = token.iter().any(|c| c.is_ascii_alphanumeric());
        let all_confusable = token.iter().all(|c| table.contains_key(c));
        for flag in &mut token_replaceable[start..i] {
            *flag = has_ascii || all_confusable;
        }
    }

    let normalized: String = chars_before
        .iter()
        .enumerate()
        .map(|(i, &c)| {
            if token_replaceable[i] {
                if let Some(&ascii) = table.get(&c) {
                    replacements.push((c, ascii, i));
                    return ascii;
                }
            }
            c
        })
        .collect();

    let scripts: Vec<u8> = chars_before.iter().map(|&c| script_id(c)).collect();
    let n = scripts.len();
    let interference: f32 = if n == 0 {
        0.0
    } else {
        let spike_sum: f32 = scripts
            .iter()
            .enumerate()
            .map(|(i, &fwd)| {
                let rev = scripts[n - 1 - i];
                if fwd != rev && (fwd != 0 || rev != 0) {
                    1.0
                } else {
                    0.0
                }
            })
            .sum();
        let non_ascii = scripts.iter().filter(|&&s| s != 0).count();
        if non_ascii == 0 {
            0.0
        } else {
            (spike_sum / n as f32).min(1.0)
        }
    };

    if !replacements.is_empty() {
        let summary: Vec<String> = replacements
            .iter()
            .take(8)
            .map(|(orig, rep, pos)| format!("U+{:04X} '{}' @{pos}→'{rep}'", *orig as u32, orig))
            .collect();
        detections.push(Detection {
            kind: PassKind::Homoglyph,
            original: text.clone(),
            normalized: normalized.clone(),
            detail: format!(
                "{} replacement(s): {}",
                replacements.len(),
                summary.join("; ")
            ),
        });
        *text = normalized;
    }

    if detect_script_intrusion && replacements.is_empty() && has_script_intrusions(&chars_before) {
        detections.push(Detection {
            kind: PassKind::ScriptIntrusion,
            original: text.clone(),
            normalized: text.clone(),
            detail: "mid-word script switch (non-ASCII embedded in ASCII word)".into(),
        });
    }

    interference
}

pub(crate) fn has_script_intrusions(chars: &[char]) -> bool {
    let text: String = chars.iter().collect();
    for word in text.split_whitespace() {
        let wc: Vec<char> = word.chars().collect();
        if wc.len() < 3 {
            continue;
        }
        // Require ASCII letters/digits — punctuation around a foreign char
        // ("(α)") is not a word for anything to intrude into.
        let ascii = wc.iter().filter(|c| c.is_ascii_alphanumeric()).count();
        let non_ascii: Vec<&char> = wc.iter().filter(|c| !c.is_ascii()).collect();
        if ascii >= 2 && !non_ascii.is_empty() {
            let all_accents = non_ascii
                .iter()
                .all(|&&c| (0x00C0u32..=0x024F).contains(&(c as u32)));
            if !all_accents {
                return true;
            }
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// SkeletonMatch pass — TR39 skeleton algorithm (unicode_skeleton crate)
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) fn pass_skeleton_match(text: &mut String, detections: &mut Vec<Detection>) {
    use unicode_skeleton::UnicodeSkeleton;

    let lower = text.to_lowercase();

    // Pure ASCII text cannot contain non-ASCII confusable chars. Digit→letter and letter→digraph
    // changes in TR39's skeleton (e.g. '0'→'O', 'm'→'rn') are not confusable-char attacks, so
    // we skip the skeleton pass entirely for ASCII input to avoid false positives.
    if lower.is_ascii() {
        return;
    }

    let skeleton: String = lower.skeleton_chars().collect();

    // Only fire if the skeleton reveals an injection keyword that was NOT plainly present in the
    // original lowercased text — meaning confusable chars were used to hide it.
    let matched_kw = INJECTION_KEYWORDS
        .iter()
        .find(|kw| skeleton.contains(**kw) && !lower.contains(**kw));
    let kw = match matched_kw {
        Some(kw) => kw,
        None => return,
    };

    // Collect which chars were flagged as potential mixed-script confusables for the detail.
    let flagged: Vec<char> = lower
        .chars()
        .filter(|c| {
            !c.is_ascii() && unicode_security::is_potential_mixed_script_confusable_char(*c)
        })
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    let detail = if flagged.is_empty() {
        format!(
            "skeleton reduces to keyword '{}'; TR39 confusable substitution detected",
            kw
        )
    } else {
        let flagged_str: String = flagged
            .iter()
            .take(8)
            .map(|c| format!("U+{:04X}'{}'", *c as u32, c))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "skeleton reduces to keyword '{}'; mixed-script confusables: {}",
            kw, flagged_str
        )
    };

    detections.push(Detection {
        kind: PassKind::SkeletonMatch,
        original: text.clone(),
        normalized: skeleton.clone(),
        detail,
    });
    *text = skeleton;
}

pub(crate) fn pass_leet(
    text: &mut String,
    detections: &mut Vec<Detection>,
    config: &Config,
) -> f32 {
    let leet: HashMap<char, char> = LEET_MAP.iter().copied().collect();
    let mut total_chars = 0usize;
    let mut total_leet = 0usize;
    let mut changed = false;
    let mut sample_before = String::new();
    let mut sample_after = String::new();

    let normalized: String = text
        .split_whitespace()
        .map(|word| {
            let chars: Vec<char> = word.chars().collect();
            let leet_count = chars.iter().filter(|c| leet.contains_key(c)).count();
            let alpha_count = chars.iter().filter(|c| c.is_alphanumeric()).count();
            let true_alpha = chars.iter().filter(|c| c.is_ascii_alphabetic()).count();

            // Hex blobs and UUIDs (git SHAs, request IDs) are identifiers,
            // not leetspeak — their digit density is structural.
            let is_hex_identifier = chars.iter().any(|c| c.is_ascii_digit())
                && chars.iter().all(|c| c.is_ascii_hexdigit() || *c == '-');

            if !is_hex_identifier
                && alpha_count >= config.leet_min_alpha
                && true_alpha >= 2
                && leet_count * 100 / alpha_count.max(1) >= config.leet_min_pct
            {
                let decoded: String = chars
                    .iter()
                    .map(|c| leet.get(c).copied().unwrap_or(*c))
                    .collect();
                total_chars += alpha_count;
                total_leet += leet_count;
                if sample_before.is_empty() {
                    sample_before = word.to_string();
                    sample_after = decoded.clone();
                }
                changed = true;
                decoded
            } else {
                word.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");

    if changed {
        detections.push(Detection {
            kind: PassKind::Leetspeak,
            original: text.clone(),
            normalized: normalized.clone(),
            detail: format!(
                "{total_leet} substitution(s) (e.g. {:?} → {:?})",
                sample_before, sample_after
            ),
        });
        *text = normalized;
    }

    if total_chars == 0 {
        0.0
    } else {
        (total_leet as f32 / total_chars as f32).min(1.0)
    }
}

#[allow(clippy::ptr_arg)]
pub(crate) fn pass_entropy_bigram(
    text: &mut String,
    detections: &mut Vec<Detection>,
    config: &Config,
) {
    if text.chars().count() < ENTROPY_INPUT_MIN {
        return;
    }

    let all_chars: Vec<char> = text.chars().collect();
    let cjk_frac = all_chars
        .iter()
        .filter(|&&c| cjk_script_zone(c) == 3)
        .count() as f32
        / all_chars.len() as f32;
    if cjk_frac > ENTROPY_CJK_GATE {
        return;
    }

    let mut worst_token = String::new();
    let mut worst_entropy: f32 = 0.0;
    let mut worst_bigram: f32 = 1.0;
    let mut fired = false;

    for token in text.split_whitespace() {
        let chars: Vec<char> = token.chars().collect();
        let n = chars.len();
        if n < ENTROPY_TOKEN_LEN {
            continue;
        }

        // Hex identifiers (git SHAs, UUIDs) and shell/path fragments are
        // structural, not encoded payloads — their bigram coverage is
        // legitimately low.
        let is_hex_identifier = chars.iter().any(|c| c.is_ascii_digit())
            && chars.iter().all(|c| c.is_ascii_hexdigit() || *c == '-');
        let is_code_shaped = chars
            .iter()
            .any(|c| matches!(c, '$' | '(' | ')' | '{' | '}' | ':' | '\\' | '/'));
        if is_hex_identifier || is_code_shaped {
            continue;
        }

        // Sub-check A: Shannon entropy
        let mut freq: HashMap<char, u32> = HashMap::new();
        for &c in &chars {
            *freq.entry(c).or_insert(0) += 1;
        }
        let entropy: f32 = freq
            .values()
            .map(|&f| {
                let p = f as f32 / n as f32;
                -p * p.log2()
            })
            .sum();

        // Sub-check B: English bigram coverage
        let upper: Vec<char> = chars
            .iter()
            .map(|c| c.to_uppercase().next().unwrap_or(*c))
            .collect();
        let alpha_count = chars.iter().filter(|c| c.is_alphabetic()).count();
        let bigram_score = if alpha_count >= ENTROPY_MIN_ALPHA {
            let pairs = n - 1;
            let hits = (0..pairs)
                .filter(|&i| {
                    ENGLISH_BIGRAMS.iter().any(|&b| {
                        let mut bc = b.chars();
                        bc.next() == Some(upper[i]) && bc.next() == Some(upper[i + 1])
                    })
                })
                .count();
            hits as f32 / pairs as f32
        } else {
            1.0 // not enough alpha chars — assume clean
        };

        let high_entropy = entropy > config.entropy_high;
        let low_bigram =
            alpha_count >= ENTROPY_MIN_ALPHA && bigram_score < config.entropy_min_english;

        if high_entropy || low_bigram {
            let is_worse = !fired || entropy > worst_entropy || bigram_score < worst_bigram;
            if is_worse {
                worst_token = token.to_string();
                worst_entropy = entropy;
                worst_bigram = bigram_score;
            }
            fired = true;
        }
    }

    if fired {
        detections.push(Detection {
            kind: PassKind::EntropyBigram,
            original: text.clone(),
            normalized: text.clone(),
            detail: format!(
                "token {:?} entropy={:.2} bigram_score={:.2}",
                worst_token, worst_entropy, worst_bigram
            ),
        });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Split-string pass
// ─────────────────────────────────────────────────────────────────────────────

#[allow(clippy::ptr_arg)]
pub(crate) fn pass_split_string(text: &mut String, detections: &mut Vec<Detection>) {
    if text.len() < 8 {
        return;
    }

    // Skeleton: (lowercased ascii-alpha char, byte position in original text)
    let skeleton: Vec<(char, usize)> = text
        .char_indices()
        .filter(|(_, c)| c.is_ascii_alphabetic())
        .map(|(i, c)| (c.to_ascii_lowercase(), i))
        .collect();

    // Only check purely alphabetic keywords — non-alpha keywords ("os.system", "system prompt")
    // cannot be matched against an alpha-only skeleton.
    let alpha_keywords: Vec<&str> = INJECTION_KEYWORDS
        .iter()
        .copied()
        .filter(|kw| kw.chars().all(|c| c.is_ascii_alphabetic()))
        .collect();

    let min_kw_len = alpha_keywords
        .iter()
        .map(|kw| kw.len())
        .min()
        .unwrap_or(usize::MAX);
    if skeleton.len() < min_kw_len {
        return;
    }

    let lower_text = text.to_lowercase();
    let skeleton_str: String = skeleton.iter().map(|&(c, _)| c).collect();

    for &keyword in &alpha_keywords {
        if keyword.len() > skeleton.len() {
            continue;
        }
        // Skip verbatim occurrences — already present as plain text, not a split attack.
        if lower_text.contains(keyword) {
            continue;
        }

        // The keyword must be CONTIGUOUS in the alpha skeleton ("ig.no.re" →
        // skeleton "ignore"). A subsequence match with arbitrary gaps flags
        // nearly every English sentence, since keyword letters scattered
        // across ordinary words always exist in order somewhere.
        let mut search_from = 0usize;
        let mut fired = false;
        while !fired {
            let Some(rel) = skeleton_str[search_from..].find(keyword) else {
                break;
            };
            let start = search_from + rel;
            let matched = &skeleton[start..start + keyword.len()];
            search_from = start + 1;

            // Count segments: matched skeleton chars are all ASCII (1 byte),
            // so a byte-position gap > 1 means a separator sits between them.
            let mut segment_count = 1usize;
            for i in 1..matched.len() {
                if matched[i].1 > matched[i - 1].1 + 1 {
                    segment_count += 1;
                }
            }
            if segment_count < 2 {
                continue; // contiguous in the raw text too — not a split attack
            }

            let confidence = if segment_count >= 3 { 1.0f32 } else { 0.5f32 };

            detections.push(Detection {
                kind: PassKind::SplitString,
                original: text.clone(),
                normalized: text.clone(),
                detail: format!(
                    "keyword {:?} reconstructed from {} segments (confidence {:.1})",
                    keyword, segment_count, confidence
                ),
            });
            fired = true;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Punycode pass (RFC 3492)
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) fn punycode_digit(c: char) -> Option<u32> {
    match c {
        'a'..='z' => Some(c as u32 - b'a' as u32),
        'A'..='Z' => Some(c as u32 - b'A' as u32),
        '0'..='9' => Some(c as u32 - b'0' as u32 + 26),
        _ => None,
    }
}

pub(crate) fn punycode_adapt(mut delta: u32, numpoints: u32, firsttime: bool) -> u32 {
    const BASE: u32 = 36;
    const TMIN: u32 = 1;
    const TMAX: u32 = 26;
    const SKEW: u32 = 38;
    const DAMP: u32 = 700;
    delta = if firsttime { delta / DAMP } else { delta / 2 };
    delta += delta / numpoints;
    let mut k: u32 = 0;
    while delta > (BASE - TMIN) * TMAX / 2 {
        delta /= BASE - TMIN;
        k += BASE;
    }
    k + (BASE - TMIN + 1) * delta / (delta + SKEW)
}

/// Decode a bare punycode label (the part after the `xn--` ACE prefix).
pub(crate) fn punycode_decode(encoded: &str) -> Option<String> {
    const BASE: u32 = 36;
    const TMIN: u32 = 1;
    const TMAX: u32 = 26;
    const INITIAL_N: u32 = 128;
    const INITIAL_BIAS: u32 = 72;

    let (basic, ext) = match encoded.rfind('-') {
        Some(p) => (&encoded[..p], &encoded[p + 1..]),
        None => ("", encoded),
    };
    if !basic.chars().all(|c| c.is_ascii_graphic()) {
        return None;
    }

    let mut output: Vec<char> = basic.chars().collect();
    let mut n: u32 = INITIAL_N;
    let mut bias: u32 = INITIAL_BIAS;
    let mut i: u32 = 0;
    let mut iter = ext.chars().peekable();

    while iter.peek().is_some() {
        let oldi = i;
        let mut w: u32 = 1;
        let mut k = BASE;
        loop {
            let digit = punycode_digit(iter.next()?)?;
            i = i.checked_add(digit.checked_mul(w)?)?;
            let t = if k <= bias {
                TMIN
            } else if k >= bias + TMAX {
                TMAX
            } else {
                k - bias
            };
            if digit < t {
                break;
            }
            w = w.checked_mul(BASE - t)?;
            k += BASE;
        }
        let numpoints = (output.len() as u32).checked_add(1)?;
        bias = punycode_adapt(i - oldi, numpoints, oldi == 0);
        n = n.checked_add(i / numpoints)?;
        i %= numpoints;
        output.insert(i as usize, char::from_u32(n)?);
        i += 1;
    }
    Some(output.iter().collect())
}

pub(crate) fn pass_punycode(text: &mut String, detections: &mut Vec<Detection>) {
    let original = text.clone();
    let mut parts: Vec<String> = Vec::new();
    let mut changed = 0usize;
    let mut rest = original.as_str();

    while !rest.is_empty() {
        let gap = rest
            .find(|c: char| !c.is_ascii_whitespace())
            .unwrap_or(rest.len());
        if gap > 0 {
            parts.push(rest[..gap].to_string());
            rest = &rest[gap..];
            continue;
        }
        let end = rest
            .find(|c: char| c.is_ascii_whitespace())
            .unwrap_or(rest.len());
        let token = &rest[..end];

        let decoded_and_normalized = if token.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            let lower = token.to_ascii_lowercase();
            if let Some(label) = lower.strip_prefix("xn--") {
                punycode_decode(label).and_then(|decoded| {
                    if decoded.is_empty() {
                        return None;
                    }
                    // Apply homoglyph normalization to expose confusable-char keywords
                    let normalized: String = decoded
                        .chars()
                        .map(|c| {
                            HOMOGLYPHS
                                .iter()
                                .find(|(src, _)| *src == c)
                                .map(|(_, dst)| *dst)
                                .unwrap_or(c)
                        })
                        .collect();
                    let norm_lower = normalized.to_lowercase();
                    if INJECTION_KEYWORDS.iter().any(|kw| norm_lower.contains(kw)) {
                        Some(normalized)
                    } else {
                        None
                    }
                })
            } else {
                None
            }
        } else {
            None
        };

        if let Some(norm) = decoded_and_normalized {
            parts.push(norm);
            changed += 1;
        } else {
            parts.push(token.to_string());
        }
        rest = &rest[end..];
    }

    if changed == 0 {
        return;
    }

    let result: String = parts.join("");
    detections.push(Detection {
        kind: PassKind::Punycode,
        original,
        normalized: result.clone(),
        detail: format!(
            "xn-- punycode label(s) decoded ({} token(s)), result contains injection keyword",
            changed
        ),
    });
    *text = result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Rot13 pass
// ─────────────────────────────────────────────────────────────────────────────

#[inline]
pub(crate) fn rot13_char(c: char) -> char {
    match c {
        'a'..='z' => (b'a' + (c as u8 - b'a' + 13) % 26) as char,
        'A'..='Z' => (b'A' + (c as u8 - b'A' + 13) % 26) as char,
        _ => c,
    }
}

pub(crate) fn pass_rot13(text: &mut String, detections: &mut Vec<Detection>) {
    // Split on whitespace; only all-ASCII-alpha tokens of ≥4 chars are ROT13-decoded.
    // Reconstruct the decoded text preserving all non-alpha tokens unchanged, then fire
    // only if the decoded text contains an injection keyword.
    let original = text.clone();
    let mut decoded_parts: Vec<String> = Vec::new();
    let mut changed = 0usize;

    // Preserve the whitespace layout by splitting on whitespace boundary runs
    // and tracking whether each chunk is a word token or a gap.
    let mut rest = original.as_str();
    while !rest.is_empty() {
        let gap_end = rest
            .find(|c: char| !c.is_ascii_whitespace())
            .unwrap_or(rest.len());
        if gap_end > 0 {
            decoded_parts.push(rest[..gap_end].to_string());
            rest = &rest[gap_end..];
            continue;
        }
        let word_end = rest
            .find(|c: char| c.is_ascii_whitespace())
            .unwrap_or(rest.len());
        let token = &rest[..word_end];
        if token.len() >= 4 && token.chars().all(|c| c.is_ascii_alphabetic()) {
            let dec: String = token.chars().map(rot13_char).collect();
            changed += 1;
            decoded_parts.push(dec);
        } else {
            decoded_parts.push(token.to_string());
        }
        rest = &rest[word_end..];
    }

    if changed == 0 {
        return;
    }

    let decoded = decoded_parts.join("");
    let decoded_lower = decoded.to_lowercase();
    let original_lower = original.to_lowercase();
    // The keyword must APPEAR because of decoding — a keyword already present
    // verbatim in the original (plain English "system", "instructions") is
    // not evidence of rot13.
    if !INJECTION_KEYWORDS
        .iter()
        .any(|kw| decoded_lower.contains(kw) && !original_lower.contains(kw))
    {
        return;
    }

    detections.push(Detection {
        kind: PassKind::Rot13,
        original,
        normalized: decoded.clone(),
        detail: format!(
            "rot13 decoded {} token(s), result contains injection keyword",
            changed
        ),
    });
    *text = decoded;
}

// ─────────────────────────────────────────────────────────────────────────────
// UnicodeEscape pass
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) fn hex_val(c: char) -> Option<u8> {
    c.to_digit(16).map(|d| d as u8)
}

pub(crate) fn pass_unicode_escape(text: &mut String, detections: &mut Vec<Detection>) {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    if n < 3 {
        return;
    }

    let mut result = String::with_capacity(text.len());
    let mut escape_count: usize = 0;
    let mut fmt_hex = false;
    let mut fmt_unicode = false;
    let mut fmt_braced = false;
    let mut fmt_octal = false;
    let mut i = 0;

    while i < n {
        if chars[i] != '\\' {
            result.push(chars[i]);
            i += 1;
            continue;
        }

        if i + 1 >= n {
            result.push('\\');
            i += 1;
            continue;
        }

        let next = chars[i + 1];

        // Format A: \xHH — hex byte escape
        if next == 'x' && i + 3 < n {
            if let (Some(d1), Some(d2)) = (hex_val(chars[i + 2]), hex_val(chars[i + 3])) {
                let byte_val = (d1 << 4) | d2;
                if byte_val < 0x80 {
                    result.push(char::from(byte_val));
                    escape_count += 1;
                    fmt_hex = true;
                    i += 4;
                    continue;
                }
            }
        }

        // Format C: \u{HEX} — braced Unicode escape (check before Format B)
        if next == 'u' && i + 3 < n && chars[i + 2] == '{' {
            let start = i + 3;
            let mut j = start;
            while j < n && j - start < 6 && chars[j].is_ascii_hexdigit() {
                j += 1;
            }
            if j > start && j < n && chars[j] == '}' {
                let hex_str: String = chars[start..j].iter().collect();
                if let Ok(val) = u32::from_str_radix(&hex_str, 16) {
                    if let Some(c) = char::from_u32(val) {
                        result.push(c);
                        escape_count += 1;
                        fmt_braced = true;
                        i = j + 1;
                        continue;
                    }
                }
            }
        }

        // Format B: \uHHHH — 4-digit Unicode escape (JS/Java style)
        if next == 'u' && i + 5 < n && chars[i + 2] != '{' {
            let parsed: Option<Vec<u8>> = (0..4).map(|k| hex_val(chars[i + 2 + k])).collect();
            if let Some(hv) = parsed {
                let val = hv.iter().fold(0u32, |acc, &b| (acc << 4) | b as u32);
                if let Some(c) = char::from_u32(val) {
                    result.push(c);
                    escape_count += 1;
                    fmt_unicode = true;
                    i += 6;
                    continue;
                }
            }
        }

        // Format D: \NNN — octal escape (1-3 octal digits)
        // Only count toward escape_count if 2-3 digits (single-digit octal = common null/etc.)
        if next.is_ascii_digit() && (next as u8) <= b'7' {
            let start = i + 1;
            let mut j = start;
            while j < n && j - start < 3 && chars[j].is_ascii_digit() && (chars[j] as u8) <= b'7' {
                j += 1;
            }
            let digit_count = j - start;
            let oct_str: String = chars[start..j].iter().collect();
            if let Ok(val) = u32::from_str_radix(&oct_str, 8) {
                if val <= 0xFF {
                    if let Some(c) = char::from_u32(val) {
                        result.push(c);
                        if digit_count >= 2 {
                            escape_count += 1;
                            fmt_octal = true;
                        }
                        i = j;
                        continue;
                    }
                }
            }
        }

        // Not a recognized escape format — copy verbatim
        result.push('\\');
        i += 1;
    }

    let lower_decoded = result.to_lowercase();
    let keyword_found = INJECTION_KEYWORDS
        .iter()
        .any(|kw| lower_decoded.contains(kw));

    let should_fire = (escape_count >= 1 && keyword_found) || escape_count >= 4;
    if !should_fire {
        return;
    }

    let mut formats_seen: Vec<&str> = Vec::new();
    if fmt_hex {
        formats_seen.push("hex");
    }
    if fmt_unicode {
        formats_seen.push("unicode");
    }
    if fmt_braced {
        formats_seen.push("braced-unicode");
    }
    if fmt_octal {
        formats_seen.push("octal");
    }

    let detail = format!(
        "unicode-escape decoded {} sequence(s) [{}]; result contains keyword: {}",
        escape_count,
        formats_seen.join(","),
        keyword_found,
    );

    detections.push(Detection {
        kind: PassKind::UnicodeEscape,
        original: text.clone(),
        normalized: result.clone(),
        detail,
    });
    *text = result;
}
