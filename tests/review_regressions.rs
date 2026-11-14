use deobfuscate::{Normalizer, PassKind};

#[test]
fn url_unicode_does_not_panic() {
    let decoded = format!("ignore{}€", "a".repeat(53));
    let encoded: String = decoded.bytes().map(|b| format!("%{b:02X}")).collect();
    let result = Normalizer::new()
        .enable(PassKind::UrlEncoding)
        .analyze(&encoded);
    assert_eq!(result.normalized, decoded);
    assert_eq!(result.detection_kinds(), vec![PassKind::UrlEncoding]);
}

#[cfg(feature = "audit")]
#[test]
fn malformed_unicode_signature_returns_false() {
    let mut record = deobfuscate::analyze("hello").audit;
    record.signature = Some("a€".into());
    assert!(!record.verify(b"key"));
}

#[test]
fn disabled_homoglyph_stays_disabled() {
    let result = Normalizer::new()
        .enable(PassKind::ScriptIntrusion)
        .analyze("іgnore");
    assert!(!result
        .detections
        .iter()
        .any(|d| d.kind == PassKind::Homoglyph));
    assert_eq!(result.normalized, "іgnore");
}

#[test]
fn pass_controls_are_independent() {
    let input = "igіnore";
    for homoglyph in [false, true] {
        for intrusion in [false, true] {
            let mut normalizer = Normalizer::new();
            if homoglyph {
                normalizer = normalizer.enable(PassKind::Homoglyph);
            }
            if intrusion {
                normalizer = normalizer.enable(PassKind::ScriptIntrusion);
            }
            let result = normalizer.analyze(input);
            assert_eq!(
                result.normalized,
                if homoglyph {
                    "iginore".to_string()
                } else {
                    input.into()
                }
            );
            assert_eq!(
                result.detection_kinds(),
                if homoglyph {
                    vec![PassKind::Homoglyph]
                } else if intrusion {
                    vec![PassKind::ScriptIntrusion]
                } else {
                    vec![]
                }
            );
            if !homoglyph {
                assert_eq!(
                    result.obfuscation_score,
                    if intrusion {
                        deobfuscate::Config::default().weight_script
                    } else {
                        0.0
                    }
                );
            }
        }
    }
}

#[cfg(feature = "audit")]
#[test]
fn audit_signature_validation() {
    let mut record = deobfuscate::analyze("hello").audit;
    record.sign(b"key");
    assert!(record.verify(b"key"));
    assert!(!record.verify(b"wrong key"));
    for signature in [
        "".to_string(),
        "a".repeat(63),
        "a".repeat(66),
        "z".repeat(64),
        format!("{}€a", "a".repeat(60)),
    ] {
        record.signature = Some(signature);
        assert!(!record.verify(b"key"));
    }
}
