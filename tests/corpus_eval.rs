//! Corpus-level detection-rate regression gate.
//!
//! The corpora live in `tests/corpus/*.jsonl`. `examples/corpus_eval.rs`
//! prints the full per-category breakdown; this test enforces the headline
//! numbers so a pass change that hurts either rate fails CI.

use std::path::Path;

fn load_corpus(name: &str) -> Vec<(String, String)> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/corpus")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let v: serde_json::Value = serde_json::from_str(line).expect("valid JSONL line");
            (
                v["category"].as_str().expect("category").to_string(),
                v["text"].as_str().expect("text").to_string(),
            )
        })
        .collect()
}

#[test]
fn adversarial_corpus_fully_detected() {
    let corpus = load_corpus("adversarial.jsonl");
    assert!(corpus.len() >= 20, "adversarial corpus shrank unexpectedly");
    let misses: Vec<String> = corpus
        .iter()
        .filter(|(_, text)| !deobfuscate::analyze(text).should_flag())
        .map(|(cat, text)| format!("[{cat}] {text:?}"))
        .collect();
    assert!(
        misses.is_empty(),
        "adversarial samples not flagged:\n{}",
        misses.join("\n")
    );
}

#[test]
fn benign_corpus_zero_false_positives() {
    let corpus = load_corpus("benign.jsonl");
    assert!(corpus.len() >= 20, "benign corpus shrank unexpectedly");
    let false_positives: Vec<String> = corpus
        .iter()
        .filter_map(|(cat, text)| {
            let r = deobfuscate::analyze(text);
            r.should_flag().then(|| {
                format!(
                    "[{cat}] score={:.2} passes={:?} {text:?}",
                    r.obfuscation_score,
                    r.detection_kinds()
                )
            })
        })
        .collect();
    assert!(
        false_positives.is_empty(),
        "benign samples flagged:\n{}",
        false_positives.join("\n")
    );
}
