//! Corpus-level detection-rate evaluation.
//!
//! Runs `analyze()` over the adversarial and benign corpora in
//! `tests/corpus/` and prints detection rate, block rate, and
//! false-positive rate at default thresholds.
//!
//! ```bash
//! cargo run --example corpus_eval
//! ```

use std::collections::BTreeMap;
use std::path::Path;

fn load_corpus(path: &Path) -> Vec<(String, String)> {
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    raw.lines()
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

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let adversarial = load_corpus(&root.join("adversarial.jsonl"));
    let benign = load_corpus(&root.join("benign.jsonl"));

    println!("== Adversarial corpus ({} samples) ==", adversarial.len());
    let mut by_cat: BTreeMap<String, (usize, usize, usize)> = BTreeMap::new();
    let (mut flagged, mut blocked) = (0usize, 0usize);
    for (cat, text) in &adversarial {
        let r = deobfuscate::analyze(text);
        let e = by_cat.entry(cat.clone()).or_default();
        e.0 += 1;
        if r.should_flag() {
            e.1 += 1;
            flagged += 1;
        } else {
            println!("  MISS [{cat}] score={:.2}  {text:?}", r.obfuscation_score);
        }
        if r.should_block() {
            e.2 += 1;
            blocked += 1;
        }
    }
    println!(
        "\n  {:<20} {:>5} {:>8} {:>8}",
        "category", "n", "flagged", "blocked"
    );
    for (cat, (n, f, b)) in &by_cat {
        println!("  {cat:<20} {n:>5} {f:>8} {b:>8}");
    }
    println!(
        "\n  detection rate (flag): {}/{} = {:.1}%",
        flagged,
        adversarial.len(),
        100.0 * flagged as f64 / adversarial.len() as f64
    );
    println!(
        "  block rate:            {}/{} = {:.1}%",
        blocked,
        adversarial.len(),
        100.0 * blocked as f64 / adversarial.len() as f64
    );

    println!("\n== Benign corpus ({} samples) ==", benign.len());
    let mut false_positives = 0usize;
    for (cat, text) in &benign {
        let r = deobfuscate::analyze(text);
        if r.should_flag() {
            false_positives += 1;
            println!(
                "  FALSE POSITIVE [{cat}] score={:.2} passes={:?}  {text:?}",
                r.obfuscation_score,
                r.detection_kinds()
            );
        }
    }
    println!(
        "\n  false-positive rate (flag): {}/{} = {:.1}%",
        false_positives,
        benign.len(),
        100.0 * false_positives as f64 / benign.len() as f64
    );
}
