#![no_main]

use libfuzzer_sys::fuzz_target;

// Core invariant target: analyze() must never panic on arbitrary UTF-8,
// and the result must respect its own scoring contract.
fuzz_target!(|input: &str| {
    let result = deobfuscate::analyze(input);

    assert!(
        (0.0..=1.0).contains(&result.obfuscation_score),
        "score out of range: {}",
        result.obfuscation_score
    );
    if result.should_block() {
        assert!(result.should_flag(), "block implies flag");
    }
    // Exercise the reporting paths too — they must not panic either.
    let _ = result.summary();
    let _ = result.detection_kinds();
});
