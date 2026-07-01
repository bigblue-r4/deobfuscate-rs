#![no_main]

use libfuzzer_sys::fuzz_target;

// Config::from_toml must reject or accept arbitrary TOML without panicking,
// and an accepted config must survive a full analyze() call.
fuzz_target!(|data: (&str, &str)| {
    let (toml_src, input) = data;
    if let Ok(config) = deobfuscate::Config::from_toml(toml_src) {
        let _ = deobfuscate::Normalizer::default()
            .with_config(config)
            .analyze(input);
    }
});
