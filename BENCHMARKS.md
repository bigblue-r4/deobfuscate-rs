# Benchmarks

Criterion suite in [`benches/deobfuscate_bench.rs`](benches/deobfuscate_bench.rs).
Reproduce with:

```bash
cargo bench --bench deobfuscate_bench
```

## Headline

**~2,000 prompts/sec** (1 KiB benign English prose, all 19 passes, default
config, single thread) — about **0.5 ms of added latency** per typical prompt.
The engine is `Send + Sync` and shares no mutable state, so throughput scales
with cores.

## Methodology

- Input: deterministic benign English prose generated to the target size —
  the common case a gateway pays for on every request. Adversarial inputs are
  benchmarked separately (`adversarial` group) and are generally *faster*
  because HALT/short-circuit paths cut work.
- Whole-pipeline `analyze()` cost, including audit-record construction
  (default features). Criterion defaults: 100 samples, 3 s warm-up.
- Hardware: Intel Core i7-4790 @ 3.60 GHz (2014 desktop, 4c/8t), Linux
  x86_64, `--release`, single thread. A 2014 CPU is the point: numbers below
  are a floor for modern hardware, not a ceiling.
- Regenerated on each minor release; last run **v1.18.0, 2026-07-01**.

## Prompt-size scaling (all 19 passes, default config)

| Prompt size | Mean latency | Prompts/sec (single core) |
|-------------|-------------:|--------------------------:|
| 128 B (chat message) | 104 µs | ~9,600 |
| 1 KiB (typical prompt) | 505 µs | ~2,000 |
| 8 KiB (RAG context) | 3.46 ms | ~290 |
| 64 KiB (long context) | 26.4 ms | ~38 |

Scaling is approximately linear in input length.

## Pass-configuration cost (1 KiB prompt)

| Configuration | Mean latency | Relative |
|---------------|-------------:|---------:|
| All 19 passes (default) | 508 µs | 1.0× |
| Without statistical passes (`EntropyBigram`, `Leetspeak`) | 202 µs | 0.40× |
| Unicode confusable core only (NFC, invisible, BiDi, homoglyph, script-intrusion) | 77 µs | 0.15× |

The per-token statistical passes dominate the budget; deployments that only
need the confusable defense run ~6.5× faster.

## Other groups

- `adversarial/*` — 13 encoding-evasion cases mirroring the README detection
  table (per-attack-category latency).
- `benign/*` — short benign baselines (score 0.0 paths).
- `full_pipeline_13_cases` — all adversarial cases in sequence.
