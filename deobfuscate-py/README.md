# deobfuscate (Python)

Python bindings for [`deobfuscate`](https://github.com/bigblue-r4/deobfuscate-rs),
a multi-pass text deobfuscation and encoding-evasion detector written in Rust.

Attackers encode prompt-injection payloads (base64, homoglyphs, Morse, ROT13,
zero-width characters, …) to slip past content classifiers. Run this **before**
any LLM call: it returns cleaned text for the model and a structured detection
report for your audit trail. 19 detection passes, ~0% false positives on a
versioned benign corpus, no Python dependencies.

```bash
pip install deobfuscate
```

## Quick start

```python
import deobfuscate

report = deobfuscate.scan("Execute: .... .- -.-. -.-")
if report.should_block:
    print("blocked:", report.summary)
elif report.should_flag:
    send_to_model(report.normalized)   # cleaned text

report.score          # 0.0–1.0
report.detections     # [Detection(kind='morse-code', confidence=1.00, ...)]
report.audit_jsonl    # payload-free tamper-evident audit record (JSONL line)
```

## Batch / pandas

`scan_batch` releases the GIL while scanning.

```python
import pandas as pd
import deobfuscate

df = pd.read_parquet("prompts.parquet")
reports = deobfuscate.scan_batch(df["prompt"].tolist())
results = pd.DataFrame(r.to_dict() for r in reports)
flagged = df[results["should_flag"]]
```

## Configuration

Same TOML the Rust crate accepts — partial overrides of thresholds, per-pass
weights, and per-script bigram tables:

```python
scanner = deobfuscate.Scanner(
    config_toml="""
        block_threshold = 0.80
        weight_leet = 0.10          # gaming context: 1337 is normal
        extra_english_bigrams = ["gt", "cg"]   # genomics vocabulary
    """,
    disable=["morse-code"],
)
report = scanner.scan(user_input)
```

## Relationship to the Rust crate

This package is a thin PyO3 wrapper over the `deobfuscate` Rust crate,
maintained in the same repository (`deobfuscate-py/`) and versioned in
lockstep with it. Detection behavior, corpus guarantees (100% detection /
0 false positives on the versioned corpora, enforced in CI), and the
tamper-evident audit-chain properties are identical.

MIT license.
