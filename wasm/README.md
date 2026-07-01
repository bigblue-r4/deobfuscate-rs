# deobfuscate — WebAssembly target

In-browser text deobfuscation via `wasm32-unknown-unknown`.

## Prerequisites

```bash
cargo install wasm-pack
rustup target add wasm32-unknown-unknown
```

## Build

```bash
# From the repo root:
wasm-pack build --target web --out-dir pkg --scope bigblue-r4 -- --features wasm --no-default-features

# Output: pkg/deobfuscate.js  pkg/deobfuscate_bg.wasm  pkg/deobfuscate.d.ts
```

## Verification (no wasm-pack required)

```bash
cargo check --target wasm32-unknown-unknown --features wasm --no-default-features
```

## JS API

```ts
import init, { analyze_text, should_block, score } from './pkg/deobfuscate.js';

await init();  // loads the .wasm binary

// Full analysis — returns a plain JS object
const result = analyze_text(userInput);
result.normalized        // string  — cleaned text for the LLM
result.obfuscation_score // number  — 0.0 to 1.0
result.is_obfuscated     // boolean
result.should_flag       // boolean — score >= 0.25
result.should_block      // boolean — score >= 0.60
result.was_halted        // boolean — CjkSuperposition HALT fired; text was cleared
result.summary           // string  — "score=0.85  detections=[bidi-control, base64]"
result.passes_fired      // string[] — ["BiDiControl", "Base64"]

// Fast single-check variants
const blocked = should_block(userInput);   // boolean
const s       = score(userInput);          // number
```

## TypeScript types

After building with wasm-pack, `pkg/deobfuscate.d.ts` exports:

```ts
export function analyze_text(input: string): {
  normalized: string;
  obfuscation_score: number;
  is_obfuscated: boolean;
  should_flag: boolean;
  should_block: boolean;
  was_halted: boolean;
  summary: string;
  passes_fired: string[];
};
export function should_block(input: string): boolean;
export function score(input: string): number;
```

## Notes

- `Config::from_file` is not available on wasm32 (no filesystem). Use `Config::default()` or `Config::from_toml()` instead.
- The `audit` and `serde` features are excluded when building with `--no-default-features --features wasm` to minimize binary size.
- See `wasm/example.html` for a self-contained browser demo.
