#!/usr/bin/env python3
"""Audit src/tables.rs HOMOGLYPHS against Unicode UTS #39 confusables.txt.

The static HOMOGLYPHS table is the hot path for confusable normalization;
SkeletonMatch (unicode-security crate) is the algorithmic TR39 fallback.
When Unicode publishes a new confusables.txt, run this script to find
single-char -> single-ASCII mappings the table is missing.

Usage:
    scripts/check_homoglyphs.py                  # download latest confusables.txt
    scripts/check_homoglyphs.py confusables.txt  # use a local copy
    scripts/check_homoglyphs.py --emit           # print missing entries as Rust code

Exit status: 0 if the table covers all upstream single-char->ASCII mappings
(outside the documented exclusions), 1 otherwise. Stdlib only.

Documented exclusions (never reported as missing):
- Fullwidth Latin U+FF01-FF5E  — handled by the FullwidthChars pass
- ASCII sources                — nothing to normalize
- Combining marks / modifier letters (Sk, Mn) that TR39 maps to quote-like
  ASCII — the table only targets alphanumerics
"""

import re
import sys
import unicodedata
import urllib.request
from pathlib import Path

UPSTREAM = "https://www.unicode.org/Public/security/latest/confusables.txt"
TABLES_RS = Path(__file__).resolve().parent.parent / "src" / "tables.rs"

# Table scope: sources the static table intentionally does not carry.
def excluded(cp: int) -> bool:
    if cp < 0x80:  # ASCII source
        return True
    if 0xFF01 <= cp <= 0xFF5E:  # fullwidth Latin — FullwidthChars pass
        return True
    cat = unicodedata.category(chr(cp))
    if cat in ("Mn", "Me", "Sk", "Lm"):  # marks/modifiers -> quote-like ASCII
        return True
    return False


def parse_confusables(text: str) -> tuple[str, dict[int, str]]:
    """Return (version, {source_cp: ascii_target}) for single->single mappings
    whose target is one ASCII alphanumeric char."""
    version = "unknown"
    mappings: dict[int, str] = {}
    for line in text.splitlines():
        if line.startswith("# Version:"):
            version = line.split(":", 1)[1].strip()
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        fields = [f.strip() for f in line.split(";")]
        if len(fields) < 2:
            continue
        src_cps = fields[0].split()
        tgt_cps = fields[1].split()
        if len(src_cps) != 1 or len(tgt_cps) != 1:
            continue
        src, tgt = int(src_cps[0], 16), int(tgt_cps[0], 16)
        if tgt < 0x80 and chr(tgt).isalnum():
            mappings[src] = chr(tgt)
    return version, mappings


def parse_table(text: str) -> dict[int, str]:
    """Extract {source_cp: ascii_target} from the HOMOGLYPHS const in tables.rs."""
    m = re.search(
        r"pub\(crate\) const HOMOGLYPHS.*?=\s*&\[(.*?)^\];", text, re.S | re.M
    )
    if not m:
        sys.exit("error: HOMOGLYPHS const not found in src/tables.rs")
    entries = re.findall(r"\('\\u\{([0-9A-Fa-f]+)\}',\s*'(\\?.)'\)", m.group(1))
    # Unescape Rust char literals like '\'' and '\\'.
    return {int(cp, 16): tgt.lstrip("\\") for cp, tgt in entries}


def main() -> int:
    emit = "--emit" in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if args:
        source = Path(args[0]).read_text(encoding="utf-8")
    else:
        print(f"downloading {UPSTREAM} ...", file=sys.stderr)
        source = urllib.request.urlopen(UPSTREAM, timeout=30).read().decode("utf-8")

    version, upstream = parse_confusables(source)
    table = parse_table(TABLES_RS.read_text(encoding="utf-8"))

    missing = {
        cp: tgt for cp, tgt in upstream.items() if cp not in table and not excluded(cp)
    }
    # Table entries upstream doesn't have (curated extras: Arabic-Indic digits,
    # enclosed alphanumerics, ...). Informational only.
    extra = {cp: tgt for cp, tgt in table.items() if cp not in upstream}

    print(f"confusables.txt version: {version}")
    print(f"upstream single-char -> ASCII-alnum mappings: {len(upstream)}")
    print(f"HOMOGLYPHS table entries: {len(table)}")
    print(f"curated extras not in upstream (expected): {len(extra)}")
    print(f"upstream mappings missing from table: {len(missing)}")

    if missing:
        print()
        for cp in sorted(missing):
            tgt = missing[cp]
            name = unicodedata.name(chr(cp), "<unnamed>")
            if emit:
                print(f"    ('\\u{{{cp:04X}}}', '{tgt}'), // {chr(cp)} {name}")
            else:
                print(f"  U+{cp:04X} {chr(cp)} -> {tgt}  ({name})")
        return 1
    print("OK: table covers all in-scope upstream mappings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
