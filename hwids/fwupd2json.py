#!/usr/bin/env python3
# fwupd2hwid.py - fwupdtool hwids → Stubble .hwids JSON (single-input, exact order)
# Usage: sudo fwupdtool hwids | ./fwupd2hwid.py --compatible lenovo,thinkpad-t14s-oled [-f custom.json]

import argparse
import json
import re
import sys
from pathlib import Path
from uuid import UUID

# ----------------------------------------------------------------------
# Defensive GUID regex: matches {guid} or guid anywhere (indented, case-insensitive, optional dashes/braces)
# ----------------------------------------------------------------------
GUID_RE = re.compile(
    r'[{]?\s*'
    r'([0-9a-fA-F]{8})[-]?([0-9a-fA-F]{4})[-]?([0-5][0-9a-fA-F]{3})[-]?([089abAB][0-9a-fA-F]{3})[-]?([0-9a-fA-F]{12})'
    r'\s*[}]?',
    re.IGNORECASE
)

# Field extraction (MULTILINE for full text)
MANUF_RE = re.compile(r'^Manufacturer:\s*(.+)$', re.MULTILINE)
FAMILY_RE = re.compile(r'^Family:\s*(.+)$', re.MULTILINE)

# ----------------------------------------------------------------------
def extract_guids(text: str) -> list[str]:
    hwids = []  # List for order preservation
    seen = set()  # Temp set for fast dup-check
    for m in GUID_RE.finditer(text):
        guid = f"{m.group(1)}-{m.group(2)}-{m.group(3)}-{m.group(4)}-{m.group(5)}".lower()
        try:
            UUID(guid)
            if guid not in seen:
                seen.add(guid)
                hwids.append(guid)  # Append in discovery order
        except ValueError:
            continue
    return hwids  # Exact sequence—no sorting!

# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="fwupdtool hwids → Stubble .hwids JSON (single-input focus)"
    )
    parser.add_argument("input", nargs="?", help="Input file (or omit for stdin)")
    parser.add_argument("--compatible", required=True, help="DTB compatible string")
    parser.add_argument("-o", "--output-dir", type=Path, default=Path("./json"))
    parser.add_argument("-f", "--output-file", help="Custom output filename (overrides auto-name)")
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)

    # Read input
    if args.input:
        text = Path(args.input).read_text()
        src_name = args.input
    else:
        text = sys.stdin.read()
        src_name = "stdin"

    # Extract fields
    manufacturer = MANUF_RE.search(text)
    family = FAMILY_RE.search(text)
    if not manufacturer or not family:
        print(f"Error: Missing Manufacturer or Family in {src_name}", file=sys.stderr)
        sys.exit(1)

    manuf = manufacturer.group(1).strip()
    fam = family.group(1).strip()
    name = f"{manuf} {fam}"

    # Extract GUIDs (in exact order)
    hwids = extract_guids(text)
    if not hwids:
        print(f"Warning: No GUIDs found in {src_name}", file=sys.stderr)
        sys.exit(1)

    # Build Stubble JSON
    device = {
        "type": "devicetree",
        "name": name,
        "compatible": args.compatible,
        "hwids": hwids
    }

    # Determine output path
    if args.output_file:
        out_path = args.output_dir / args.output_file
    else:
        safe_name = re.sub(r"[^\w\-]", "_", name) + ".json"
        out_path = args.output_dir / safe_name

    # Save
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(device, f, indent=4, ensure_ascii=False)

    print(f"→ {out_path}  ({len(hwids)} hwids)")
# ----------------------------------------------------------------------
if __name__ == "__main__":
    main()
