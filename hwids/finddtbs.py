#!/usr/bin/python3
# SPDX-License-Identifier: 0BSD

from pathlib import Path
import json
import sys
import glob
import libfdt

def collect_compats(jsondir: Path):
    compats = []
    json_files = jsondir.rglob('*.json')
    for json_file in json_files:
        with open(json_file, 'r', encoding='utf-8') as f:
            j = json.load(f)

            # Having FIXME! as compatible is probably an error
            if j['compatible'] == 'FIXME!':
                print("warning: {} contains \"compatible: FIXME!\"".format(json_file));

            compats.append(j['compatible'])
    return compats

def find_dtbs(dtbdir: Path, compatibles_in: list[str]):
    files = []
    dtb_files = dtbdir.glob('**/*[!el2].dtb')
    for dtb_file in dtb_files:
        # XXX: Filter el2
        with open(dtb_file, 'rb') as f:
            fdt = libfdt.Fdt(f.read())
            root = fdt.path_offset('/')
            compatibles = fdt.getprop(root, 'compatible').as_stringlist()
            # XXX: Check duplicates?
            if set(compatibles_in).intersection(compatibles) != set():
                files.append(dtb_file)
    return files

jsondir = Path('./json')
dtbdir =  Path()

if len(sys.argv) > 1:
    dtbdir = Path(sys.argv[1])

if len(sys.argv) > 2:
    jsondir = Path(sys.argv[2])

compats = collect_compats(jsondir)
dtb_paths = find_dtbs(dtbdir, compats)
for p in dtb_paths:
    print("{}".format(p))
