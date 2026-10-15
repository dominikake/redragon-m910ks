#!/usr/bin/env python3
"""
Print one function out of a large objdump disassembly, by address.

Exists because `objdump -d` disassembles linearly from .text and silently
loses instruction alignment in data regions. Around 0x40b000 it starts
emitting bytes as garbage instructions and never recovers, which makes
`grep -A50 40b010` useless. Restarting the disassembly at a known function
boundary recovers it:

    objdump -d vendor/gui/app/OemDrv.exe > /tmp/OemDrv.asm
    python3 tools/re_fn.py /tmp/OemDrv.asm 0x40b010
    python3 tools/re_fn.py /tmp/OemDrv.asm 0x40b680 --count 60 --calls

With --calls it also lists the call targets inside the function, which is
usually what you actually want when tracing a protocol routine.

Usage:
    python3 tools/re_fn.py DISASM VA [--count N] [--calls] [--no-int3]
"""

from __future__ import annotations

import argparse
import re
import sys

INSN = re.compile(r"^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2} )+\s*(\S+)\s*(.*)$")
CALL = re.compile(r"^call\s+(0x[0-9a-f]+|\*%[a-z]+)$")
PUSH_STR = re.compile(r"^push\s+\$(0x[0-9a-f]+)$")


def parse(path: str) -> list[tuple[int, str, str, str]]:
    rows = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            raw = line.rstrip("\n")
            m = INSN.match(raw)
            if m:
                rows.append((int(m.group(1), 16), m.group(2),
                             m.group(3).strip(), raw))
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("disasm")
    ap.add_argument("va", type=lambda s: int(s, 0))
    ap.add_argument("--count", type=int, default=60,
                    help="max instructions to print (default 60)")
    ap.add_argument("--calls", action="store_true",
                    help="also list call targets inside the function")
    ap.add_argument("--keep-int3", action="store_true",
                    help="do not stop at int3 padding")
    args = ap.parse_args()

    rows = parse(args.disasm)
    start = next((i for i, (a, _, _, _) in enumerate(rows) if a == args.va), None)
    if start is None:
        near = min(rows, key=lambda r: abs(r[0] - args.va))
        print(f"address {args.va:#x} not found; nearest is {near[0]:#x}",
              file=sys.stderr)
        return 1

    print(f"function at 0x{args.va:08x}\n")
    calls: list[tuple[int, str]] = []
    strings: list[tuple[int, str]] = []
    shown = 0
    pad = 0
    for a, op, arg, raw in rows[start:]:
        if not args.keep_int3 and op == "int3":
            pad += 1
            if pad > 3 and shown:
                break
            continue
        if shown:
            print(raw)
            shown += 1
        else:
            print(raw)
            shown = 1
        m = CALL.match(f"{op} {arg}")
        if m:
            calls.append((a, m.group(1)))
        m = PUSH_STR.match(f"{op} {arg}")
        if m and arg.startswith("0x"):
            strings.append((a, arg))
        if shown >= args.count:
            break

    if args.calls:
        if calls:
            print("\ncall targets:")
            for a, t in calls:
                print(f"  0x{a:08x} -> {t}")
        if strings:
            print("\npushed immediates (possible string addresses):")
            for a, t in strings:
                print(f"  0x{a:08x} -> {t}")
    return 0


if __name__ == "__main__":
    sys.exit(main())