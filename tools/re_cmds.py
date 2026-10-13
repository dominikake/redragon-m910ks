#!/usr/bin/env python3
"""
Recover the Sino Wealth command table from the vendor binary's disassembly.

Background: the `0x01..0xFF` sweep in sweep.py uses an echo oracle -- it
sends a command and checks whether byte 1 of the reply echoes it. That finds
every command the firmware *answers*. It cannot find a command that only
*writes*, because a write never echoes. That is how 0x12, 0x22 and 0x30 came
to be recorded as "empty" or "never sent" when the vendor app plainly uses
them.

Reading the app's own code sidesteps the oracle entirely: the command ids are
stored as immediate byte writes into the stack frame that is about to be
handed to SendCmd or GetCmd.

Both entry points take a 5-byte struct {cmd, a1, a2, a3, a4} built on the
stack immediately before the call. So: find each call, walk backwards over
the preceding instructions, and collect the `movb $imm, disp(%esp)` writes.

Input is an objdump disassembly, not the binary, because reading
instructions is easier to verify than reading machine code:

    objdump -d vendor/gui/app/OemDrv.exe > /tmp/OemDrv.asm
    python3 tools/re_cmds.py /tmp/OemDrv.asm

Usage:
    python3 tools/re_cmds.py DISASM [--send 0x409f80] [--get 0x40a150]
"""

from __future__ import annotations

import argparse
import re
import sys

INSN = re.compile(r"^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2} )+\s*(\S+)\s*(.*)$")
CALL = re.compile(r"^call\s+0x([0-9a-f]+)$")
MOVB_IMM = re.compile(r"^movb\s+\$0x([0-9a-f]+),")

DEFAULT_SEND = 0x409F80     # SendCmd
DEFAULT_GET = 0x40A150      # GetCmd


def parse(path: str) -> list[tuple[int, str, str]]:
    rows = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = INSN.match(line.rstrip("\n"))
            if m:
                rows.append((int(m.group(1), 16), m.group(2), m.group(3).strip()))
    return rows


def extract(rows, send: int, get: int, window: int = 60) -> list[dict]:
    """
    For each call into send/get, collect the movb immediates just before.

    `window` is how far back to look. 14 is enough for the short query
    routines; the bulk writers (SetMatrix, SetMacro) build a large frame
    first, so pass --window 60 for those.
    """
    hits = []
    for idx, (addr, op, arg) in enumerate(rows):
        m = CALL.match(f"{op} {arg}")
        if not m or int(m.group(1), 16) not in (send, get):
            continue
        written = []
        for j in range(idx - 1, max(idx - window, 0) - 1, -1):
            a2, op2, arg2 = rows[j]
            if op2 in ("ret", "int3"):
                break
            mb = MOVB_IMM.match(f"{op2} {arg2}")
            if mb:
                written.append((a2, int(mb.group(1), 16)))
        if written:
            hits.append({
                "call": addr,
                "fn": "SendCmd" if int(m.group(1), 16) == send else "GetCmd",
                "bytes": list(reversed(written)),
            })
    return hits


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("disasm", help="objdump -d output of OemDrv.exe")
    ap.add_argument("--send", type=lambda s: int(s, 0), default=DEFAULT_SEND)
    ap.add_argument("--get", type=lambda s: int(s, 0), default=DEFAULT_GET)
    ap.add_argument("--window", type=int, default=60,
                    help="instructions to look back for movb immediates "
                         "(60 catches the bulk writers)")
    args = ap.parse_args()

    rows = parse(args.disasm)
    hits = extract(rows, args.send, args.get, window=args.window)

    print(f"{len(rows)} instructions parsed, {len(hits)} call site(s) "
          f"into SendCmd/GetCmd\n")
    print(f"{'call site':<12} {'fn':<8} command bytes written just before")
    print("-" * 62)
    for h in hits:
        desc = "  ".join(f"0x{a:x}=0x{v:02x}" for a, v in h["bytes"])
        print(f"0x{h['call']:08x}   {h['fn']:<8} {desc}")

    values = sorted({v for h in hits for _, v in h["bytes"]})
    print(f"\ndistinct immediate bytes: "
          f"{' '.join(f'0x{v:02x}' for v in values)}")
    print("\nCaveat: this reports every movb immediate near the call, not just\n"
          "the command byte. The command byte is the first one written. See\n"
          "docs/GUI-ANALYSIS.md for the interpreted table.")
    return 0


if __name__ == "__main__":
    sys.exit(main())