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

    objdump -d vendor/gui/app/OemDrv.exe > vendor/OemDrv.asm
    python3 tools/re_cmds.py vendor/OemDrv.asm

Scratch goes in vendor/, not /tmp -- see the section of the same name in
docs/GUI-ANALYSIS.md. A /tmp wipe has already destroyed this analysis once.

Usage:
    python3 tools/re_cmds.py DISASM [--send 0x409f80] [--get 0x40a150]
"""

from __future__ import annotations

import argparse
import re
import sys

# Group 2 is the raw byte column. Capturing it is what makes address
# contiguity checkable: if the previous instruction is N bytes long, its
# successor must begin at prev+N.
INSN = re.compile(
    r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s*(\S+)\s*(.*)$")

# objdump prints at most 7 bytes of an instruction on its first line and
# spills the rest onto a continuation line that has an address and bytes but
# no mnemonic. `movl $0x0,0x15(%esp)` is 8 bytes, so it lands on two lines.
# Without the merge below those spill lines parse as real instructions named
# "00" (or "ff"), the length of the instruction they belong to comes out
# short, and the contiguity check reports a gap that is not there -- which
# silently truncates the walk and drops the command byte behind it.
CONT = re.compile(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s*$")

CALL = re.compile(r"^call\s+0x([0-9a-f]+)$")
MOVB_IMM = re.compile(r"^movb\s+\$0x([0-9a-f]+),")

DEFAULT_SEND = 0x409F80     # SendCmd
DEFAULT_GET = 0x40A150      # GetCmd

# 60, not 14. The short query routines do finish inside 14 instructions, but
# GetCmd at 0x40a727 and 0x40a7fb build a larger frame first and need 30+.
# A default of 14 silently reports 3 of the 6 real call sites, so a bare
# `python3 tools/re_cmds.py vendor/OemDrv.asm` stops reproducing the table
# docs/GUI-ANALYSIS.md quotes.
DEFAULT_WINDOW = 60


def insn_length(byte_col: str) -> int:
    """Instruction length in bytes, from objdump's byte column.

    INSN only matches a complete, space-terminated byte group, so this is
    always well-defined for rows that came out of parse().
    """
    return len(byte_col.split())


def parse(path: str) -> list[tuple[int, str, str, int]]:
    """[(addr, mnemonic, operands, length)] from objdump -d output.

    Continuation lines are folded into the length of the instruction they
    spill from. Every such line in a full OemDrv.exe dump begins exactly at
    prev_addr + prev_len, so the arithmetic is unambiguous; a line that does
    not follow on is left alone and the contiguity check will stop there.
    """
    rows = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            raw = line.rstrip("\n")
            m = INSN.match(raw)
            if m:
                rows.append([int(m.group(1), 16), m.group(3),
                             m.group(4).strip(), insn_length(m.group(2))])
                continue
            c = CONT.match(raw)
            if c and rows:
                addr, n = int(c.group(1), 16), len(c.group(2).split())
                prev = rows[-1]
                if addr == prev[0] + prev[3]:
                    prev[3] += n
    return [tuple(r) for r in rows]


def extract(rows, send: int, get: int, window: int = DEFAULT_WINDOW) -> list[dict]:
    """
    For each call into send/get, collect the movb immediates just before.

    The backward walk stops at the first of: `ret`, `int3`, a `(bad)` line, or
    an **address discontinuity**. The last one matters most. This tool exists
    because objdump "loses instruction alignment in data regions near
    0x40b000 and never recovers", and in such a region the recovered text
    contains no genuine ret/int3 -- so a walk bounded only by those runs the
    full window through unrelated code and data and attributes every movb
    immediate it passes to one call site. Checking that each instruction
    begins exactly where the previous one ended turns that silent
    misattribution into a reported boundary. On the real OemDrv.exe dump that
    check finds ~2900 discontinuities.

    What survives is the contiguous run immediately before the call. Anything
    past the first gap is dropped, so an immediate on the far side of a gap is
    never attributed -- which is the conservative direction.

    `window` is how far back to look. The default is deliberately generous:
    GetCmd at 0x40a727 and 0x40a7fb need 30+ instructions, so a tight window
    reports fewer call sites than exist. Truncation is visible in the output
    as "stopped at window of N".
    """
    hits = []
    for idx, (addr, op, arg, _n) in enumerate(rows):
        m = CALL.match(f"{op} {arg}")
        if not m or int(m.group(1), 16) not in (send, get):
            continue
        written = []
        stop_reason = f"window of {window}"
        for j in range(idx - 1, max(idx - window, 0) - 1, -1):
            a2, op2, arg2, n2 = rows[j]
            # (bad) first: those bytes are not a valid instruction, so
            # nothing behind them can be trusted whatever the arithmetic
            # says. Its 1-byte width would usually read as a gap anyway.
            if op2 == "(bad)":
                stop_reason = f"(bad) at 0x{a2:08x}"
                break
            if op2 in ("ret", "int3"):
                stop_reason = f"{op2} at 0x{a2:08x}"
                break
            # Contiguity. An instruction of length L at address A occupies
            # [A, A+L), so the *next* one must begin at A+L -- i.e. this row's
            # own length is what constrains the row after it.
            a_next = rows[j + 1][0]
            if a2 + n2 != a_next:
                stop_reason = (f"address gap at 0x{a2:08x} "
                               f"(0x{a2 + n2:08x} expected, "
                               f"0x{a_next:08x} found)")
                break
            mb = MOVB_IMM.match(f"{op2} {arg2}")
            if mb:
                written.append((a2, int(mb.group(1), 16)))
        if written:
            hits.append({
                "call": addr,
                "fn": "SendCmd" if int(m.group(1), 16) == send else "GetCmd",
                "bytes": list(reversed(written)),
                "stop": stop_reason,
            })
    return hits


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("disasm", help="objdump -d output of OemDrv.exe")
    ap.add_argument("--send", type=lambda s: int(s, 0), default=DEFAULT_SEND)
    ap.add_argument("--get", type=lambda s: int(s, 0), default=DEFAULT_GET)
    ap.add_argument("--window", type=int, default=DEFAULT_WINDOW,
                    help="instructions to look back for movb immediates "
                         f"(default {DEFAULT_WINDOW})")
    args = ap.parse_args()

    rows = parse(args.disasm)
    hits = extract(rows, args.send, args.get, window=args.window)

    print(f"{len(rows)} instructions parsed, {len(hits)} call site(s) "
          f"into SendCmd/GetCmd")
    print(f"look-back window: {args.window} instruction(s)\n")
    print(f"{'call site':<12} {'fn':<8} command bytes written just before")
    print("-" * 62)
    for h in hits:
        desc = "  ".join(f"0x{a:x}=0x{v:02x}" for a, v in h["bytes"])
        print(f"0x{h['call']:08x}   {h['fn']:<8} {desc}")

    values = sorted({v for h in hits for _, v in h["bytes"]})
    print(f"\ndistinct immediate bytes: "
          f"{' '.join(f'0x{v:02x}' for v in values)}")

    bounded = [h for h in hits if not h["stop"].startswith("window of")]
    if bounded:
        print(f"\n{len(bounded)} of {len(hits)} call site(s) hit a real code "
              f"boundary rather than the window edge:\n")
        for h in bounded:
            print(f"  0x{h['call']:08x}  {h['fn']:<8} stopped at {h['stop']}")

    print("\nCaveat: this reports every movb immediate in the contiguous run "
          "before\nthe call, not just the command byte -- some are packet "
          "constants, not\ncommand ids. The command byte is the first one "
          "written. See\ndocs/GUI-ANALYSIS.md for the interpreted table.")
    return 0


if __name__ == "__main__":
    sys.exit(main())