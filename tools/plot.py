#!/usr/bin/env python3
"""
Render the recorded battery history as a discharge curve.

This is the evidence that matters: a smooth, monotonic decline under use
(and a rise while charging) is what distinguishes a real fuel gauge from a
field that merely happens to contain a plausible number.

Usage:
    python3 tools/plot.py                 # ASCII chart to stdout
    python3 tools/plot.py --json          # summary stats as JSON
    python3 tools/plot.py --csv > b.csv   # raw data for a real graph

Read-only. Never sends 0x75 (DFU).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import history  # noqa: E402

WIDTH = 64
HEIGHT = 12


def ascii_chart(points: list[dict]) -> str:
    if not points:
        return "no history recorded yet"

    xs = list(range(len(points)))
    ys = [p["percent"] for p in points]
    lo, hi = min(ys), max(ys)
    span = max(1, hi - lo)

    grid = [[" "] * WIDTH for _ in range(HEIGHT)]
    for x, y in zip(xs, points and xs and ys):
        col = 0 if len(points) == 1 else int(x * (WIDTH - 1) / (len(points) - 1))
        row = HEIGHT - 1 - int((y - lo) * (HEIGHT - 1) / span)
        grid[row][col] = "*"

    lines = []
    for i, row in enumerate(grid):
        label = hi - int(span * (HEIGHT - 1 - i) / (HEIGHT - 1))
        lines.append(f"{label:3d}% |" + "".join(row))
    lines.append("     +" + "-" * WIDTH)

    first = points[0]
    last = points[-1]
    span_h = (last["ts"] - first["ts"]) / 3600.0
    lines.append(f"      {len(points)} readings over {span_h:.1f} h")
    lines.append(f"      {first['iso']}  {first['percent']}%")
    lines.append(f"      {last['iso']}  {last['percent']}%")
    return "\n".join(lines)


def verdict(points: list[dict]) -> str:
    if len(points) < 2:
        return "not enough data yet (need 2+ readings)"
    ys = [p["percent"] for p in points]
    drops = sum(1 for a, b in zip(ys, ys[1:]) if b < a)
    rises = sum(1 for a, b in zip(ys, ys[1:]) if b > a)
    total = ys[-1] - ys[0]
    note = []
    if drops:
        note.append(f"{drops} drop(s)")
    if rises:
        note.append(f"{rises} rise(s) (charging?)")
    if not note:
        note.append("flat")
    return (f"{ys[0]}% -> {ys[-1]}% (net {total:+d}) over "
            f"{len(points)} readings; {', '.join(note)}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--csv", action="store_true")
    ap.add_argument("--limit", type=int, default=200)
    args = ap.parse_args()

    points = history.read_history(limit=args.limit)
    if args.csv:
        print("iso,ts,percent,link")
        for p in points:
            print(f"{p.get('iso','')},{p.get('ts','')},"
                  f"{p.get('percent','')},{p.get('link','')}")
        return 0

    if args.json:
        st = history.staleness()
        print(json.dumps({
            "readings": len(points),
            "verdict": verdict(points) if points else "no data",
            "first": points[0] if points else None,
            "last": points[-1] if points else None,
            "freshness": st,
        }, indent=2))
        return 0

    if not points:
        print("No history yet.")
        print("Run:  python3 tools/battery.py --retries 5   (a few times)")
        print("Or:   sudo python3 -B tools/confirm.py --seconds 300")
        return 1

    print("Redragon M910-KS battery history")
    print(ascii_chart(points))
    print()
    print("verdict:", verdict(points))
    st = history.staleness()
    if st["status"] != "fresh":
        print(f"freshness: {st['status']} "
              f"(last reading {history.humanise_age(st['age'])})")
    return 0


if __name__ == "__main__":
    sys.exit(main())