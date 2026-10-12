#!/usr/bin/env python3
"""
Confirmation harness for the provisional battery reading.

`cmd 0x90` byte 3 is *believed* to be the charge percentage (observed
0x57 = 87 once). This tool collects timestamped samples so that claim can be
falsified: if the value tracks charging and discharge, it is the battery;
if it sits at 87 regardless, it is something else.

It logs one line per sample:

    <ISO8601>  <percent|->  link=<wired|wireless|->  raw=<hex>

Then prints a summary (min/max/distinct) per phase.

Usage:
    # sample every 10s for 5 min, logging to a file
    sudo python3 -B tools/confirm.py --seconds 300 --every 10 --log captures/battery-log.txt

    # compare wired vs dongle right now
    sudo python3 -B tools/confirm.py --compare

Read-only. Never sends 0x75 (DFU).
"""

from __future__ import annotations

import argparse
import datetime
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from battery import (  # noqa: E402
    find_dongle_vendor_node,
    read_once,
)
from sinowealth import HidError, SinoWealthDevice, enumerate_nodes  # noqa: E402


def now_iso() -> str:
    return datetime.datetime.now().isoformat(timespec="seconds")


def fmt(info: dict) -> str:
    pct = info.get("percent")
    pct_s = f"{pct:3d}" if pct is not None and info.get("state") == "ok" else "  -"
    link = info.get("link", "-") if info.get("link_code") else "-"
    return (f"{now_iso()}  {pct_s}%  link={link:<16} "
            f"raw={info.get('raw', '')}")


def collect(node: str, seconds: float, every: float, log_path: str | None):
    fh = None
    if log_path:
        os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)
        fh = open(log_path, "a")
        fh.write(f"\n=== session {now_iso()} node={node} ===\n")
        fh.flush()
    print(f"sampling {node} every {every}s for {seconds}s")
    print("Phase ideas: idle -> unplug -> charge -> full.\n")
    samples = []
    t0 = time.monotonic()
    try:
        dev = SinoWealthDevice(node)
    except HidError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    try:
        while time.monotonic() - t0 < seconds:
            info = read_once(dev)
            line = fmt(info)
            print(line)
            samples.append(info)
            if fh:
                fh.write(line + "\n")
                fh.flush()
            time.sleep(every)
    finally:
        dev.close()
        if fh:
            fh.close()

    pcts = [s["percent"] for s in samples
            if s.get("state") == "ok" and s.get("percent") is not None]
    print(f"\n--- summary over {len(samples)} samples ---")
    if not pcts:
        print("no live readings (mouse stayed asleep).")
        print("Move the mouse, or retry with --every 3 while active.")
        return 2
    print(f"  readings : {len(pcts)}/{len(samples)}")
    print(f"  min/max  : {min(pcts)}% / {max(pcts)}%")
    print(f"  distinct : {sorted(set(pcts))}")
    if len(set(pcts)) <= 1:
        print("\n  VERDICT: value never changed -> NOT yet evidence of a "
              "battery.\n  Change the charging state and re-run.")
    else:
        print("\n  VERDICT: value varies -> consistent with a live battery "
              "reading.\n  Confirm the min/max track discharge/charge.")
    return 0


def compare() -> int:
    rows = []
    for pid, label in (("002E", "wired"), ("002F", "dongle")):
        for _, node in enumerate_nodes("258A", pid):
            try:
                with SinoWealthDevice(node) as dev:
                    info = read_once(dev)
            except HidError as exc:
                print(f"  {label:6s} {node}: {exc}")
                continue
            rows.append((label, node, info))
            print(f"  {label:6s} {node}: {fmt(info)}")
    print()
    wireless = [i for _, _, i in rows if i.get("link_code") == 0x11]
    if wireless and any(i.get("state") == "ok" for i in wireless):
        print("  dongle reports a live level -> this is the battery source.")
    else:
        print("  dongle currently asleep -> move the mouse and re-run.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--node", type=int, default=None)
    ap.add_argument("--seconds", type=float, default=120.0)
    ap.add_argument("--every", type=float, default=10.0)
    ap.add_argument("--log", default=None)
    ap.add_argument("--compare", action="store_true")
    args = ap.parse_args()

    if args.compare:
        return compare()

    node = f"/dev/hidraw{args.node}" if args.node is not None \
        else find_dongle_vendor_node()
    if node is None:
        print("dongle (258a:002f) not found", file=sys.stderr)
        return 2
    return collect(node, args.seconds, args.every, args.log)


if __name__ == "__main__":
    sys.exit(main())