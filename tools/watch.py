"""
Poll one Sino Wealth command repeatedly and report when its reply changes.

This is the decisive test for the battery: if a command's payload moves
when you charge the mouse, unplug it, or toggle wireless, that field is
the battery. A single dump cannot tell you that; a change can.

Usage:
    # watch cmd 0x90 on the wired mouse (default node)
    sudo python3 -B tools/watch.py --cmd 0x90 --seconds 30

    # watch it on the wireless dongle instead
    sudo python3 -B tools/watch.py --node 1 --cmd 0x90

    # compare wired vs dongle right now
    sudo python3 -B tools/watch.py --cmd 0x90 --compare

Read-only: sends only the bare query [0x05, cmd, 0,0,0,0], never 0x75.
"""

from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import safety  # noqa: E402

from sinowealth import (  # noqa: E402
    HidError,
    REPORT_ID_CMD,
    REPORT_SIZE_CONFIG,
    REPORT_SIZE_SHORT,
    SinoWealthDevice,
    enumerate_nodes,
)

REPLY_TARGETS = (
    (REPORT_ID_CMD, REPORT_SIZE_SHORT),
    (0x06, REPORT_SIZE_SHORT),
    (0x07, REPORT_SIZE_SHORT),
    (0x08, REPORT_SIZE_CONFIG),
)


def query(dev: SinoWealthDevice, cmd: int) -> tuple[int, bytes] | None:
    payload = bytes([REPORT_ID_CMD, cmd]) + b"\x00" * (REPORT_SIZE_SHORT - 2)
    try:
        dev.set_feature_report(REPORT_ID_CMD, payload)
    except OSError:
        return None
    time.sleep(0.09)
    for rid, length in REPLY_TARGETS:
        try:
            reply = dev.get_feature_report(rid, length)
        except OSError:
            continue
        if len(reply) >= 2 and reply[1] == cmd:
            return rid, reply
    return None


def open_node(node: str) -> SinoWealthDevice:
    return SinoWealthDevice(node)


def watch(dev: SinoWealthDevice, cmd: int, seconds: float,
          every: float) -> None:
    print(f"polling cmd {cmd:#04x} every {every * 1000:.0f}ms for "
          f"{seconds:.0f}s")
    print("Action suggestions: charge via USB-C, unplug, move the mouse,"
          "\ntoggle the power switch. Any change below is a live field.\n")
    last = None
    t0 = time.monotonic()
    n = 0
    while time.monotonic() - t0 < seconds:
        hit = query(dev, cmd)
        if hit is None:
            print(f"  [{time.monotonic() - t0:6.1f}s] no echoing reply")
        else:
            rid, reply = hit
            body = reply[2:]
            if body != last:
                tag = "CHANGE" if last is not None else "initial"
                print(f"  [{time.monotonic() - t0:6.1f}s] {tag:7s} "
                      f"on={rid:#04x} body={body.hex(' ')}")
                last = body
        n += 1
        time.sleep(every)
    print(f"\n{n} poll(s) done. If nothing changed, the field may be "
          f"static\nwhile conditions are unchanged -- change something "
          f"(plug in the cable) and re-run.")


def compare() -> None:
    """Query the same command on every Sino Wealth node side by side."""
    targets = []
    for pid, label in (("002E", "wired"), ("002F", "dongle")):
        for _, node in enumerate_nodes("258A", pid):
            targets.append((label, node))
    if not targets:
        print("no Sino Wealth nodes found")
        return
    print(f"comparing cmd across {len(targets)} node(s)\n")
    for label, node in targets:
        try:
            dev = open_node(node)
        except HidError as exc:
            print(f"  {label:6s} {node}: {exc}")
            continue
        try:
            for cmd in (0x01, 0x02, 0x90):
                hit = query(dev, cmd)
                if hit is None:
                    print(f"  {label:6s} {node}: cmd {cmd:#04x} -> no reply")
                else:
                    rid, reply = hit
                    print(f"  {label:6s} {node}: cmd {cmd:#04x} -> "
                          f"on={rid:#04x} body={reply[2:].hex(' ')}")
            print()
        finally:
            dev.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cmd", type=lambda s: int(s, 0), default=0x90)
    ap.add_argument("--node", type=int, default=None)
    ap.add_argument("--seconds", type=float, default=30.0)
    ap.add_argument("--every", type=float, default=0.5)
    ap.add_argument("--compare", action="store_true",
                    help="one-shot comparison of all nodes")
    args = ap.parse_args()

    if args.cmd in safety.WRITE_COMMANDS:
        print(f"refusing to probe {args.cmd:#04x}: it is a write command "
              f"and this repo is read-only (see tools/safety.py)",
              file=sys.stderr)
        return 1
    try:
        safety.guard_command(args.cmd)
    except safety.UnsafeCommand as exc:
        print(f"refusing to probe {args.cmd:#04x}: {exc}", file=sys.stderr)
        return 1

    if args.compare:
        compare()
        return 0

    if args.node is not None:
        node = f"/dev/hidraw{args.node}"
    else:
        node = None
        for pid in ("002E", "002F"):
            nodes = enumerate_nodes("258A", pid)
            if nodes:
                node = nodes[-1][1]
                break
        if node is None:
            print("no Sino Wealth node found", file=sys.stderr)
            return 1

    print(f"target: {node}\n")
    try:
        dev = open_node(node)
    except HidError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    try:
        watch(dev, args.cmd, args.seconds, args.every)
    finally:
        dev.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())