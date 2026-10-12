"""
Passive sniffer for the Sino Wealth receiver's vendor HID channel.

Opens /dev/hidrawN read-only in spirit: it only calls read(2) and the
GET_REPORT ioctls. It never issues SET_FEATURE, so it cannot perturb the
device configuration.

The point is to find out what the dongle volunteers on its own when you
move the mouse -- there is a real chance a status report already carries
the battery level and we never have to send anything.

Usage:
    python3 tools/sniff.py [--node 1] [--seconds 20] [--interval 250]

Options:
    --node N        hidraw node to sniff (default: auto-pick the vendor one)
    --seconds S     how long to listen (default 20)
    --interval MS   also poll GET_REPORT every MS (default 250, 0 disables)
"""

from __future__ import annotations

import argparse
import collections
import os
import select
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sinowealth import (  # noqa: E402
    HidError,
    SinoWealthDevice,
    enumerate_nodes,
    hexdump,
    REPORT_ID_CMD,
)

VENDOR_USAGE_PAGE = 0xFF00

# How many times to print each distinct payload before staying quiet.
MAX_SAMPLES_PER_PAYLOAD = 3


def pick_vendor_node() -> str | None:
    """Prefer the node whose descriptor exposes the 0xFF00 vendor page."""
    candidates = []
    for vid, pid in (("258A", "002F"), ("258A", "002E")):
        candidates.extend(node for _, node in enumerate_nodes(vid, pid))
    if not candidates:
        return None

    for node in candidates:
        try:
            with SinoWealthDevice(node) as dev:
                desc = dev.get_report_descriptor()
        except (HidError, OSError):
            continue
        if b"\x06\x00\xff" in desc:  # Usage Page (Vendor Defined 0xFF00)
            return node
    return candidates[-1]


def sniff(node: str, seconds: float, interval_ms: int) -> int:
    seen = collections.Counter()
    samples: dict[bytes, int] = {}
    deadline = time.monotonic() + seconds
    interval = interval_ms / 1000.0

    print(f"sniffing {node} for {seconds:.0f}s")
    print("Move the mouse, click buttons, scroll. Unplug/replug to pair.")
    if interval:
        print(f"polling GET_REPORT every {interval_ms}ms\n")
    else:
        print("interrupt reads only\n")

    try:
        dev = SinoWealthDevice(node)
    except HidError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    fd = dev._fd  # noqa: SLF001 -- deliberate, we need the raw fd for select
    next_poll = time.monotonic()
    got_any = False

    try:
        while time.monotonic() < deadline:
            now = time.monotonic()
            wait = 0.05
            if interval and now < next_poll:
                wait = min(wait, max(0.0, next_poll - now))
            r, _, _ = select.select([fd], [], [], wait)

            if r:
                try:
                    data = os.read(fd, 64)
                except BlockingIOError:
                    data = b""
                except OSError:
                    data = b""
                if data:
                    got_any = True
                    seen[("interrupt", data[0], len(data))] += 1
                    n = samples.get(data, 0)
                    if n < MAX_SAMPLES_PER_PAYLOAD:
                        samples[data] = n + 1
                        print(f"[interrupt] {len(data)} bytes")
                        print(hexdump(data))

            now = time.monotonic()
            if interval and now >= next_poll:
                next_poll = now + interval
                for rid, length in (
                    (REPORT_ID_CMD, 8),
                    (0x06, 8),
                    (0x07, 8),
                    (0x08, 520),
                ):
                    try:
                        reply = dev.get_feature_report(rid, length)
                    except OSError:
                        continue
                    if reply and any(reply[1:]):
                        got_any = True
                        seen[("getreport", rid, len(reply))] += 1
                        n = samples.get(reply, 0)
                        if n < MAX_SAMPLES_PER_PAYLOAD:
                            samples[reply] = n + 1
                            print(f"[GET_REPORT id={rid:#04x}] {len(reply)} bytes")
                            print(hexdump(reply[:64]))
    except Exception as exc:  # noqa: BLE001
        # Never lose what we already captured to a late crash.
        print(f"\n[!] stopped early: {type(exc).__name__}: {exc}", file=sys.stderr)
    finally:
        dev.close()

    print("\n--- summary ---")
    if not seen:
        print("nothing captured. The dongle may be asleep; move the mouse")
        print("repeatedly, or plug in the mouse via USB-C to test 258a:002e.")
        return 2

    for (kind, ident, size), count in seen.most_common():
        label = f"{kind} id={ident:#04x}" if kind == "getreport" else \
                f"{kind} first_byte={ident:#04x}"
        print(f"  {count:6d}x  {label:<34} {size} bytes")

    print(f"\n{len(samples)} distinct payload(s) captured.")
    print("Look for a byte that plausibly tracks 0-100 while you watch it.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--node", type=int, default=None,
                    help="hidraw node number (default: auto-detect vendor node)")
    ap.add_argument("--seconds", type=float, default=20.0)
    ap.add_argument("--interval", type=int, default=250,
                    help="GET_REPORT poll interval in ms; 0 disables polling")
    args = ap.parse_args()

    if args.node is not None:
        node = f"/dev/hidraw{args.node}"
    else:
        node = pick_vendor_node()
        if node is None:
            print("no Sino Wealth hidraw nodes found. Is the dongle plugged in?",
                  file=sys.stderr)
            return 1
        print(f"auto-selected {node}\n")

    return sniff(node, args.seconds, args.interval)


if __name__ == "__main__":
    sys.exit(main())