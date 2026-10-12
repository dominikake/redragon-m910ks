"""
Read the battery level of a Redragon M910-KS Ranger Lite on Linux.

Reverse-engineered wire format (see docs/PROTOCOL.md):

    SET_FEATURE(report 0x05, [0x05, 0x90, 0, 0, 0, 0])
    sleep 90ms
    GET_FEATURE(report 0x05, 8)
      -> [0]=0x05  [1]=0x90  [2]=link 0x10 wired / 0x11 wireless
                     [3]=battery percent, 0x00 while the mouse is asleep

The charge level lives on the 2.4 GHz receiver (`258a:002f`), not on the
wired mouse, so this reads the dongle's vendor HID node.

Standard library only -- no pip, pyusb, or hidapi.

Usage:
    python3 tools/battery.py                 # one-shot, human readable
    python3 tools/battery.py --json          # machine readable
    python3 tools/battery.py --watch         # poll until it wakes up
    python3 tools/battery.py --retries 5     # wake the link, retry

Read-only. Never sends 0x75 (DFU).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sinowealth import (  # noqa: E402
    HidError,
    REPORT_ID_CMD,
    REPORT_SIZE_SHORT,
    SinoWealthDevice,
    enumerate_nodes,
)
import history  # noqa: E402

CMD_BATTERY = 0x90

LINK_WIRED = 0x10
LINK_WIRELESS = 0x11

LINK_NAMES = {
    LINK_WIRED: "wired (USB)",
    LINK_WIRELESS: "wireless (2.4GHz)",
}

# The receiver reports 0x00 while the mouse is asleep. Any other value is
# the charge percentage.
ASLEEP = 0


def find_dongle_vendor_node() -> str | None:
    """Locate the dongle (258a:002f) vendor interface.

    Prefers the node whose descriptor carries the 0xFF00 vendor usage page.
    """
    nodes = [node for _, node in enumerate_nodes("258A", "002F")]
    if not nodes:
        return None
    for node in nodes:
        try:
            with SinoWealthDevice(node) as dev:
                desc = dev.get_report_descriptor()
            if b"\x06\x00\xff" in desc:
                return node
        except (HidError, OSError):
            continue
    return nodes[-1]


def read_raw(dev: SinoWealthDevice) -> bytes | None:
    """Send the battery query and return the echoing reply, or None."""
    payload = bytes([REPORT_ID_CMD, CMD_BATTERY]) + b"\x00" * (
        REPORT_SIZE_SHORT - 2)
    try:
        dev.set_feature_report(REPORT_ID_CMD, payload)
    except OSError:
        return None
    time.sleep(0.09)
    try:
        reply = dev.get_feature_report(REPORT_ID_CMD, REPORT_SIZE_SHORT)
    except OSError:
        return None
    if len(reply) >= 2 and reply[1] == CMD_BATTERY:
        return reply
    return None


def parse(reply: bytes | None) -> dict:
    if reply is None or len(reply) < 4:
        return {"ok": False, "percent": None, "state": "no-reply",
                "raw": reply.hex() if reply else ""}
    link = reply[2]
    level = reply[3]
    asleep = level == ASLEEP
    return {
        "ok": True,
        "percent": None if asleep else level,
        "state": "asleep" if asleep else "ok",
        "link_code": link,
        "link": LINK_NAMES.get(link, f"unknown(0x{link:02x})"),
        "charging": None,      # filled in by the caller if it knows
        "raw": reply.hex(),
    }


def read_once(dev: SinoWealthDevice) -> dict:
    """One query. A live reading is also recorded in the history log."""
    info = parse(read_raw(dev))
    if info.get("state") == "ok" and info.get("percent") is not None:
        history.record(info["percent"], info.get("link"), info.get("raw", ""))
    return info


def read_with_retries(dev: SinoWealthDevice, retries: int,
                      delay: float) -> dict:
    """Poll until the mouse reports a non-zero level."""
    last = read_once(dev)
    if last["state"] == "ok":
        return last
    for i in range(retries):
        print(f"  mouse asleep; nudge it and retrying "
              f"({i + 1}/{retries})...", file=sys.stderr)
        time.sleep(delay)
        last = read_once(dev)
        if last["state"] == "ok":
            return last
    return last


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--node", type=int, default=None,
                    help="hidraw node (default: auto-detect dongle)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--watch", action="store_true",
                    help="poll every --interval until a level is read")
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--retries", type=int, default=0,
                    help="retry N times waiting for the link to wake")
    args = ap.parse_args()

    node = f"/dev/hidraw{args.node}" if args.node is not None \
        else find_dongle_vendor_node()
    if node is None:
        print("dongle (258a:002f) not found -- plug in the receiver",
              file=sys.stderr)
        return 2

    try:
        dev = SinoWealthDevice(node)
    except HidError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    try:
        if args.watch:
            print(f"polling {node} every {args.interval}s "
                  f"(move the mouse to wake it)")
            while True:
                info = read_once(dev)
                if args.json:
                    print(json.dumps(info))
                elif info["state"] == "ok":
                    print(f"{info['percent']:3d}%  ({info['link']})")
                else:
                    print("-- asleep/unknown --")
                time.sleep(args.interval)
        else:
            info = read_with_retries(dev, args.retries, 2.0) \
                if args.retries else read_once(dev)
            if args.json:
                print(json.dumps(info))
            else:
                if info["state"] == "ok":
                    print(f"Redragon M910-KS battery: {info['percent']}%  "
                          f"({info['link']})")
                    print(f"  raw: {info['raw']}")
                elif info["state"] == "asleep":
                    print("mouse asleep -- battery unknown "
                          "(move the mouse and retry, or use --retries 5)")
                    print(f"  raw: {info['raw']}")
                else:
                    print("no reply from the dongle")
                    print(f"  raw: {info.get('raw', '')}")
                    return 1
    finally:
        dev.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())