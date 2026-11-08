"""
Read the battery level of a Redragon M910-KS Ranger Lite on Linux.

Reverse-engineered wire format (see docs/PROTOCOL.md):

    SET_FEATURE(report 0x05, [0x05, 0x90, 0, 0, 0, 0])
    sleep 90ms
    GET_FEATURE(report 0x05, 8)
      -> [0]=0x05  [1]=0x90
         [2]=link: 0x10 USB-connected (wired) / 0x11 wireless
         [3]=power percent, 0x00 while the wireless link has nothing to say

The same command answers on both transports:

    258a:002f  dongle  -- charge level of a wireless mouse
    258a:002e  cable   -- charge level while charging, and the only device
                          that knows anything once the mouse is plugged in

While the cable is attached the mouse turns its radio off, so the dongle
reports `0x11` + `0x00` ("asleep") and cannot distinguish charging from a
flat battery. The wired node can, which is why this reader prefers it
whenever it is present.

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
    enumerate_vendor_nodes,
)
import history  # noqa: E402

CMD_BATTERY = 0x90

LINK_WIRED = 0x10
LINK_WIRELESS = 0x11

LINK_NAMES = {
    LINK_WIRED: "wired (USB)",
    LINK_WIRELESS: "wireless (2.4GHz)",
}

# The vendor app's ReadPower (OemDrv.exe 0x40a590) treats byte 2 as
# `nUsbConnect`: 0x10 -> 1, 0x11 -> 0, anything else -> "no reading". Byte 3
# is `nPower` in both branches, so it is a percentage while charging too.

# The wireless link reports 0x00 while the mouse is asleep or out of range.
# Any other value is the charge percentage.
ASLEEP = 0

DONGLE_IDS = ("258A", "002F")
WIRED_IDS = ("258A", "002E")


def find_vendor_node(vendor: str, product: str) -> str | None:
    """Locate the vendor-channel node for a USB VID:PID, or None."""
    nodes = [node for _, node in enumerate_vendor_nodes(vendor, product)]
    return nodes[-1] if nodes else None


def find_dongle_vendor_node() -> str | None:
    """Locate the dongle (258a:002f) vendor interface."""
    return find_vendor_node(*DONGLE_IDS)


def find_wired_vendor_node() -> str | None:
    """Locate the wired mouse (258a:002e) vendor interface."""
    return find_vendor_node(*WIRED_IDS)


def wired_present() -> bool:
    """True when the cable is attached (258a:002e enumerates)."""
    return bool(enumerate_nodes(*WIRED_IDS))


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


def parse(reply: bytes | None, source: str | None = None) -> dict:
    """
    Decode a 0x90 reply with the vendor app's own semantics.

    byte 2 is `nUsbConnect` (0x10 yes / 0x11 no / anything else unknown) and
    byte 3 is `nPower`. In wired mode 0x00 means "not reported yet", not
    "0%"; on the wireless link it means the mouse is asleep or out of range.
    """
    base = {"ok": False, "percent": None, "state": "no-reply",
            "charging": None, "source": source,
            "raw": reply.hex() if reply else ""}
    if reply is None or len(reply) < 4:
        return base

    link = reply[2]
    level = reply[3]
    charging = {LINK_WIRED: True, LINK_WIRELESS: False}.get(link)
    if charging is None:
        return {**base, "state": "unknown-link", "link_code": link,
                "link": LINK_NAMES.get(link, f"unknown(0x{link:02x})")}

    if charging:
        # Wired: the mouse is on USB, so it is charging even before the gauge
        # reports a number. 0x00 is "pending", never "asleep".
        state = "ok" if level != ASLEEP else "pending"
        percent = level if level != ASLEEP else None
    else:
        state = "asleep" if level == ASLEEP else "ok"
        percent = None if level == ASLEEP else level

    return {
        **base,
        "ok": True,
        "percent": percent,
        "state": state,
        "link_code": link,
        "link": LINK_NAMES.get(link, f"unknown(0x{link:02x})"),
        "charging": charging,
    }


def read_once(dev: SinoWealthDevice, source: str | None = None) -> dict:
    """One query. A live reading is also recorded in the history log."""
    info = parse(read_raw(dev), source)
    if info.get("percent") is not None:
        history.record(info["percent"], info.get("link"), info.get("raw", ""),
                       info.get("charging"))
    return info


def query_node(node: str, source: str | None = None) -> dict:
    """One query against one node, flattening open failures into a reply."""
    try:
        with SinoWealthDevice(node) as dev:
            return read_once(dev, source)
    except HidError as exc:
        return {"ok": False, "percent": None, "state": "no-reply",
                "charging": None, "source": source, "raw": "",
                "error": str(exc)}


def read_battery() -> dict:
    """
    Read whichever transport knows the answer.

    With the cable in, the mouse is wired and its radio is off: the dongle
    reports "asleep" no matter what the charge is. The wired node is the only
    honest source then, so it wins whenever it enumerates.
    """
    wired_node = find_wired_vendor_node()
    if wired_node is not None:
        info = query_node(wired_node, "wired")
        if info.get("state") in ("ok", "pending"):
            return info
        # The cable is attached even if the vendor channel did not answer
        # (mouse switched off, or the gauge has not woken yet). Report that
        # as charging-with-no-level rather than falling back to the dongle,
        # which would look like a flat battery.
        return {**info, "state": "pending", "charging": True,
                "link_code": LINK_WIRED, "link": LINK_NAMES[LINK_WIRED]}

    dongle_node = find_dongle_vendor_node()
    if dongle_node is None:
        return {"ok": False, "percent": None, "state": "no-device",
                "charging": None, "source": None, "raw": ""}
    return query_node(dongle_node, "dongle")


def read_with_retries(retries: int, delay: float) -> dict:
    """Poll until a level is reported (or the link says it is charging)."""
    last = read_battery()
    if last.get("percent") is not None or last.get("charging"):
        return last
    for i in range(retries):
        print(f"  mouse asleep; nudge it and retrying "
              f"({i + 1}/{retries})...", file=sys.stderr)
        time.sleep(delay)
        last = read_battery()
        if last.get("percent") is not None or last.get("charging"):
            return last
    return last


def describe(info: dict) -> str:
    """Human-readable one-liner for a reading."""
    state = info.get("state")
    if state == "ok":
        line = f"{info['percent']:3d}%  ({info.get('link', '?')})"
        if info.get("charging"):
            line += "  [charging]"
        return line
    if state == "pending":
        return "charging -- level not reported yet"
    if state == "asleep":
        return "-- asleep/unknown --"
    return f"-- {state or 'no reply'} --"


def read_any(node: int | None, retries: int = 0) -> dict:
    """Read a forced node, or auto-detect across both transports."""
    if node is not None:
        info = query_node(f"/dev/hidraw{node}")
        if retries and info.get("percent") is None \
                and not info.get("charging"):
            for i in range(retries):
                print(f"  retrying ({i + 1}/{retries})...", file=sys.stderr)
                time.sleep(2.0)
                info = query_node(f"/dev/hidraw{node}")
                if info.get("percent") is not None or info.get("charging"):
                    break
        return info
    return read_with_retries(retries, 2.0) if retries else read_battery()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--node", type=int, default=None,
                    help="force a hidraw node (default: auto-detect)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--watch", action="store_true",
                    help="poll every --interval until a level is read")
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--retries", type=int, default=0,
                    help="retry N times waiting for the link to wake")
    args = ap.parse_args()

    if args.watch:
        print(f"polling every {args.interval}s "
              f"(move the mouse to wake it)")
        while True:
            info = read_any(args.node)
            if args.json:
                print(json.dumps(info))
            else:
                print(describe(info))
            time.sleep(args.interval)

    info = read_any(args.node, args.retries)
    if args.json:
        print(json.dumps(info))
        return 0

    state = info.get("state")
    if state == "ok":
        print(f"Redragon M910-KS battery: {info['percent']}%  "
              f"({info.get('link', '?')})")
        if info.get("charging"):
            print("  charging over USB")
        print(f"  raw: {info['raw']}")
    elif state == "pending":
        print("Redragon M910-KS is charging over USB -- "
              "the charge level is not reported yet")
        print(f"  raw: {info.get('raw', '')}")
    elif state == "asleep":
        print("mouse asleep -- battery unknown "
              "(move the mouse and retry, or use --retries 5)")
        print(f"  raw: {info['raw']}")
    elif state == "no-device":
        print("no device found -- plug in the receiver or the USB cable",
              file=sys.stderr)
        return 2
    else:
        print(f"no reply ({state})")
        print(f"  raw: {info.get('raw', '')}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())