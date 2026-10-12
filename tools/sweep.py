"""
Command-ID sweep and config dumper for Sino Wealth HID devices.

The reply to `SET_FEATURE [id, cmd]` then `GET_FEATURE` tells us whether a
command exists: on this device a supported command echoes its own ID in
byte 1, while an unsupported one falls back to 0x01 (the firmware-version
reply). That gives us a reliable oracle to enumerate the command space and
find the battery command, which libratbag does not document.

Read-only discipline:
  * every SET_FEATURE sends [report_id, cmd, 0, 0, 0, 0] -- the same bare
    query idiom libratbag's sinowealth_query_read() uses.
  * 0x75 (DFU / bootloader) is never sent.
  * no command is ever sent with a write payload.

Usage:
    sudo python3 -B tools/sweep.py --sweep            # enumerate commands
    sudo python3 -B tools/sweep.py --dump             # full config hexdump
    sudo python3 -B tools/sweep.py --sweep --save captures/sweep.json
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
    REPORT_SIZE_CONFIG,
    REPORT_SIZE_SHORT,
    SinoWealthDevice,
    enumerate_nodes,
    hexdump,
)

# Never probe these: 0x75 enters the DFU bootloader. 0x00 is not a command.
NEVER_PROBE = {0x00, 0x75}

CONFIG_REPORT_ID = 0x08

# Commands can reply on the CMD report (0x05, short) OR on the config report
# (0x08, 520 bytes). Checking only 0x05 makes 0x11/0x12/0x21 look
# unsupported, because their payload arrives on 0x08 instead. Both report
# IDs echo the command id in byte 1, so the oracle works on either.
REPLY_TARGETS = (
    (REPORT_ID_CMD, REPORT_SIZE_SHORT),
    (0x06, REPORT_SIZE_SHORT),
    (0x07, REPORT_SIZE_SHORT),
    (CONFIG_REPORT_ID, REPORT_SIZE_CONFIG),
)


def resolve_node(explicit: int | None) -> str:
    if explicit is not None:
        return f"/dev/hidraw{explicit}"
    # Prefer the wired device, then the dongle; take the vendor interface.
    for pid in ("002E", "002F"):
        nodes = enumerate_nodes("258A", pid)
        if nodes:
            return nodes[-1][1]
    raise SystemExit("no Sino Wealth hidraw node found (need 258a:002e or 002f)")


def raw_query(dev: SinoWealthDevice, cmd: int,
              length: int = REPORT_SIZE_SHORT) -> bytes | None:
    """SET_FEATURE [id,cmd] then GET_FEATURE on the CMD report. None on error."""
    payload = bytes([REPORT_ID_CMD, cmd]) + b"\x00" * (length - 2)
    try:
        dev.set_feature_report(REPORT_ID_CMD, payload)
    except OSError:
        return None
    time.sleep(0.09)
    try:
        return dev.get_feature_report(REPORT_ID_CMD, length)
    except OSError:
        return None


def probe_command(dev: SinoWealthDevice, cmd: int) -> dict | None:
    """
    Send one command, then look for an echoing reply on every report ID.

    Returns None if no report echoed the command id (= not supported).
    """
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
            body = reply[2:]
            return {
                "report_id": rid,
                "length": len(reply),
                "reply": reply.hex(),
                "body": body.hex(),
            }
    return None


def sweep(dev: SinoWealthDevice, lo: int, hi: int) -> dict:
    print(f"sweeping command IDs {lo:#04x}..{hi:#04x}")
    print("reply must echo the command id in byte 1, on any of "
          f"{[hex(r) for r, _ in REPLY_TARGETS]}\n")
    results = {}
    for cmd in range(lo, hi + 1):
        if cmd in NEVER_PROBE:
            results[cmd] = {"skipped": True}
            continue
        hit = probe_command(dev, cmd)
        if hit is None:
            continue
        results[cmd] = hit
        print(f"  cmd {cmd:#04x}: SUPPORTED  reply_on={hit['report_id']:#04x}"
              f"  body={hit['body'][:64]}")
        time.sleep(0.015)

    # Only entries that actually got a reply count as supported. Skipped
    # entries (e.g. 0x75 DFU, which we must never send) are NOT supported --
    # they were never even tried.
    supported = sorted(c for c, r in results.items() if "reply" in r)
    skipped = sorted(c for c, r in results.items() if r.get("skipped"))
    print(f"\n{len(supported)} supported command(s):")
    print("  " + " ".join(f"{c:#04x}" for c in supported))
    if skipped:
        print(f"\n{len(skipped)} deliberately NOT probed (never sent): "
              + " ".join(f"{c:#04x}" for c in skipped))
    return results


def dump_config(dev: SinoWealthDevice, label: str) -> bytes:
    cmd = 0x11
    payload = bytes([REPORT_ID_CMD, cmd]) + b"\x00" * (REPORT_SIZE_SHORT - 2)
    dev.set_feature_report(REPORT_ID_CMD, payload)
    time.sleep(0.09)
    print(f"[{label}] get-config (cmd {cmd:#04x}), report id "
          f"{CONFIG_REPORT_ID:#04x}")
    reply = dev.get_feature_report(CONFIG_REPORT_ID, REPORT_SIZE_CONFIG)
    print(f"  {len(reply)} bytes")
    print(hexdump(reply))
    return reply


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--node", type=int, default=None)
    ap.add_argument("--sweep", action="store_true")
    ap.add_argument("--lo", type=lambda s: int(s, 0), default=0x01)
    ap.add_argument("--hi", type=lambda s: int(s, 0), default=0xFF)
    ap.add_argument("--dump", action="store_true",
                    help="dump the full 520-byte config blob")
    ap.add_argument("--save", default=None,
                    help="write sweep results as JSON to this path")
    args = ap.parse_args()

    node = resolve_node(args.node)
    print(f"target: {node}\n")
    try:
        dev = SinoWealthDevice(node)
    except HidError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    try:
        if args.sweep:
            results = sweep(dev, args.lo, args.hi)
            if args.save:
                os.makedirs(os.path.dirname(args.save) or ".", exist_ok=True)
                with open(args.save, "w") as fh:
                    json.dump(results, fh, indent=1)
                print(f"\nsaved -> {args.save}")
        if args.dump or not args.sweep:
            dump_config(dev, "config")
    except HidError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        dev.close()

    print("\nNext: for any supported cmd above, run --dump and look for a "
          "byte in 0..100 that is the battery, then vary charging state to "
          "confirm it moves.")
    return 0


if __name__ == "__main__":
    sys.exit(main())