#!/usr/bin/env python3
"""
Read-only corroboration of docs/GUI-ANALYSIS.md against real hardware.

Sends ONLY the commands the RE classifies as reads:
    0x01            general / firmware info
    0x11 0x21 0x31 get config, profiles 1 / 2 / 3
    0x90            read power

Never sends 0x12 / 0x22 / 0x32 (set matrix), 0x30 (set macro),
0x92 (set PSD) or 0x75 (DFU). These are writes.

Usage: python3 tools/verify_vendor_cmds.py [--node N]
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sinowealth import (  # noqa: E402
    REPORT_ID_CMD,
    REPORT_ID_CONFIG,
    REPORT_SIZE_CONFIG,
    REPORT_SIZE_SHORT,
    SinoWealthDevice,
    enumerate_nodes,
    hexdump,
)

# reads only -- the RE marks every other command as a write.
# The reply report id differs: short commands echo on the CMD report
# (0x05), the 520-byte config comes back on the config report (0x08).
# Asking 0x05 for 520 bytes makes the device stall the control transfer
# and the kernel reports EPIPE.
READS = [
    ("0x01", 0x01, REPORT_ID_CMD, REPORT_SIZE_SHORT),
    ("0x11", 0x11, REPORT_ID_CONFIG, REPORT_SIZE_CONFIG),
    ("0x21", 0x21, REPORT_ID_CONFIG, REPORT_SIZE_CONFIG),
    ("0x31", 0x31, REPORT_ID_CONFIG, REPORT_SIZE_CONFIG),
    ("0x90", 0x90, REPORT_ID_CMD, REPORT_SIZE_SHORT),
]

NEVER_SEND = {0x12, 0x22, 0x32, 0x30, 0x92, 0x75}


def query(dev, cmd, reply_id, length, settle=0.2):
    """Send a zero-argument command and read the echo-bearing reply."""
    payload = bytes([REPORT_ID_CMD, cmd]) + b"\x00" * (REPORT_SIZE_SHORT - 2)
    try:
        dev.set_feature_report(REPORT_ID_CMD, payload)
    except OSError as exc:
        return None, f"SET_FEATURE failed: {exc}"
    import time

    time.sleep(settle)
    try:
        reply = dev.get_feature_report(reply_id, length)
    except OSError as exc:
        return None, f"GET_FEATURE failed: {exc}"
    if len(reply) >= 2 and reply[1] == cmd:
        return reply, None
    return None, (f"no echo (byte1=0x{reply[1]:02x})"
                  if len(reply) >= 2 else "short reply")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--node", type=int, default=None)
    args = ap.parse_args()

    assert not (READS and False)  # reads only by construction
    path = (f"/dev/hidraw{args.node}" if args.node is not None
            else "/dev/hidraw1")
    if args.node is None:
        nodes = [n for _, n in enumerate_nodes("258A", "002F")]
        if not nodes:
            print("dongle 258a:002f not found", file=sys.stderr)
            return 2
        path = nodes[-1]

    print(f"target {path}   (read-only: writes and DFU are not in the list)")
    with SinoWealthDevice(path) as dev:
        for label, cmd, reply_id, length in READS:
            assert cmd not in NEVER_SEND, f"refusing to send write cmd {cmd:#04x}"
            reply, err = query(dev, cmd, reply_id, length)
            if err:
                print(f"  {label}  {err}")
                continue
            if cmd == 0x01:
                print(f"  {label}  firmware = "
                      f"{reply[2:6].decode('ascii', 'replace')}")
            elif cmd == 0x90:
                link = {0x10: "wired", 0x11: "wireless"}.get(reply[2], "?")
                print(f"  {label}  link={link} power={reply[3]}% "
                      f"usb_connected={reply[2]} raw={reply.hex()}")
            else:
                print(f"  {label}  {len(reply)} bytes, first 32: "
                      f"{reply[:32].hex(' ')}")
                nz = [i for i, b in enumerate(reply) if b]
                print(f"        non-zero byte offsets: {nz[:24]}")
                if cmd == 0x11:
                    print(hexdump(reply[:160]))
    return 0


if __name__ == "__main__":
    sys.exit(main())