#!/usr/bin/env python3
"""
Read-only corroboration of docs/GUI-ANALYSIS.md against real hardware.

Sends ONLY the commands the RE classifies as reads:
    0x01            general / firmware info
    0x11 0x21 0x31 get config, profiles 1 / 2 / 3
    0x90            read power

Never sends 0x12 / 0x22 / 0x32 (set matrix), 0x30 (set macro),
0x92 (set PSD) or 0x75 (DFU). These are writes, and that is enforced by
tools/safety.py on every send -- not merely by this list.

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

import safety  # noqa: E402

# Reads only. The list is not merely a convention here: every send still goes
# through SinoWealthDevice.set_feature_report, which consults tools/safety.py
# and refuses anything that would write. This set is the human-readable
# statement of intent; safety.py is what enforces it.
READS = [
    ("0x01", 0x01, REPORT_ID_CMD, REPORT_SIZE_SHORT),
    ("0x11", 0x11, REPORT_ID_CONFIG, REPORT_SIZE_CONFIG),
    ("0x21", 0x21, REPORT_ID_CONFIG, REPORT_SIZE_CONFIG),
    ("0x31", 0x31, REPORT_ID_CONFIG, REPORT_SIZE_CONFIG),
    ("0x90", 0x90, REPORT_ID_CMD, REPORT_SIZE_SHORT),
]


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


def guard_test(dev: SinoWealthDevice) -> int:
    """
    Adversarially check that the safety guard cannot be talked into sending a
    write. Every attempt below is expected to raise before it reaches the
    device, so this test never actually transmits anything.

    The point is to exercise the real send paths -- cmd_query and
    set_feature_report -- rather than the policy functions in isolation.
    """
    attempts = [
        ("cmd_query(0x30) SetMacro", lambda: dev.cmd_query(0x30)),
        ("cmd_query(0x12) SetMatrix p1", lambda: dev.cmd_query(0x12)),
        ("cmd_query(0x22) SetMatrix p2", lambda: dev.cmd_query(0x22)),
        ("cmd_query(0x32) SetMatrix p3", lambda: dev.cmd_query(0x32)),
        ("cmd_query(0x92) SetPSD", lambda: dev.cmd_query(0x92)),
        ("cmd_query(0x75) DFU", lambda: dev.cmd_query(0x75)),
        ("SET_FEATURE report 0x08, 520 bytes",
         lambda: dev.set_feature_report(REPORT_ID_CONFIG, bytes(520))),
        ("SET_FEATURE report 0x05, cmd 0x12",
         lambda: dev.set_feature_report(REPORT_ID_CMD,
                                         bytes([0x12]) + bytes(6))),
        # and the one that must never have a way through
        ("DFU with allow_write=True",
         lambda: dev.set_feature_report(REPORT_ID_CMD,
                                         bytes([0x75]) + bytes(6),
                                         allow_write=True)),
    ]

    blocked = 0
    for name, fn in attempts:
        try:
            fn()
        except safety.UnsafeCommand:
            blocked += 1
            print(f"  blocked  {name}")
        except Exception as exc:                       # noqa: BLE001
            print(f"  LEAKED   {name} -- reached the device: {exc}")
        else:
            print(f"  LEAKED   {name} -- sent with no objection")

    print(f"\n{blocked}/{len(attempts)} refused. Nothing was transmitted.")
    return 0 if blocked == len(attempts) else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--node", type=int, default=None)
    ap.add_argument("--guard-test", action="store_true",
                    help="only run the adversarial safety-guard check "
                         "(sends nothing)")
    args = ap.parse_args()

    path = (f"/dev/hidraw{args.node}" if args.node is not None
            else "/dev/hidraw1")
    if args.node is None:
        nodes = [n for _, n in enumerate_nodes("258A", "002F")]
        if not nodes:
            print("dongle 258a:002f not found", file=sys.stderr)
            return 2
        path = nodes[-1]

    if args.guard_test:
        print("safety guard, adversarial check against the real send paths\n")
        with SinoWealthDevice(path) as dev:
            return guard_test(dev)

    print(f"target {path}   (read-only: writes and DFU are not in the list)")
    with SinoWealthDevice(path) as dev:
        for label, cmd, reply_id, length in READS:
            safety.guard_command(cmd)
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