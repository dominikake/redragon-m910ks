"""
Read-only probe for the Sino Wealth vendor interface.

Sends only the benign read commands and prints raw replies so we can learn
the protocol. It deliberately never sends a write-style command or 0x75
(DFU). Every action here is safe against the device.

Usage:
    sudo python3 tools/probe.py                     # auto-detect node
    sudo python3 tools/probe.py --node 5
    sudo python3 tools/probe.py --firmware          # fw version only
    sudo python3 tools/probe.py --sweep             # try candidate cmd ids
"""

from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import safety  # noqa: E402

from sinowealth import (  # noqa: E402
    CMD_DEBOUNCE,
    CMD_FIRMWARE_VERSION,
    CMD_GET_BUTTONS,
    CMD_GET_CONFIG,
    CMD_GET_CONFIG2,
    CMD_LONG_LOD_ANGLE_SNAP,
    CMD_PROFILE,
    HidError,
    SinoWealthDevice,
    enumerate_nodes,
    hexdump,
    REPORT_ID_CMD,
    REPORT_SIZE_CONFIG,
    REPORT_SIZE_SHORT,
)


def pick_node(prefer: str = "002E") -> str:
    """Prefer the wired device (no radio sleep), else the dongle."""
    for pid in (prefer, "002F"):
        nodes = enumerate_nodes("258A", pid)
        if nodes:
            return nodes[-1][1]  # last = vendor interface
    raise SystemExit("no Sino Wealth hidraw nodes found (need 258a:002e or 002f)")


def show(label: str, reply: bytes) -> None:
    print(f"  {label}: {len(reply)}B")
    print(hexdump(reply[:48]))


def probe_firmware(dev: SinoWealthDevice) -> None:
    print("[firmware version]  cmd 0x01")
    reply = dev.cmd_query(CMD_FIRMWARE_VERSION)
    show("reply", reply)
    if len(reply) >= 6 and reply[1] == CMD_FIRMWARE_VERSION:
        print(f"  -> firmware = {bytes(reply[2:6]).decode('ascii', 'replace')!r}")
    elif len(reply) >= 2:
        print(f"  -> command byte = {reply[1]:#04x} "
              f"(asked {CMD_FIRMWARE_VERSION:#04x}) -- may not match this model")


def probe_debounce(dev: SinoWealthDevice) -> None:
    print("[debounce]  cmd 0x1a")
    reply = dev.cmd_query(CMD_DEBOUNCE)
    show("reply", reply)
    if len(reply) >= 3 and reply[1] == CMD_DEBOUNCE:
        print(f"  -> debounce = {reply[2] * 2} ms")


def probe_profile(dev: SinoWealthDevice) -> None:
    print("[active profile]  cmd 0x02")
    reply = dev.cmd_query(CMD_PROFILE)
    show("reply", reply)
    if len(reply) >= 3 and reply[1] == CMD_PROFILE:
        print(f"  -> active profile index (0-based) = {reply[2] - 1}")


def probe_config(dev: SinoWealthDevice, cmd: int, label: str) -> None:
    print(f"[{label}]  cmd {cmd:#04x} via report id 5, read config id 8")
    payload = bytes([REPORT_ID_CMD, cmd]) + b"\x00" * (REPORT_SIZE_SHORT - 2)
    dev.set_feature_report(REPORT_ID_CMD, payload)
    time.sleep(0.09)
    for cfg_id in (0x08, 0x06, 0x04):
        try:
            reply = dev.get_feature_report(cfg_id, REPORT_SIZE_CONFIG)
        except OSError:
            continue
        # Ignore an all-ones or all-zero response = unsupported report id.
        body = reply[1:]
        if body and (len(set(body)) == 1):
            continue
        print(f"  config report id {cfg_id:#04x}: {len(reply)}B")
        print(hexdump(reply[:80]))
        sensor = body[8] if len(body) > 8 else None
        if sensor is not None:
            print(f"  -> byte[8] sensor = {sensor:#04x}; first 64 bytes above")
        return
    print("  -> no populated config reply on ids 8/6/4")


def probe_buttons(dev: SinoWealthDevice, cmd: int, label: str) -> None:
    print(f"[{label}]  cmd {cmd:#04x}")
    payload = bytes([REPORT_ID_CMD, cmd]) + b"\x00" * (REPORT_SIZE_SHORT - 2)
    dev.set_feature_report(REPORT_ID_CMD, payload)
    time.sleep(0.09)
    for cfg_id in (0x08, 0x06, 0x04):
        try:
            reply = dev.get_feature_report(cfg_id, REPORT_SIZE_CONFIG)
        except OSError:
            continue
        body = reply[1:]
        if body and len(set(body)) == 1:
            continue
        print(f"  button report id {cfg_id:#04x}: {len(reply)}B")
        print(hexdump(reply[:64]))
        return
    print("  -> no populated button reply")


def sweep_candidates(dev: SinoWealthDevice) -> None:
    """
    Try a range of plausible command IDs and report any reply that echoes
    the command byte or returns non-trivial data. Read-only: every send is
    checked by tools/safety.py, which refuses write commands and makes 0x75
    unreachable.
    """
    print("[sweep] probing candidate command ids on report id 5")
    print("        (read-only; writes and 0x75 DFU are refused by safety.py)\n")
    baseline = None
    for cmd in list(range(0x01, 0x20)) + list(range(0x30, 0x38)):
        if cmd in safety.WRITE_COMMANDS or cmd == safety.DFU:
            continue
        try:
            reply = dev.cmd_query(cmd, length=REPORT_SIZE_SHORT)
        except HidError as exc:
            print(f"  cmd {cmd:#04x}: error {exc}")
            continue
        body = reply[1:]
        # Classify: echoed? uniform? non-trivial?
        echoed = len(reply) >= 2 and reply[1] == cmd
        uniform = len(set(body)) <= 1 if body else True
        tag = "ECHO" if echoed else ("uniform" if uniform else "DATA")
        if baseline is None and tag != "DATA":
            baseline = tag
        print(f"  cmd {cmd:#04x}: {tag:7s} {reply.hex(' ')}")
        time.sleep(0.02)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--node", type=int, default=None)
    ap.add_argument("--firmware", action="store_true")
    ap.add_argument("--sweep", action="store_true",
                    help="probe candidate command ids (read-only)")
    args = ap.parse_args()

    if args.node is not None:
        node = f"/dev/hidraw{args.node}"
    else:
        node = pick_node()

    print(f"target: {node}\n")
    try:
        dev = SinoWealthDevice(node)
    except HidError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    try:
        with dev:
            try:
                ids = dev.list_report_ids()
                print(f"report IDs on this node: {[hex(i) for i in ids]}")
            except HidError:
                pass
            print()

            if args.sweep:
                sweep_candidates(dev)
                return 0

            probe_firmware(dev)
            print()
            probe_debounce(dev)
            print()
            probe_profile(dev)
            print()
            probe_config(dev, CMD_GET_CONFIG, "config profile 1")
            print()
            probe_buttons(dev, CMD_GET_BUTTONS, "buttons profile 1")
            if args.firmware:
                return 0
            probe_config(dev, CMD_GET_CONFIG2, "config profile 2")
            probe_buttons(dev, 0x22, "buttons profile 2")
            print()
            print("[lift-off / angle snap]  cmd 0x1b")
            try:
                show("reply", dev.cmd_query(CMD_LONG_LOD_ANGLE_SNAP))
            except HidError as exc:
                print(f"  error: {exc}")
    except HidError as exc:
        print(f"ERROR mid-probe: {exc}", file=sys.stderr)
        return 1

    print("\nDone. Compare raw bytes against the known struct in "
          "docs/PROTOCOL.md; hunt for a byte that tracks 0-100.")
    return 0


if __name__ == "__main__":
    sys.exit(main())