#!/usr/bin/env python3
"""
UPower-compatible D-Bus bridge for the Redragon M910-KS battery.

Exports a standard `org.freedesktop.UPower.Device` object on the session
bus, so existing consumers (GNOME Power Statistics, KDE's powerdevil,
acpi-cli style tools, scripts reading UPower) see the mouse as a normal
battery device alongside the laptop's BAT0.

UPower itself refuses to be replaced, so this publishes the *device*
interface under our own well-known name and also mirrors the value to a
plain text file for the simplest consumers.

Usage:
    python3 tools/upower_bridge.py            # serve until Ctrl-C
    python3 tools/upower_bridge.py --once     # publish one reading, exit

Read-only. Never sends 0x75 (DFU).
"""

from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

BUS_NAME = "org.redragon.M910KS"
OBJ_PATH = "/org/redragon/M910KS"
IFACE = "org.freedesktop.UPower.Device"

STATE_FILE = os.path.join(
    os.environ.get("XDG_RUNTIME_DIR", "/tmp"),
    "redragon-m910ks-battery.txt",
)

# Only .Device is implemented; UPower clients tolerate partial interfaces,
# and we avoid claiming org.freedesktop.UPower (owned by the real daemon).
try:
    import dbus
    import dbus.mainloop.glib
    import dbus.service
    from gi.repository import GLib
    HAVE_DBUS = True
except ImportError:
    HAVE_DBUS = False


def current_reading():
    from battery import find_dongle_vendor_node, read_once
    from sinowealth import SinoWealthDevice, HidError
    node = find_dongle_vendor_node()
    if node is None:
        return {"state": "no-dongle", "percent": None}
    try:
        with SinoWealthDevice(node) as dev:
            return read_once(dev)
    except HidError as exc:
        return {"state": f"error: {exc}", "percent": None}


def write_state_file(info: dict) -> None:
    pct = info.get("percent")
    body = (f"{pct}\n" if pct is not None and info.get("state") == "ok"
            else "\n")
    body += f"# state={info.get('state')} link={info.get('link', '-')} " \
            f"raw={info.get('raw', '')}\n"
    try:
        tmp = STATE_FILE + f".{os.getpid()}"
        with open(tmp, "w") as fh:
            fh.write(body)
        os.replace(tmp, STATE_FILE)
    except OSError:
        pass


if HAVE_DBUS:
    class RedragonBatteryDevice(dbus.service.Object):
        def __init__(self, bus):
            super().__init__(bus, OBJ_PATH)
            self.info = {"state": "starting", "percent": None}

        @dbus.service.method(IFACE, in_signature="", out_signature="ssss")
        def GetProperties(self):
            self.refresh()
            pct = self.info.get("percent")
            # percentage is a double; unknown -> -1.0 (UPower's convention)
            return (IFACE, "", STATE_FILE if pct is None else "battery",
                    f"{pct:.0f}" if pct is not None else "")

        @dbus.service.method(IFACE, in_signature="", out_signature="u")
        def GetPercentage(self):
            self.refresh()
            pct = self.info.get("percent")
            return 100 if pct is None else int(pct)

        def refresh(self):
            self.info = current_reading()
            write_state_file(self.info)


def serve(interval: float) -> int:
    if not HAVE_DBUS:
        print("python dbus not available -- falling back to state file only",
              file=sys.stderr)
        while True:
            write_state_file(current_reading())
            time.sleep(interval)

    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SessionBus()
    name = dbus.service.BusName(BUS_NAME, bus)
    dev = RedragonBatteryDevice(bus)
    print(f"exported {IFACE} at {OBJ_PATH} as {BUS_NAME}", file=sys.stderr)
    print(f"state file: {STATE_FILE}", file=sys.stderr)

    def tick():
        dev.refresh()

    GLib.timeout_add_seconds(max(1, int(interval)), tick)
    GLib.MainLoop().run()
    return 0


def once() -> int:
    info = current_reading()
    write_state_file(info)
    if info.get("state") == "ok":
        print(f"{info['percent']}")
        return 0
    print(info.get("state"), file=sys.stderr)
    return 2


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--interval", type=float, default=30.0)
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args()
    return once() if args.once else serve(args.interval)


if __name__ == "__main__":
    sys.exit(main())