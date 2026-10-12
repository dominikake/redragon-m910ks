#!/usr/bin/env python3
"""
Omarchy bar module: Redragon M910-KS battery indicator.

Emits Waybar-style JSON on stdout, which is what the Omarchy bar's
`type: "command"` modules consume:

    {"text": "󰍉 87%", "tooltip": "Redragon M910-KS: 87%", "class": "ok"}

Caching matters: the bar calls this on a timer, and the mouse sleeps when
idle, so a cache avoids both USB traffic and flicker. Set REDRAGON_BATTERY_TTL
to control staleness (seconds).

Shell-out:
    REDRAGON_BATTERY_CMD   path to battery.py (default: sibling file)
    REDRAGON_BATTERY_NODE  force a hidraw node number

Read-only. Never sends 0x75 (DFU).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
DEFAULT_READER = os.path.join(HERE, "battery.py")

import history  # noqa: E402

# The mouse sleeps constantly, so a single asleep reply is normal and must
# NOT clear a known reading. Only a live reply updates the last-good time.
# After this long with no live reading we stop presenting the number.
STALE_AFTER = float(os.environ.get("REDRAGON_BATTERY_STALE", "900"))
FLAT_AFTER = float(os.environ.get("REDRAGON_BATTERY_FLAT", "21600"))

# Plain ASCII by default. The bar may not render Nerd Font private-use
# glyphs (a missing glyph can show as a stray box, or render as an
# unrelated fallback icon such as a magnifying glass). Reliability beats
# decoration here. Override with REDRAGON_BATTERY_ICON_OK / _LOW /
# _WARN / _UNKNOWN / _UNAVAILABLE if your font covers the glyphs you want.
ICON_OK = os.environ.get("REDRAGON_BATTERY_ICON_OK", "M")
ICON_LOW = os.environ.get("REDRAGON_BATTERY_ICON_LOW", "M")
ICON_WARN = os.environ.get("REDRAGON_BATTERY_ICON_WARN", "M!")
ICON_UNKNOWN = os.environ.get("REDRAGON_BATTERY_ICON_UNKNOWN", "M?")
ICON_UNAVAILABLE = os.environ.get("REDRAGON_BATTERY_ICON_UNAVAILABLE", "M--")
ICON_FLAT = os.environ.get("REDRAGON_BATTERY_ICON_FLAT", "M!!")


def emit(text: str, tooltip: str, css_class: str) -> None:
    print(json.dumps({"text": text, "tooltip": tooltip, "class": css_class}))


def read_cached() -> dict | None:
    """
    Last known reading from the persistent store, annotated with how old it
    is. Returns None only if nothing has ever been read.
    """
    st = history.staleness()
    if st["percent"] is None:
        return None
    return {
        "state": "ok",
        "percent": st["percent"],
        "link": st.get("link") or "",
        "age": st.get("age"),
        "freshness": st["status"],
    }


def read_live() -> dict | None:
    reader = os.environ.get("REDRAGON_BATTERY_CMD", DEFAULT_READER)
    cmd = [sys.executable, "-B", reader, "--json"]
    node = os.environ.get("REDRAGON_BATTERY_NODE")
    if node:
        cmd += ["--node", node]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if out.returncode != 0 or not out.stdout.strip():
        return None
    try:
        return json.loads(out.stdout.strip().splitlines()[-1])
    except ValueError:
        return None


def render(info: dict | None) -> None:
    if info is None:
        emit(ICON_UNAVAILABLE,
             "Redragon M910-KS: no reading yet "
             "(plug in the receiver; click to retry)",
             "unavailable")
        return

    # A mouse that is merely asleep must still show its last known level.
    # Only the passage of time turns that number into a guess.
    fresh = info.get("freshness", "fresh")
    age = info.get("age")
    age_txt = history.humanise_age(age)

    if fresh == "flat":
        emit(ICON_FLAT,
             f"Redragon M910-KS: no signal since {age_txt} "
             f"(last read {info.get('percent')}%) "
             f"-- mouse may be flat or out of range",
             "unavailable")
        return
    if fresh == "stale":
        emit(ICON_UNKNOWN,
             f"Redragon M910-KS: {info.get('percent')}% (last read "
             f"{age_txt})",
             "unknown")
        return

    pct = info.get("percent")
    if pct is None:
        emit(ICON_UNKNOWN, "Redragon M910-KS: asleep", "unknown")
        return

    link = info.get("link", "")
    if pct <= 15:
        css, icon = "critical", ICON_LOW
    elif pct <= 30:
        css, icon = "warning", ICON_WARN
    else:
        css, icon = "ok", ICON_OK
    tip = f"Redragon M910-KS: {pct}% ({link})"
    if age and age > 60:
        tip += f" -- read {age_txt}"
    emit(f"{icon} {pct}%", tip, css)


def main() -> int:
    """
    Ask the device once; fall back to the stored reading.

    The bar calls this on a timer, so it must stay cheap and must never
    block for long. A live reading updates the persistent last-good record
    (battery.py does that); an asleep or failed read must NOT erase it --
    otherwise the display would forget everything the moment you stop
    moving the mouse.
    """
    live = read_live()
    if live is not None and live.get("state") == "ok" \
            and live.get("percent") is not None:
        render(read_cached() or live)
        return 0

    cached = read_cached()
    if cached is not None:
        render(cached)          # last known value + its age
        return 0

    render(live if live is not None else None)
    return 0


if __name__ == "__main__":
    sys.exit(main())