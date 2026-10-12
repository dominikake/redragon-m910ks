"""
Persistent reading history and staleness tracking for the M910-KS.

The mouse sleeps when idle and stops answering entirely when its battery is
flat or it is out of range. In both cases the receiver simply stops
reporting, so a naive reader would sit frozen on its last value and display
a confident but wrong percentage.

This module keeps a small append-only history plus a "last good reading"
timestamp, so consumers can distinguish:

    fresh   -- a level was read moments ago
    stale   -- no reading for a while; the number may be out of date
    flat    -- nothing heard for hours; probably flat / out of range
    unseen  -- no successful reading has ever been recorded

State lives under $XDG_STATE_HOME (default ~/.local/state) so it survives
reboots, which is exactly when a silent device matters most.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone

STATE_DIR = os.path.join(
    os.environ.get("XDG_STATE_HOME",
                   os.path.expanduser("~/.local/state")),
    "redragon-m910ks",
)
HISTORY_FILE = os.path.join(STATE_DIR, "history.jsonl")
LAST_FILE = os.path.join(STATE_DIR, "last.json")

# How old a reading may be before we stop presenting it as current.
STALE_AFTER = float(os.environ.get("REDRAGON_BATTERY_STALE", "900"))   # 15 min
FLAT_AFTER = float(os.environ.get("REDRAGON_BATTERY_FLAT", "21600"))   # 6 h


def _now() -> float:
    return time.time()


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).astimezone().isoformat(
        timespec="seconds")


def _ensure_dir() -> None:
    os.makedirs(STATE_DIR, exist_ok=True)


def record(percent: int, link: str | None = None, raw: str = "") -> None:
    """Append a successful reading and refresh the last-good marker."""
    _ensure_dir()
    ts = _now()
    entry = {
        "ts": ts,
        "iso": _iso(ts),
        "percent": percent,
        "link": link,
        "raw": raw,
    }
    try:
        with open(HISTORY_FILE, "a") as fh:
            fh.write(json.dumps(entry) + "\n")
    except OSError:
        pass
    try:
        tmp = LAST_FILE + f".{os.getpid()}"
        with open(tmp, "w") as fh:
            json.dump(entry, fh)
        os.replace(tmp, LAST_FILE)
    except OSError:
        pass


def last_good() -> dict | None:
    """Most recent successful reading, or None if there has never been one."""
    try:
        with open(LAST_FILE) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def read_history(limit: int | None = None) -> list[dict]:
    """All recorded readings, oldest first. Tolerates a truncated tail."""
    out = []
    try:
        with open(HISTORY_FILE) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        return []
    if limit is not None and len(out) > limit:
        out = out[-limit:]
    return out


def age_of(last: dict | None) -> float | None:
    if not last:
        return None
    try:
        return max(0.0, _now() - float(last["ts"]))
    except (KeyError, TypeError, ValueError):
        return None


def staleness() -> dict:
    """
    Describe how much to trust the last recorded reading.

    Returns keys: status, percent, age, iso, link.
    status is one of fresh | stale | flat | unseen.
    """
    last = last_good()
    age = age_of(last)
    if last is None or age is None:
        return {"status": "unseen", "percent": None, "age": None,
                "iso": None, "link": None}
    if age <= STALE_AFTER:
        status = "fresh"
    elif age <= FLAT_AFTER:
        status = "stale"
    else:
        status = "flat"
    return {
        "status": status,
        "percent": last.get("percent"),
        "age": age,
        "iso": last.get("iso"),
        "link": last.get("link"),
    }


def humanise_age(seconds: float | None) -> str:
    if seconds is None:
        return "never"
    s = int(seconds)
    if s < 60:
        return f"{s}s ago"
    if s < 3600:
        return f"{s // 60}m ago"
    if s < 86400:
        return f"{s // 3600}h {(s % 3600) // 60}m ago"
    return f"{s // 86400}d ago"