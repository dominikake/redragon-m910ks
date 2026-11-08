#!/usr/bin/env python3
"""Resolve a Redragon M910-KS key-matrix FunID to its action name.

Read-only, offline: this is a pure table lookup. It takes a FunID that came
out of a `Cfg.ini` key record (`K<n>_<profile>` -> `class, FunID, param0,
param1`) or out of the app's own label lookup, and says what the vendor app
calls it.

    python3 tools/decode_funid.py 0x11

The FunID space is two families:

* software-assigned action IDs used by the UI and by `Cfg.ini` defaults:
  0x11..0x18 (mouse clicks / double / triple / R-double), 0x21..0x28 (media),
  0x30..0x39 (web / browser media), plus the programmable-macro FunIDs
  0xa8, 0xa9, 0xac, 0xae.
* hardware event family 0xf0..0xfa produced by the matrix builder at
  `0x40b010` (physical buttons and macro events), dispatched through the
  case table at `0x40b284` / jump table at `0x40b244`.

Confidence is per entry: every row below was read out of the dispatch or the
UI label path in `OemDrv.exe`, not inferred from a live read (#8 stayed a
static-analysis issue; the live confirmation never happened because physical
buttons do not reach the host in this model).
"""

from __future__ import annotations

import argparse
import sys

# FunID -> (action, category, case, encoded, size)
#
# `encoded` is the action byte written by the builder handler: a mouse bit
# for the button family (0x01 left, 0x02 right, 0x04 middle, 0x08 forward,
# 0x10 back) or a FunID-resolved value for the event family. `size` is the
# `bl` field of the handler's key-list record (the descriptor length);
# cases writing a literal use it directly, cases resolving through the
# lookup at 0x5a2040 use 2..4 and flip byte 1 with `not`/`inc` where noted.
# `None` means the value is not a literal: it is resolved at runtime through
# the lookup table (default case) or is UI-label metadata only.
FUNID_ACTIONS: dict[int, dict] = {
    # Builder special cases (case table at 0x40b284).
    0x10: {"action": "Right button", "category": "mouse", "case": 0,
          "encoded": 0x02, "size": 6},
    0xa0: {"action": "Right button", "category": "mouse", "case": 0,
          "encoded": 0x02, "size": 6},
    0xa1: {"action": "Right button", "category": "mouse", "case": 0,
          "encoded": 0x02, "size": 6},
    0x11: {"action": "Left button", "category": "mouse", "case": 1,
          "encoded": 0x01, "size": 6},
    0xa2: {"action": "Left button", "category": "mouse", "case": 1,
          "encoded": 0x01, "size": 6},
    0xa3: {"action": "Left button", "category": "mouse", "case": 1,
          "encoded": 0x01, "size": 6},
    0x12: {"action": "Middle button", "category": "mouse", "case": 2,
          "encoded": 0x04, "size": 6},
    0xa4: {"action": "Middle button", "category": "mouse", "case": 2,
          "encoded": 0x04, "size": 6},
    0xa5: {"action": "Middle button", "category": "mouse", "case": 2,
          "encoded": 0x04, "size": 6},
    0x5b: {"action": "Forward", "category": "mouse", "case": 3,
          "encoded": 0x08, "size": 6},
    0x5c: {"action": "Forward", "category": "mouse", "case": 3,
          "encoded": 0x08, "size": 6},
    # UI-labelled mouse actions that fall through to the default case.
    0x13: {"action": "Right button", "category": "mouse", "case": None,
          "encoded": None, "size": 5, "note": "resolved by the default case"},
    0x14: {"action": "Forward", "category": "mouse", "case": None,
          "encoded": None, "size": 5, "note": "resolved by the default case"},
    0x15: {"action": "Back", "category": "mouse", "case": None,
          "encoded": None, "size": 5, "note": "resolved by the default case"},
    0x16: {"action": "Double Click", "category": "mouse", "case": None,
          "encoded": None, "size": 5, "note": "resolved by the default case"},
    0x17: {"action": "Three Click", "category": "mouse", "case": None,
          "encoded": None, "size": 5, "note": "resolved by the default case"},
    0x18: {"action": "R-Double Click", "category": "mouse", "case": None,
          "encoded": None, "size": 5, "note": "resolved by the default case"},
    # Media (UI label path).
    0x21: {"action": "Media Player", "category": "media", "case": 8,
          "encoded": None, "size": 6},
    0x22: {"action": "Play/Pause", "category": "media", "case": 9,
          "encoded": None, "size": 4},
    0x23: {"action": "Stop playing", "category": "media", "case": 10,
          "encoded": None, "size": 4},
    0x24: {"action": "Previous", "category": "media", "case": 11,
          "encoded": None, "size": 3},
    0x25: {"action": "Next", "category": "media", "case": 12,
          "encoded": None, "size": 3},
    0x26: {"action": "Volume up", "category": "media", "case": 13,
          "encoded": None, "size": 2},
    0x27: {"action": "Volume down", "category": "media", "case": 14,
          "encoded": None, "size": 2},
    0x28: {"action": "Mute", "category": "media", "case": 15,
          "encoded": None, "size": 5},
    # Web / browser media (UI label path).
    0x30: {"action": "Favorites", "category": "web", "case": None,
          "encoded": None, "size": None, "note": "UI label path"},
    0x31: {"action": "Calculator", "category": "web", "case": None,
          "encoded": None, "size": None, "note": "UI label path"},
    0x32: {"action": "Explorer", "category": "web", "case": None,
          "encoded": None, "size": None, "note": "UI label path"},
    0x33: {"action": "Search", "category": "web", "case": None,
          "encoded": None, "size": None, "note": "UI label path"},
    0x34: {"action": "Home", "category": "web", "case": None,
          "encoded": None, "size": None, "note": "UI label path"},
    0x35: {"action": "Email", "category": "web", "case": None,
          "encoded": None, "size": None, "note": "UI label path"},
    0x36: {"action": "Web Forward", "category": "web", "case": None,
          "encoded": None, "size": None, "note": "UI label path"},
    0x37: {"action": "Web Stop", "category": "web", "case": None,
          "encoded": None, "size": None, "note": "UI label path"},
    0x38: {"action": "Web Refresh", "category": "web", "case": None,
          "encoded": None, "size": None, "note": "UI label path"},
    0x39: {"action": "Web Favorites", "category": "web", "case": None,
          "encoded": None, "size": None, "note": "UI label path"},
    # Programmable macros.
    0xa8: {"action": "Macro button (K6)", "category": "macro", "case": 11,
          "encoded": None, "size": 3},
    0xa9: {"action": "Macro button (K7)", "category": "macro", "case": 11,
          "encoded": None, "size": 3},
    0xac: {"action": "Macro button (K10)", "category": "macro", "case": 12,
          "encoded": None, "size": 3},
    0xae: {"action": "Macro button (K8)", "category": "macro", "case": 12,
          "encoded": None, "size": 3},
}

# Hardware / event family from the matrix builder.
HARDWARE_ACTIONS: list[tuple[int, str, str, int | None, int]] = [
    (0xF0, "Left button", "mouse", 0x01, 1),
    (0xF1, "Right button", "mouse", 0x02, 1),
    (0xF2, "Middle button", "mouse", 0x04, 1),
    (0xF3, "Forward", "mouse", 0x08, 1),
    (0xF4, "Back", "mouse", 0x10, 1),
    (0xF5, "Scroll Up", "scroll", None, 4),
    (0xF6, "Scroll Down", "scroll", None, 4),
    (0xF7, "Key Down", "macro-event", None, 3),
    (0xF8, "Key Up", "macro-event", None, 3),
    (0xF9, "Delay", "macro-event", None, 2),
    (0xFA, "Delay", "macro-event", None, 2),
]


def decode_funid(funid: int) -> dict:
    """Return the action record for a FunID, or the default-case record."""
    if funid in FUNID_ACTIONS:
        row = dict(FUNID_ACTIONS[funid])
        row["funid"] = funid
        row["default"] = False
        return row
    for f, action, category, encoded, size in HARDWARE_ACTIONS:
        if funid == f:
            return {
                "funid": funid,
                "action": action,
                "category": category,
                "case": None,
                "encoded": encoded,
                "size": size,
                "default": False,
            }
    return {
        "funid": funid,
        "action": "default (keyboard / media / combo)",
        "category": "default",
        "case": 15,
        "encoded": None,
        "size": 5,
        "default": True,
    }


def format_entry(row: dict) -> str:
    funid = row.get("funid")
    head = f"FunID 0x{funid:02x}  {row['action']}"
    if row.get("default"):
        return head + "   [default case]"
    bits = f"encoded=0x{row['encoded']:02x}" if row["encoded"] is not None else "encoded=<lookup>"
    size = row["size"]
    size_str = f"size={size}" if size is not None else "size=<n/a>"
    return (f"{head}   category={row['category']} case={row['case']} "
            f"{size_str} {bits}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Resolve a M910-KS key-matrix FunID to its action name.")
    ap.add_argument("funid", type=lambda s: int(s, 0), help="FunID, e.g. 0x11 or 17")
    args = ap.parse_args(argv)
    row = decode_funid(args.funid)
    print(format_entry(row))
    return 0


if __name__ == "__main__":
    sys.exit(main())
