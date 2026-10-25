#!/usr/bin/env python3
"""Decode the 146-byte general block of an M910-KS config reply.

Read-only, offline: this takes a blob that is already on disk. It does not
talk to the device and does not need one.

    python3 tools/decode_general_block.py captures/vendor-0x21-dongle.bin

The general block is the only part of the 520-byte reply that the vendor
app's own packers actually own: `0x11`/`0x21`/`0x31` write a 146-byte body
starting at reply byte 8, and everything past byte 0x99 belongs to other
commands. The field map comes from the two packers at `0x40b750` (DPI, report
rate, level colours) and `0x40b9f0` (LED mode table); see
`docs/GUI-ANALYSIS.md` for the disassembly evidence.

Confidence is per field: values below are what the bytes say, not a guess at
what the firmware does with them.
"""

from __future__ import annotations

import argparse
import sys

REPORT_ID = 0x08
GENERAL_START = 8
GENERAL_LEN = 0x92
BLOB_LEN = 520

# Cfg.ini [SENSOR_1] DPISET, in order. The wire value is the 1-based index
# into this ladder -- 500 is entry 1 (0-based), so it goes out as 2.
DPISET = [250, 500, 750, 1000, 1200, 1500, 1750, 2000, 2250, 2400,
          2750, 3000, 3250, 3500, 3750, 4000, 4500, 5000, 5500, 6000,
          6500, 7000, 7500, 8000]

# Report-rate nibble -> Hz. The comparands in the packer are 0x125/0x250/
# 0x500/0x1000, which are the vendor's decimal labels typed as hex.
REPORT_RATE = {1: 125, 2: 250, 3: 500, 4: 1000}

# LedOpt1..LedOpt10 on the wire. `opt` is the byte holding the Light (high)
# and Speed (low) nibbles, except where the packer only writes one of them.
# `slots` is how many RGB triples the field can hold; mode 3 also stores an
# explicit count, the others are fixed-size or zero-padded.
LED_MODES = [
    # mode, opt, extra, colours, slots, count_at
    (1, 0x3E, 0x3F, None, 0, None),      # extra = (Random == 3)
    (2, 0x40, None, 0x41, 1, None),
    (3, 0x44, None, 0x46, 7, 0x45),
    (4, 0x5B, None, None, 0, None),      # low nibble only
    (5, 0x5C, None, None, 0, None),
    (6, 0x5D, None, 0x5E, 10, None),
    (7, 0x7C, None, 0x7D, 2, None),
    (8, 0x83, None, None, 0, None),
    (9, 0x84, None, None, 0, None),
    (10, 0x85, None, None, 0, None),     # low nibble only
]

# Payload bytes neither packer writes, so they are whatever the device
# returned. Listed so the decoder can say "echoed", not "unknown".
ECHOED = [0x01, 0x04] + list(range(0x86, 0x90)) + [0x91]


def _u16(buf: bytes, off: int) -> int:
    return buf[off] | (buf[off + 1] << 8)


def _ladder_value(code: int) -> int | None:
    """Wire code is 1-based index into DPISET; 0 means 'not set'."""
    if 1 <= code <= len(DPISET):
        return DPISET[code - 1]
    return None


def _rgb(buf: bytes, off: int) -> tuple[int, int, int]:
    return buf[off], buf[off + 1], buf[off + 2]


def decode_general(blob: bytes) -> dict:
    """Decode one 520-byte 0x11/0x21/0x31 reply. Raises ValueError on shape."""
    if len(blob) != BLOB_LEN:
        raise ValueError(f"expected {BLOB_LEN} bytes, got {len(blob)}")
    if blob[0] != REPORT_ID:
        raise ValueError(f"reply[0] = {blob[0]:#04x}, expected report "
                         f"{REPORT_ID:#04x}")
    g = blob[GENERAL_START:GENERAL_START + GENERAL_LEN]

    enabled = g[0x03] & 0x0F
    active = (g[0x03] >> 4) & 0x0F
    dual_axis = bool(g[0x02] & 0x80)
    rate_code = g[0x02] & 0x0F

    dpi_x = [_ladder_value(_u16(g, 0x05 + 2 * i)) for i in range(8)]
    dpi_y = ([_ladder_value(_u16(g, 0x15 + 2 * i)) for i in range(8)]
             if dual_axis else None)

    modes = []
    for num, opt, extra, colours, slots, count_at in LED_MODES:
        entry = {
            "mode": num,
            "options": g[opt],
            "light": (g[opt] >> 4) & 0x0F,
            "speed": g[opt] & 0x0F,
        }
        if extra is not None:
            entry["random_is_3"] = bool(g[extra])
        if colours is None:
            entry["colours"] = []
        else:
            count = g[count_at] if count_at is not None else slots
            count = min(count, slots)
            entry["colours"] = [_rgb(g, colours + 3 * i) for i in range(count)]
            if count_at is None:
                # Fixed-size field: trailing black slots are padding.
                while entry["colours"] and entry["colours"][-1] == (0, 0, 0):
                    entry["colours"].pop()
        modes.append(entry)

    return {
        "constant_100": g[0x00],
        "echoed_byte_09": g[0x01],
        "report_rate_hz": REPORT_RATE.get(rate_code),
        "report_rate_code": rate_code,
        "dual_dpi_axis": dual_axis,
        "levels_enabled": enabled,
        "active_level": active,
        "dpi_x": dpi_x[:enabled],
        "dpi_y": dpi_y[:enabled] if dpi_y is not None else None,
        "level_colours": [_rgb(g, 0x25 + 3 * i) for i in range(enabled)],
        "led_active": g[0x3D],
        "led_modes": modes,
        "echoed": {f"{o:#04x}": g[o] for o in ECHOED},
        "terminator": _u16(g, 0x90),
    }


def format_report(d: dict) -> str:
    out = [
        f"report-rate    {d['report_rate_hz']} Hz "
        f"(code {d['report_rate_code']})",
        f"DPI levels     {d['levels_enabled']} enabled, "
        f"active is #{d['active_level']}",
        f"dual axis      {'yes' if d['dual_dpi_axis'] else 'no'}",
    ]
    for i, (x, y) in enumerate(zip(d["dpi_x"], d["dpi_y"] or d["dpi_x"])):
        rgb = d["level_colours"][i]
        out.append(f"  level {i + 1}      {x} dpi"
                   + (f" / {y} dpi" if d["dpi_y"] else "")
                   + f"   rgb={rgb}")
    out.append(f"LED active     {d['led_active']}")
    for m in d["led_modes"]:
        colours = " ".join(f"#{r:02x}{g:02x}{b:02x}"
                           for r, g, b in m["colours"])
        out.append(f"  LedOpt{m['mode']:<2}     light={m['light']} "
                   f"speed={m['speed']}"
                   + (f" random3={int(m['random_is_3'])}"
                      if "random_is_3" in m else "")
                   + (f" colours=[{colours}]" if colours else ""))
    out.append(f"terminator     {d['terminator']:#06x}")
    out.append("echoed (payload offsets, device state the app never writes)")
    out.append("               " + " ".join(
        f"[{k}]={v:#04x}" for k, v in d["echoed"].items()))
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Decode the general block of a 520-byte config reply.")
    ap.add_argument("blob", help="520-byte reply captured from the device")
    args = ap.parse_args(argv)
    with open(args.blob, "rb") as fh:
        blob = fh.read()
    print(format_report(decode_general(blob)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
