#!/usr/bin/env python3
"""
Differential field mapping for the 520-byte config blob.

The point: the mouse has physical buttons for DPI, profile and lighting.
Pressing one changes device-internal state without us sending a write at all.
So we can map which blob offset corresponds to which setting by pressing a
button and diffing a plain read.

Zero writes. Nothing here can modify the device.

Usage:
    # save the current blob as the baseline to compare against
    python3 tools/profile_diff.py --baseline

    # read once and show what changed
    python3 tools/profile_diff.py --diff

    # poll for a while and report changes as they happen.
    # Press a button on the mouse while this runs.
    python3 tools/profile_diff.py --watch --seconds 60

    # forget the baseline
    python3 tools/profile_diff.py --reset

The baseline lives in the repo state dir, so it survives across runs.
"""

from __future__ import annotations

import argparse
import errno as _errno
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import safety  # noqa: E402
from history import STATE_DIR  # noqa: E402
from sinowealth import (  # noqa: E402
    REPORT_ID_CONFIG,
    REPORT_SIZE_CONFIG,
    SinoWealthDevice,
    enumerate_nodes,
)

# cmd 0x21 is the only config command this device answers (see #4).
CMD_CONFIG = 0x21

BASELINE = os.path.join(STATE_DIR, "config-baseline.bin")


def read_config(dev: SinoWealthDevice, retries: int = 3,
                errors: list | None = None) -> bytes | None:
    """
    Read the config blob. Returns None if no read succeeded.

    None does NOT mean "asleep". A short read, a stalled control transfer and
    a permissions problem all land here, and they have different fixes --
    docs/GUI-ANALYSIS.md records a 520-byte read stalling into EPIPE, which
    "looks like a dead device but is not one". So collect the errno into
    `errors` (if given) and let the caller say something true.

    A None result is NOT the same as an empty read, and must never be
    recorded as one.
    """
    safety.guard_command(CMD_CONFIG)
    from sinowealth import REPORT_ID_CMD  # local: only needed on this path

    for _ in range(retries):
        try:
            dev.set_feature_report(
                REPORT_ID_CMD,
                bytes([REPORT_ID_CMD, CMD_CONFIG, 0, 0, 0, 0, 0, 0]),
            )
            time.sleep(0.25)
            reply = dev.get_feature_report(REPORT_ID_CONFIG, REPORT_SIZE_CONFIG)
        except OSError as exc:
            if errors is not None:
                errors.append(exc.errno)
            time.sleep(0.4)
            continue
        if len(reply) >= 2 and reply[1] == CMD_CONFIG:
            return reply
        if errors is not None:
            # Not an error, but not a usable answer either: the device
            # answered, just not with our command echoed back.
            errors.append(_errno.EPROTO)
        time.sleep(0.4)
    return None


# What each failure errno most likely means for *this* tool, and what to do
# about it. Ordered most-specific first.
_READ_FAILURES = (
    (_errno.EACCES, _errno.EPERM,
     "permission denied on the hidraw node -- add a udev rule, or re-run "
     "with sufficient access (see install.sh)"),
    (_errno.ENODEV, _errno.ENXIO,
     "the device went away -- unplug it, plug it back in, retry"),
    (_errno.EPIPE,
     "the control transfer stalled mid-read. A sleeping mouse looks exactly "
     "like this, so nudge the mouse and retry -- but it is not proof the "
     "device is dead"),
    (_errno.EPROTO,
     "the device answered, but not with cmd 0x21 echoed in byte 1"),
)


def explain_read_failure(errnos: list) -> str:
    """One honest line about why the read did not produce a blob."""
    if not errnos:
        return ("no error was reported, so the mouse is probably asleep -- "
                "move it while watching, then run this again")
    for codes, text in _READ_FAILURES:
        if any(e in codes for e in errnos):
            return text
    names = ", ".join(sorted({_errno.errorcode.get(e, str(e)) for e in errnos}))
    return f"reads failed with: {names}"


def diff(a: bytes, b: bytes, label_a="baseline", label_b="current") -> list:
    out = []
    for i in range(max(len(a), len(b))):
        x = a[i] if i < len(a) else None
        y = b[i] if i < len(b) else None
        if x != y:
            out.append((i, x, y))
    if out:
        print(f"{len(out)} byte(s) differ ({label_a} -> {label_b}):\n")
        for i, x, y in out:
            xs = f"0x{x:02x}" if x is not None else "--"
            ys = f"0x{y:02x}" if y is not None else "--"
            print(f"  offset {i:#06x} ({i:3d}): {xs} -> {ys}")
    return out


def open_device() -> SinoWealthDevice:
    nodes = [n for _, n in enumerate_nodes("258A", "002F")]
    if not nodes:
        raise SystemExit("dongle 258a:002f not found")
    return SinoWealthDevice(nodes[-1])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--baseline", action="store_true",
                   help="save the current blob as the baseline")
    g.add_argument("--diff", action="store_true",
                   help="read once and compare against the baseline")
    g.add_argument("--watch", action="store_true",
                   help="poll and report changes as they happen")
    g.add_argument("--reset", action="store_true",
                   help="delete the saved baseline")
    ap.add_argument("--seconds", type=float, default=60.0)
    ap.add_argument("--every", type=float, default=1.0)
    args = ap.parse_args()

    if args.reset:
        if os.path.exists(BASELINE):
            os.remove(BASELINE)
            print(f"removed {BASELINE}")
        else:
            print("no baseline saved")
        return 0

    if args.watch:
        if not os.path.exists(BASELINE):
            print("no baseline saved -- run with --baseline first",
                  file=sys.stderr)
            return 1
        with open(BASELINE, "rb") as fh:
            base = fh.read()
        print(f"watching for {args.seconds:.0f}s against the saved baseline.")
        print("Press a button on the MOUSE while this runs.")
        print("Keep nudging the mouse -- if it sleeps, reads stall.\n")
        prev = base
        deadline = time.time() + args.seconds
        seen: set = set()
        reads = stalled = 0
        errnos: list = []
        with open_device() as dev:
            while time.time() < deadline:
                blob = read_config(dev, errors=errnos)
                if blob is None:
                    stalled += 1
                    if stalled == 3 and reads == 0:
                        print("  still no response -- nudge the mouse and "
                              "keep waiting.\n")
                    time.sleep(args.every)
                    continue
                reads += 1
                if blob == prev:
                    time.sleep(args.every)
                    continue
                changes = diff(prev, blob, "previous", "now")
                if changes:
                    print("  ^^ press a button now and watch for the next "
                          "change\n")
                    seen.update(i for i, _, _ in changes)
                prev = blob
                time.sleep(args.every)

        # Without this, "nothing changed" and "never managed to read at all"
        # print the same thing, and the second one makes the run worthless.
        print(f"\nreads: {reads} successful, {stalled} unsuccessful "
              f"out of {reads + stalled} attempts")
        if reads == 0:
            print("\nNO SUCCESSFUL READS.")
            print(f"  {explain_read_failure(errnos)}")
            return 2
        if seen:
            print("offsets that moved at least once: "
                  + " ".join(hex(i) for i in sorted(seen)))
        else:
            print("offsets that moved at least once: none "
                  "-- nothing you pressed changed the config, "
                  "which is itself an answer")
        return 0

    errnos: list = []
    with open_device() as dev:
        blob = read_config(dev, errors=errnos)

    if blob is None:
        print("could not read the config blob", file=sys.stderr)
        print(f"  {explain_read_failure(errnos)}", file=sys.stderr)
        return 2

    if args.baseline:
        os.makedirs(os.path.dirname(BASELINE), exist_ok=True)
        with open(BASELINE, "wb") as fh:
            fh.write(blob)
        print(f"baseline saved ({len(blob)} bytes) -> {BASELINE}")
        nz = [i for i, b in enumerate(blob) if b]
        print(f"non-zero offsets: {nz}")
        return 0

    if not os.path.exists(BASELINE):
        print("no baseline saved -- run with --baseline first", file=sys.stderr)
        return 1
    with open(BASELINE, "rb") as fh:
        base = fh.read()

    changes = diff(base, blob, "baseline", "current")
    if not changes:
        print("identical to the baseline")
    return 0


if __name__ == "__main__":
    sys.exit(main())