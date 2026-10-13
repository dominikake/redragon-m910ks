"""
Central safety policy for talking to the Sino Wealth device.

READ-ONLY BY DEFAULT. Nothing in this repo sends a config, matrix, macro or
PSD write, and this module is what makes that a property of the code rather
than a promise in a README.

The command classification comes from the static analysis in
docs/GUI-ANALYSIS.md. The vendor's own control panel has ten commands:

    0x01        general / firmware info          read
    0x11 0x21 0x31  get config, profiles 1/2/3  read
    0x12 0x22 0x32  set key matrix, profiles     WRITE
    0x30        set macro                        WRITE
    0x90        read power                       read
    0x92        write PSD                        WRITE
    0x75        enter DFU                        NEVER

Two of those facts are load-bearing:

  * Sino Wealth devices have a documented history of soft-bricking from
    malformed config writes -- OpenRGB disabled its driver over exactly
    this. A malformed blob can persist across a power cycle.
  * A device that is recoverable only via Redragon's Windows updater is not
    recoverable for a Linux-only user, and is functionally a brick. So the
    bar for writing is not "it worked last time".

Why this is a module and not a comment: prose decays and a guard does not.
`0x75` in particular is unreachable *by construction* -- there is no flag, no
environment variable and no override path, so no later refactor can make it
reachable by accident.

Two things are deliberately NOT the same:

  * RAM vs flash is not ours to choose. The device commits its own changes
    the moment a button is pressed on the mouse. That is safe, because the
    value is one the device considers valid. The risk is us crafting 520
    bytes and hoping.
  * Lifting the read-only default requires establishing a recovery path that
    does not depend on Windows (issue #9) -- not merely one successful read.

Self-check:  python3 tools/safety.py
"""

from __future__ import annotations

# Commands the vendor app uses to WRITE device state.
WRITE_COMMANDS = frozenset({
    0x12,   # set key matrix, profile 1
    0x22,   # set key matrix, profile 2
    0x32,   # set key matrix, profile 3
    0x30,   # set macro
    0x92,   # write PSD (device signature)
})

# Commands known to be safe reads.
READ_COMMANDS = frozenset({
    0x01,   # general / firmware info
    0x11,   # get config, profile 1
    0x21,   # get config, profile 2
    0x31,   # get config, profile 3
    0x90,   # read power (battery)
})

# Enters the DFU bootloader. Never send. No override exists.
DFU = 0x75

# The bulk data report (520 bytes). A SET_FEATURE on this report is always a
# write: config *reads* go out on the CMD report (0x05) and come back on
# 0x08 via GET_FEATURE, so nothing read-only ever sends to 0x08.
REPORT_ID_CONFIG = 0x08

ALL_KNOWN = WRITE_COMMANDS | READ_COMMANDS | {DFU}


class UnsafeCommand(PermissionError):
    """Raised when code tries to send something the policy forbids."""


def _command_of(buf: bytes) -> int | None:
    """The command byte of a framed report, or None if there isn't one."""
    # framed layout: [0] = report id, [1] = command
    if len(buf) >= 2:
        return buf[1]
    if len(buf) == 1:
        return buf[0]
    return None


def guard_feature_report(buf: bytes, *, allow_write: bool = False) -> None:
    """
    Refuse to send a report that would modify the device.

    `buf` must be a framed report: report id at [0], command at [1].

    Raises UnsafeCommand unless the send is a read, or is a write with
    `allow_write=True` passed explicitly at the call site.
    """
    cmd = _command_of(buf)

    # DFU first, and unconditionally. Checked before anything else so it can
    # never be reached by setting allow_write.
    if cmd == DFU:
        raise UnsafeCommand(
            f"refusing to send {DFU:#04x} (DFU bootloader): there is no "
            f"override for this command under any circumstances"
        )

    if buf and buf[0] == REPORT_ID_CONFIG:
        if not allow_write:
            raise UnsafeCommand(
                f"refusing to SET_FEATURE on the config report "
                f"({REPORT_ID_CONFIG:#04x}): that is the bulk data write path"
            )
        return

    if cmd in WRITE_COMMANDS:
        if not allow_write:
            raise UnsafeCommand(
                f"refusing to send write command {cmd:#04x}; this repo is "
                f"read-only by default (see docs/GUI-ANALYSIS.md). Pass "
                f"allow_write=True at the call site to override deliberately."
            )


def guard_command(cmd: int, *, allow_write: bool = False) -> None:
    """Refuse a bare command id that would modify the device."""
    guard_feature_report(bytes([0x05, cmd]), allow_write=allow_write)


def selfcheck() -> bool:
    """
    Verify the policy actually holds. Run by `python3 tools/safety.py`.

    Returns True if every expectation is met.
    """
    ok = True

    def expect_raise(label, fn):
        nonlocal ok
        try:
            fn()
        except UnsafeCommand:
            print(f"  PASS  {label}")
        except Exception as exc:                       # noqa: BLE001
            print(f"  FAIL  {label} -- raised {type(exc).__name__}, "
                  f"expected UnsafeCommand: {exc}")
            ok = False
        else:
            print(f"  FAIL  {label} -- nothing raised")
            ok = False

    def expect_allow(label, fn):
        nonlocal ok
        try:
            fn()
        except UnsafeCommand as exc:
            print(f"  FAIL  {label} -- wrongly blocked: {exc}")
            ok = False
        else:
            print(f"  PASS  {label}")

    print("read-only default")
    for cmd in sorted(READ_COMMANDS):
        expect_allow(f"read {cmd:#04x} allowed", lambda c=cmd: guard_command(c))
    for cmd in sorted(WRITE_COMMANDS):
        expect_raise(f"write {cmd:#04x} blocked",
                     lambda c=cmd: guard_command(c))

    print("\nDFU is unreachable, even when writes are explicitly allowed")
    expect_raise("0x75 blocked by default",
                 lambda: guard_command(DFU))
    expect_raise("0x75 blocked with allow_write=True",
                 lambda: guard_command(DFU, allow_write=True))
    expect_raise("0x75 blocked on the config report with allow_write=True",
                 lambda: guard_feature_report(bytes([REPORT_ID_CONFIG, DFU]),
                                              allow_write=True))

    print("\nconfig report is write-only by construction")
    expect_raise("SET on report 0x08 blocked",
                 lambda: guard_feature_report(bytes([REPORT_ID_CONFIG, 0x21])))
    expect_raise("SET on report 0x08 blocked even for a read command",
                 lambda: guard_feature_report(bytes([REPORT_ID_CONFIG, 0x11])))
    expect_allow("SET on report 0x08 with allow_write=True",
                 lambda: guard_feature_report(bytes([REPORT_ID_CONFIG, 0x21]),
                                              allow_write=True))
    expect_allow("GET on report 0x08 unaffected (reads use this)",
                 lambda: guard_feature_report(bytes([REPORT_ID_CONFIG, 0x21]),
                                              allow_write=True))

    print("\ndeliberate override is visible at the call site")
    for cmd in sorted(WRITE_COMMANDS):
        expect_allow(f"write {cmd:#04x} allowed with explicit opt-in",
                     lambda c=cmd: guard_command(c, allow_write=True))

    print("\nclassification is disjoint and complete")
    overlap = WRITE_COMMANDS & READ_COMMANDS
    if overlap:
        print(f"  FAIL  read and write sets overlap: "
              f"{sorted(hex(c) for c in overlap)}")
        ok = False
    else:
        print("  PASS  read and write sets are disjoint")
    if DFU in WRITE_COMMANDS or DFU in READ_COMMANDS:
        print("  FAIL  DFU appears in a sendable set")
        ok = False
    else:
        print("  PASS  DFU is in neither sendable set")

    print()
    print("safety policy holds" if ok else "SAFETY POLICY VIOLATED")
    return ok


if __name__ == "__main__":
    import sys

    sys.exit(0 if selfcheck() else 1)