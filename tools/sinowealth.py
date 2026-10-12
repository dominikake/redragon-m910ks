"""
Minimal Sino Wealth HID transport for the Redragon M910-KS.

Pure standard library -- no pyusb, no hidapi, no pip. Uses fcntl.ioctl
against /dev/hidrawN, which is exactly what HIDIOCGFEATURE /
HIDIOCSFEATURE do.

Device under test:
    258a:002f  SINOWEALTH 2.4G Wireless Receiver   (dongle)
      interface 1.0 -> hidraw0 : boot mouse
      interface 1.1 -> hidraw1 : vendor control channel

    258a:002e  SINOWEALTH Wired Gaming Mouse       (cable mode)
      interface 1.0 -> hidraw4 : boot mouse
      interface 1.1 : vendor channel, not bound to hid-generic yet

Wire format, as recovered from the interface 1.1 HID report descriptor:

    Usage Page 0xFF00 (vendor defined)
      Report ID 5 -> 7 byte report   (CMD channel)
      Report ID 6 -> 7 byte report
      Report ID 7 -> 7 byte report
      Report ID 8 -> 519 byte report (+1 report ID byte = 520)

The 520 byte total matches libratbag's
SINOWEALTH_CONFIG_REPORT_SIZE, so the config blob layout from
libratbag's sinowealth driver should apply here.

SAFETY: nothing in this module writes a config blob. Only read-style
queries are implemented. See docs/PROTOCOL.md.
"""

from __future__ import annotations

import ctypes
import fcntl
import glob
import os
import re
import struct
import sys
import time

# --- Linux HID ioctl numbers (from linux/hidraw.h) -------------------------
# _IOC(dir, type, nr, size) with dir=3 (read|write) for these.
_IOC_NRBITS = 8
_IOC_TYPEBITS = 8
_IOC_SIZEBITS = 14
_IOC_NRSHIFT = 0
_IOC_TYPESHIFT = _IOC_NRSHIFT + _IOC_NRBITS
_IOC_SIZESHIFT = _IOC_TYPESHIFT + _IOC_TYPEBITS
_IOC_DIRSHIFT = _IOC_SIZESHIFT + _IOC_SIZEBITS
_IOC_NONE = 0
_IOC_WRITE = 1
_IOC_READ = 2


def _ioc(direction: int, typ: str, nr: int, size: int) -> int:
    return (
        (direction << _IOC_DIRSHIFT)
        | (ord(typ) << _IOC_TYPESHIFT)
        | (nr << _IOC_NRSHIFT)
        | (size << _IOC_SIZESHIFT)
    )


# The kernel derives the transfer length from _IOC_SIZE(cmd) -- it does NOT
# get the length from the userspace buffer. So the size encoded here MUST
# match the buffer we actually pass, or the kernel writes past its end.
# Hence HIDIOCGFEATURE/SFEATURE are functions of the length below, exactly
# as hidapi does it.
HID_MAX_DESCRIPTOR_SIZE = 4096

HIDIOCGRDESCSIZE = _ioc(_IOC_READ, "H", 0x01, 4)
HIDIOCGRDESC = _ioc(_IOC_READ, "H", 0x02, HID_MAX_DESCRIPTOR_SIZE)
HIDIOCGFEATURE = _ioc(_IOC_READ | _IOC_WRITE, "H", 0x07, HID_MAX_DESCRIPTOR_SIZE)
HIDIOCSFEATURE = _ioc(_IOC_READ | _IOC_WRITE, "H", 0x06, HID_MAX_DESCRIPTOR_SIZE)

# Python's fcntl.ioctl refuses immutable bytes buffers larger than 1024.
_IOCTL_BUF_LIMIT = 1024

_libc = ctypes.CDLL(None, use_errno=True)


def hidiocgfeature(length: int) -> int:
    return _ioc(_IOC_READ | _IOC_WRITE, "H", 0x07, length)


def hidiocsfeature(length: int) -> int:
    return _ioc(_IOC_READ | _IOC_WRITE, "H", 0x06, length)


def _ioctl_raw(fd: int, request: int, buf: bytearray) -> int:
    """
    ioctl(2) via ctypes, for buffers larger than fcntl's 1024-byte limit.
    fcntl.ioctl is simpler for the common small case; a full 4096-byte
    report descriptor does not fit there, so it goes through libc.
    """
    arr = (ctypes.c_char * len(buf)).from_buffer(buf)
    rc = _libc.ioctl(ctypes.c_int(fd), ctypes.c_ulong(request),
                     ctypes.byref(arr))
    if rc < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return rc

# --- Report IDs seen on the vendor usage page ------------------------------
REPORT_ID_CMD = 0x05
REPORT_ID_SHORT_A = 0x06
REPORT_ID_SHORT_B = 0x07
REPORT_ID_CONFIG = 0x08

# Total on-wire size including the leading report ID byte.
REPORT_SIZE_SHORT = 8
REPORT_SIZE_CONFIG = 520

# Command IDs recovered from libratbag's driver-sinowealth.c. These are
# documented for the wired Sino Wealth mouse protocol. They are NOT yet
# confirmed on this dongle -- treat as hypotheses until observed.
CMD_FIRMWARE_VERSION = 0x01
CMD_PROFILE = 0x02
CMD_GET_CONFIG = 0x11
CMD_GET_BUTTONS = 0x12
CMD_DEBOUNCE = 0x1A
CMD_LONG_LOD_ANGLE_SNAP = 0x1B
CMD_GET_CONFIG2 = 0x21
CMD_GET_BUTTONS2 = 0x22
CMD_MACRO = 0x30
CMD_GET_CONFIG3 = 0x31
CMD_GET_BUTTONS3 = 0x32
CMD_DFU = 0x75  # NEVER send this. Enters the bootloader.


class HidError(RuntimeError):
    pass


def _errno_text(exc: OSError) -> str:
    err = exc.errno
    try:
        return f"{os.strerror(err)} (errno {err})"
    except ValueError:
        return str(exc)


class SinoWealthDevice:
    """A single hidraw node."""

    def __init__(self, path: str):
        self.path = path
        try:
            self._fd = os.open(path, os.O_RDWR)
        except PermissionError:
            raise HidError(
                f"permission denied opening {path}; needs a udev rule "
                f"(see docs/SETUP.md)"
            ) from None
        except OSError as exc:
            raise HidError(f"cannot open {path}: {_errno_text(exc)}") from None

    # -- lifecycle ---------------------------------------------------------
    def close(self) -> None:
        if getattr(self, "_fd", None) is not None:
            try:
                os.close(self._fd)
            finally:
                self._fd = None

    def __enter__(self) -> "SinoWealthDevice":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- introspection -----------------------------------------------------
    def get_report_descriptor(self) -> bytes:
        # Two-step, as hidapi does: ask the size, then fetch exactly that.
        size = fcntl.ioctl(self._fd, HIDIOCGRDESCSIZE, 0)
        size = int(size) if not isinstance(size, int) else size
        size = max(1, min(size, HID_MAX_DESCRIPTOR_SIZE))
        buf = bytearray(size)
        _ioctl_raw(self._fd, _ioc(_IOC_READ, "H", 0x02, size), buf)
        return bytes(buf)

    def list_report_ids(self) -> list[int]:
        """Report IDs present in this node's descriptor."""
        try:
            desc = self.get_report_descriptor()
        except OSError:
            return []
        return sorted({desc[i + 1] for i in range(len(desc) - 1)
                       if desc[i] == 0x85})

    # -- feature report transport -----------------------------------------
    def get_feature_report(self, report_id: int, length: int) -> bytes:
        buf = bytearray(length)
        buf[0] = report_id
        req = hidiocgfeature(length)
        if length > _IOCTL_BUF_LIMIT:
            _ioctl_raw(self._fd, req, buf)
        else:
            buf = bytearray(fcntl.ioctl(self._fd, req, bytes(buf)))
        return bytes(buf)

    def set_feature_report(self, report_id: int, data: bytes) -> int:
        if data[0] != report_id:
            data = bytes([report_id]) + bytes(data)
        buf = bytearray(data)
        req = hidiocsfeature(len(buf))
        if len(buf) > _IOCTL_BUF_LIMIT:
            return _ioctl_raw(self._fd, req, buf)
        return fcntl.ioctl(self._fd, req, bytes(buf))

    # -- high level queries ------------------------------------------------
    def cmd_query(self, command: int, length: int = REPORT_SIZE_SHORT,
                  settle: float = 0.09) -> bytes:
        """
        The Sino Wealth read idiom, per libratbag:

            SET_FEATURE(report_id, [report_id, command, ...])
            sleep
            GET_FEATURE(report_id, length)

        Returns the raw reply. Raises HidError if the node refuses.
        """
        payload = bytes([REPORT_ID_CMD, command]) + b"\x00" * (length - 2)
        try:
            self.set_feature_report(REPORT_ID_CMD, payload)
        except OSError as exc:
            raise HidError(
                f"SET_FEATURE id={REPORT_ID_CMD} cmd={command:#04x} failed: "
                f"{_errno_text(exc)}"
            ) from None
        if settle:
            time.sleep(settle)
        try:
            return self.get_feature_report(REPORT_ID_CMD, length)
        except OSError as exc:
            raise HidError(
                f"GET_FEATURE id={REPORT_ID_CMD} cmd={command:#04x} failed: "
                f"{_errno_text(exc)}"
            ) from None

    def firmware_version(self) -> str:
        reply = self.cmd_query(CMD_FIRMWARE_VERSION)
        if len(reply) < 6:
            return f"<short reply {len(reply)}B: {reply.hex(' ')}>"
        if reply[1] != CMD_FIRMWARE_VERSION:
            return (f"<command mismatch: asked {CMD_FIRMWARE_VERSION:#04x}, "
                    f"got {reply[1]:#04x}; raw {reply.hex(' ')}>")
        # Driver reads 4 bytes starting at offset 2.
        return bytes(reply[2:6]).decode("ascii", errors="replace")


# --- discovery -------------------------------------------------------------
def enumerate_nodes(vendor: str = "258A", product: str = "002F") -> list[tuple[str, str]]:
    """
    Map hidraw nodes belonging to a given USB VID:PID.

    Returns [(hid_id, /dev/hidrawN), ...].
    Reads sysfs only; safe to call without permissions.
    """
    found = []
    for link in sorted(glob.glob("/sys/class/hidraw/hidraw*")):
        real = os.path.realpath(link)
        m = re.search(r"0003:([0-9A-F]{4}):([0-9A-F]{4})", real)
        if not m:
            continue
        if m.group(1) != vendor.upper() or m.group(2) != product.upper():
            continue
        node = f"/dev/{os.path.basename(link)}"
        found.append((f"{m.group(1)}:{m.group(2)}", node))
    return found


def hexdump(data: bytes, width: int = 16) -> str:
    out = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"  {off:04x}  {hexpart:<{width * 3}}  |{ascii_part}|")
    return "\n".join(out)


if __name__ == "__main__":
    # Self-test: report IDs exposed by each matching node.
    target = sys.argv[1] if len(sys.argv) > 1 else "258A:002F"
    vendor, product = target.split(":")
    nodes = enumerate_nodes(vendor, product)
    if not nodes:
        print(f"no hidraw nodes found for {target}")
        sys.exit(1)
    print(f"{target}: {len(nodes)} hidraw node(s)\n")
    for hid_id, path in nodes:
        print(f"=== {path}  ({hid_id}) ===")
        try:
            with SinoWealthDevice(path) as dev:
                desc = dev.get_report_descriptor()
                print(f"  report descriptor: {len(desc)} bytes")
                ids = sorted({desc[i + 1] for i in range(len(desc) - 1)
                              if desc[i] == 0x85})
                print(f"  report IDs: {[hex(i) for i in ids] or 'none'}")
        except HidError as exc:
            print(f"  ERROR: {exc}")
        print()