#!/usr/bin/env python3
"""
Minimal PE reader for the vendor binaries in vendor/.

Stdlib only. Exists because two things the analysis needed were not
available from the tooling on hand:

  * binutils `objdump -p` refused to print Lowerdev.dll's export directory,
    yet every function address in docs/GUI-ANALYSIS.md depends on it
  * mapping a virtual address to a file offset is the basis for every
    byte-level claim in the write-up, so it should be a one-liner that a
    reader can check rather than something reconstructed by hand

Deliberately not a general PE library. It does sections, RVA<->offset, the
export table, and the immediate-directory walk -- that is all this project
needs, and less surface means less to get subtly wrong.

Usage:
    python3 tools/re_pe.py vendor/gui/app/Lowerdev.dll           # overview
    python3 tools/re_pe.py vendor/gui/app/OemDrv.exe --exports
    python3 tools/re_pe.py vendor/gui/app/OemDrv.exe --sections
    python3 tools/re_pe.py vendor/gui/app/OemDrv.exe --where 0x40b680
    python3 tools/re_pe.py vendor/gui/app/OemDrv.exe --data 0x5a1a6c:64
"""

from __future__ import annotations

import argparse
import struct
import sys


class PEError(Exception):
    pass


class PE:
    def __init__(self, path: str):
        self.path = path
        try:
            with open(path, "rb") as fh:
                self.data = fh.read()
        except OSError as exc:
            # A missing or unreadable vendor file is an expected condition,
            # not a crash: this tool is pointed at paths that may not exist.
            raise PEError(f"{path}: cannot read ({exc.strerror or exc})")
        self._parse()

    # -- bounds-checked reads ----------------------------------------------
    # Every offset in a PE header is attacker-controlled in the sense that
    # matters here: the file is whatever someone dropped in vendor/, and it
    # may be truncated, garbage, or a structurally valid image whose export
    # directory points off the end of the file. struct.unpack_from raises
    # struct.error on a short buffer, which is not a PEError and so escapes
    # main()'s handler as a traceback. Route every read through these instead.

    def _at(self, off: int, size: int, what: str) -> None:
        if off < 0 or off + size > len(self.data):
            raise PEError(
                f"{self.path}: truncated -- {what} needs {size} byte(s) at "
                f"0x{off:x} but the file is 0x{len(self.data):x} bytes")

    def _u16(self, off: int, what: str) -> int:
        self._at(off, 2, what)
        return struct.unpack_from("<H", self.data, off)[0]

    def _u32(self, off: int, what: str) -> int:
        self._at(off, 4, what)
        return struct.unpack_from("<I", self.data, off)[0]

    def _u64(self, off: int, what: str) -> int:
        self._at(off, 8, what)
        return struct.unpack_from("<Q", self.data, off)[0]

    # -- parsing ----------------------------------------------------------
    def _parse(self) -> None:
        d = self.data
        if d[:2] != b"MZ":
            raise PEError(f"{self.path}: not a PE file (no MZ)")

        # e_lfanew lives at 0x3C, so anything under 0x40 bytes cannot hold it.
        self._at(0x3C, 4, "e_lfanew")
        pe_off = self._u32(0x3C, "e_lfanew")
        self._at(pe_off, 4, "PE signature")
        if d[pe_off:pe_off + 4] != b"PE\0\0":
            raise PEError(f"{self.path}: bad PE signature")

        coff = pe_off + 4
        n_sections = self._u16(coff + 2, "NumberOfSections")
        opt_size = self._u16(coff + 16, "SizeOfOptionalHeader")
        opt = coff + 20

        self.magic = self._u16(opt, "optional header magic")
        self.entry_rva = self._u32(opt + 16, "AddressOfEntryPoint")

        # PE32 has a 4-byte BaseOfData at 24, so ImageBase is at 28.
        # PE32+ has no BaseOfData and an 8-byte ImageBase at 24.
        if self.magic == 0x10B:                     # PE32
            self.image_base = self._u32(opt + 28, "ImageBase")
            # NumberOfRvaAndSizes sits at 92, so the directories start at 96.
            self._num_dd_offset = opt + 96
        elif self.magic == 0x20B:                   # PE32+
            self.image_base = self._u64(opt + 24, "ImageBase")
            self._num_dd_offset = opt + 112
        else:
            raise PEError(f"{self.path}: unknown optional header magic "
                          f"0x{self.magic:04x}")
        self._opt_end = opt + opt_size

        self.sections = []
        off = opt + opt_size
        for i in range(n_sections):
            self._at(off, 40, f"section header {i}")
            name = d[off:off + 8].rstrip(b"\0").decode("latin1")
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", d, off + 8)
            self.sections.append({
                "name": name, "vaddr": vaddr, "vsize": vsize,
                "rawsize": rawsize, "rawptr": rawptr,
            })
            off += 40

    # -- mapping ----------------------------------------------------------
    def rva_to_offset(self, rva: int) -> int | None:
        """Virtual address -> file offset, or None if unmapped."""
        for s in self.sections:
            span = max(s["vsize"], s["rawsize"])
            if s["vaddr"] <= rva < s["vaddr"] + span:
                delta = rva - s["vaddr"]
                if delta >= s["rawsize"]:
                    return None          # in .bss-style padding
                return s["rawptr"] + delta
        return None

    def offset_to_rva(self, off: int) -> int | None:
        for s in self.sections:
            if s["rawptr"] <= off < s["rawptr"] + s["rawsize"]:
                return s["vaddr"] + (off - s["rawptr"])
        return None

    def va_to_offset(self, va: int) -> int | None:
        return self.rva_to_offset(va - self.image_base)

    def offset_to_va(self, off: int) -> int | None:
        rva = self.offset_to_rva(off)
        return None if rva is None else self.image_base + rva

    def section_of_va(self, va: int) -> str | None:
        rva = va - self.image_base
        for s in self.sections:
            if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rawsize"]):
                return s["name"]
        return None

    # -- data directories -------------------------------------------------
    def directory(self, index: int) -> tuple[int, int]:
        off = self._num_dd_offset + index * 8
        if off + 8 > self._opt_end:
            return (0, 0)
        if off + 8 > len(self.data):
            return (0, 0)
        return struct.unpack_from("<II", self.data, off)

    # -- exports ----------------------------------------------------------
    def exports(self) -> list[tuple[str, int, int]]:
        """[(name, ordinal, va)] sorted by va. Empty if not exported."""
        exp_rva, _exp_size = self.directory(0)
        if not exp_rva:
            return []
        eo = self.rva_to_offset(exp_rva)
        if eo is None:
            return []

        # 40-byte IMAGE_EXPORT_DIRECTORY.
        self._at(eo, 40, "export directory")
        ord_base = self._u32(eo + 16, "export Base")
        n_addr = self._u32(eo + 20, "export NumberOfFunctions")
        n_names = self._u32(eo + 24, "export NumberOfNames")
        addr_rva = self._u32(eo + 28, "export AddressOfFunctions")
        names_rva = self._u32(eo + 32, "export AddressOfNames")
        ords_rva = self._u32(eo + 36, "export AddressOfNameOrdinals")
        if not n_names:
            return []

        names_off = self.rva_to_offset(names_rva)
        addrs_off = self.rva_to_offset(addr_rva)
        ords_off = self.rva_to_offset(ords_rva)
        if None in (names_off, addrs_off, ords_off):
            return []

        # NumberOfNames indexes both the name-pointer and the ordinal arrays,
        # so one check covers both. Without it a structurally valid PE whose
        # n_names is larger than the arrays it points at reads past them.
        self._at(names_off, 4 * n_names, "export name-pointer array")
        self._at(ords_off, 2 * n_names, "export ordinal array")
        self._at(addrs_off, 4 * n_addr, "export function-address array")

        out = []
        skipped = 0
        for i in range(n_names):
            name_rva = self._u32(names_off + 4 * i, f"export name pointer {i}")
            no = self.rva_to_offset(name_rva)
            name = "" if no is None else \
                self.data[no:].split(b"\0")[0].decode("latin1")
            oi = self._u16(ords_off + 2 * i, f"export ordinal {i}")
            # The ordinal indexes the *functions* array, not the names array,
            # so it is bounded by n_addr -- a different, usually smaller,
            # count. An out-of-range oi is corrupt, not fatal: skip it.
            if oi >= n_addr:
                skipped += 1
                continue
            fn_rva = self._u32(addrs_off + 4 * oi, f"export function address {oi}")
            out.append((name, ord_base + oi, self.image_base + fn_rva))
        if skipped:
            print(f"warning: {skipped} export name(s) had an ordinal index "
                  f">= NumberOfFunctions ({n_addr}); skipped", file=sys.stderr)
        return sorted(out, key=lambda e: e[2])

    def hexdump(self, off: int, length: int = 64, width: int = 16) -> str:
        lines = []
        for base in range(off, min(off + length, len(self.data)), width):
            chunk = self.data[base:base + width]
            hexpart = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            # A dump long enough to run past the end of its section leaves
            # unmapped offsets, which have no VA to print.
            va_here = self.offset_to_va(base)
            va_txt = f"{va_here:08x}" if va_here is not None else "--------"
            lines.append(f"  {va_txt}  {hexpart:<{width * 3}}"
                         f"  |{ascii_part}|")
        return "\n".join(lines)


def _int_arg(text: str) -> int:
    """argparse type= for a hex-or-decimal integer.

    Without this, a typo reaches int() inside main() and surfaces as a raw
    ValueError traceback instead of a usage error.
    """
    try:
        return int(text, 0)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"{text!r} is not an integer (try 0x40b680 or 1234)")


def _data_arg(text: str) -> tuple[int, int]:
    """argparse type= for VA:LEN, e.g. 0x5a1a6c:64."""
    va_s, sep, len_s = text.partition(":")
    if not sep:
        raise argparse.ArgumentTypeError(
            f"{text!r} is not VA:LEN (try 0x5a1a6c:64)")
    try:
        va = int(va_s, 0)
        n = int(len_s, 0) if len_s else 64
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"{text!r} is not VA:LEN with hex-or-decimal parts (try 0x5a1a6c:64)")
    if n < 0:
        raise argparse.ArgumentTypeError(f"{text!r}: length must not be negative")
    return va, n


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path")
    ap.add_argument("--sections", action="store_true")
    ap.add_argument("--exports", action="store_true")
    ap.add_argument("--where", metavar="VA", type=_int_arg,
                    help="report which section and file offset a VA lands in")
    ap.add_argument("--data", metavar="VA:LEN", type=_data_arg,
                    help="hexdump LEN bytes at a VA")
    args = ap.parse_args()

    pe = PE(args.path)
    kind = "PE32+" if pe.magic == 0x20B else "PE32"
    print(f"{args.path}")
    print(f"  {kind}  image_base=0x{pe.image_base:08x}  "
          f"entry=0x{pe.image_base + pe.entry_rva:08x}  "
          f"{len(pe.data)} bytes")

    if args.where is not None:
        va = args.where
        off = pe.va_to_offset(va)
        print(f"  VA 0x{va:08x}: section {pe.section_of_va(va)}, "
              f"file offset {'0x%x' % off if off is not None else 'unmapped'}")

    if args.data is not None:
        va, n = args.data
        off = pe.va_to_offset(va)
        if off is None:
            print(f"  VA 0x{va:08x} is unmapped")
            return 1
        print(pe.hexdump(off, n))

    if args.sections or not (args.exports or args.where or args.data):
        print("  sections:")
        for s in pe.sections:
            print(f"    {s['name']:<9} vaddr=0x{s['vaddr']:06x} "
                  f"vsize=0x{s['vsize']:06x} rawptr=0x{s['rawptr']:06x} "
                  f"rawsize=0x{s['rawsize']:06x}")

    if args.exports:
        exps = pe.exports()
        print(f"  {len(exps)} export(s):")
        for name, ordv, va in exps:
            print(f"    [{ordv:3d}] 0x{va:08x}  {name}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except PEError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)