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
        with open(path, "rb") as fh:
            self.data = fh.read()
        self._parse()

    # -- parsing ----------------------------------------------------------
    def _parse(self) -> None:
        d = self.data
        if d[:2] != b"MZ":
            raise PEError(f"{self.path}: not a PE file (no MZ)")
        pe_off = struct.unpack_from("<I", d, 0x3C)[0]
        if d[pe_off:pe_off + 4] != b"PE\0\0":
            raise PEError(f"{self.path}: bad PE signature")

        coff = pe_off + 4
        n_sections, = struct.unpack_from("<H", d, coff + 2)
        opt_size, = struct.unpack_from("<H", d, coff + 16)
        opt = coff + 20

        self.magic, = struct.unpack_from("<H", d, opt)
        self.entry_rva, = struct.unpack_from("<I", d, opt + 16)

        # PE32 has a 4-byte BaseOfData at 24, so ImageBase is at 28.
        # PE32+ has no BaseOfData and an 8-byte ImageBase at 24.
        if self.magic == 0x10B:                     # PE32
            self.image_base, = struct.unpack_from("<I", d, opt + 28)
            # NumberOfRvaAndSizes sits at 92, so the directories start at 96.
            self._num_dd_offset = opt + 96
        elif self.magic == 0x20B:                   # PE32+
            self.image_base, = struct.unpack_from("<Q", d, opt + 24)
            self._num_dd_offset = opt + 112
        else:
            raise PEError(f"{self.path}: unknown optional header magic "
                          f"0x{self.magic:04x}")
        self._opt_end = opt + opt_size

        self.sections = []
        off = opt + opt_size
        for _ in range(n_sections):
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
        return struct.unpack_from("<II", self.data, off)

    # -- exports ----------------------------------------------------------
    def exports(self) -> list[tuple[str, int, int]]:
        """[(name, ordinal, va)] sorted by va. Empty if not exported."""
        exp_rva, exp_size = self.directory(0)
        if not exp_rva:
            return []
        eo = self.rva_to_offset(exp_rva)
        if eo is None:
            return []
        (_flags, _ts, _mj, _mn, _name_rva, ord_base, n_addr, n_names,
         addr_rva, names_rva, ords_rva) = struct.unpack_from(
            "<IIHHIIIIIII", self.data, eo)
        if not n_names:
            return []
        names_off = self.rva_to_offset(names_rva)
        addrs_off = self.rva_to_offset(addr_rva)
        ords_off = self.rva_to_offset(ords_rva)
        if None in (names_off, addrs_off, ords_off):
            return []
        out = []
        for i in range(n_names):
            name_rva, = struct.unpack_from("<I", self.data, names_off + 4 * i)
            no = self.rva_to_offset(name_rva)
            name = "" if no is None else \
                self.data[no:].split(b"\0")[0].decode("latin1")
            oi, = struct.unpack_from("<H", self.data, ords_off + 2 * i)
            fn_rva, = struct.unpack_from("<I", self.data, addrs_off + 4 * oi)
            out.append((name, ord_base + oi, self.image_base + fn_rva))
        return sorted(out, key=lambda e: e[2])

    def hexdump(self, off: int, length: int = 64, width: int = 16) -> str:
        lines = []
        va = self.offset_to_va(off)
        for base in range(off, min(off + length, len(self.data)), width):
            chunk = self.data[base:base + width]
            hexpart = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            va_here = self.offset_to_va(base)
            lines.append(f"  {va_here:08x}  {hexpart:<{width * 3}}"
                         f"  |{ascii_part}|")
        return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path")
    ap.add_argument("--sections", action="store_true")
    ap.add_argument("--exports", action="store_true")
    ap.add_argument("--where", metavar="VA",
                    help="report which section and file offset a VA lands in")
    ap.add_argument("--data", metavar="VA:LEN",
                    help="hexdump LEN bytes at a VA")
    args = ap.parse_args()

    pe = PE(args.path)
    kind = "PE32+" if pe.magic == 0x20B else "PE32"
    print(f"{args.path}")
    print(f"  {kind}  image_base=0x{pe.image_base:08x}  "
          f"entry=0x{pe.image_base + pe.entry_rva:08x}  "
          f"{len(pe.data)} bytes")

    if args.where:
        va = int(args.where, 0)
        off = pe.va_to_offset(va)
        print(f"  VA 0x{va:08x}: section {pe.section_of_va(va)}, "
              f"file offset {'0x%x' % off if off is not None else 'unmapped'}")

    if args.data:
        va_s, _, len_s = args.data.partition(":")
        va = int(va_s, 0)
        n = int(len_s, 0) if len_s else 64
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