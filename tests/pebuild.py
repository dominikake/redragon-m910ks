"""
Build synthetic PE images in memory, for testing tools/re_pe.py.

re_pe.py's header arithmetic is the foundation every address in
docs/GUI-ANALYSIS.md rests on, so it is worth pinning against images whose
layout we control exactly -- including ones no vendor binary would ever be.

Real PE32/PE32+ headers, two sections, and an optional export directory.
No third-party code; the repo is standard library only by policy.
"""

from __future__ import annotations

import struct

FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000
E_LFANEW = 0x80

OPT_SIZE_32 = 96 + 8 * 16      # dirs begin at 96 in a PE32 optional header
OPT_SIZE_64 = 112 + 8 * 16     # ...and at 112 in PE32+


def _align(n: int, a: int) -> int:
    return (n + a - 1) // a * a


def build_pe(
    *,
    magic: int = 0x10B,
    image_base: int | None = None,
    exports: tuple[tuple[str, int], ...] = (),
    n_names: int | None = None,
    n_addr: int | None = None,
    overdeclare_raw: int = 0,
    trailing: bytes = b"",
    slots_addr: int | None = None,
    slots_names: int | None = None,
) -> bytes:
    """
    A PE image with a .text section and a .rdata section.

    exports      -- ((name, function_index), ...) for the export directory
    n_names      -- override the *declared* NumberOfNames
    n_addr       -- override the *declared* NumberOfFunctions
    slots_addr   -- size the function-address array independently of the
                    declared count, to build a directory that over-claims
    slots_names  -- likewise for the name-pointer/ordinal arrays
    overdeclare_raw
                  -- inflate the last section's SizeOfRawData past the end of
                     the file, so a dump can run off the mapped data
    trailing     -- bytes appended after every section's raw data, i.e. file
                     offsets that no section maps (an overlay)
    """
    if image_base is None:
        image_base = 0x10000000 if magic == 0x10B else 0x140000000
    opt_size = OPT_SIZE_32 if magic == 0x10B else OPT_SIZE_64

    text = b"\x55\x48\x89\xe5\x5d\xc3"          # push rbp; mov rbp,rsp; ...; ret
    text_rva = SECT_ALIGN                        # 0x1000

    # ---- .rdata: the export directory and everything it points at -------
    n_funcs = len(exports) if n_addr is None else n_addr
    n_named = len(exports) if n_names is None else n_names

    dir_off = 0x20
    # Allocate room for whichever is larger: the declared count, or the number
    # of entries we actually write -- unless the caller explicitly under-sizes
    # an array, which is how a directory that over-claims gets built.
    n_addr_slots = (max(n_funcs, len(exports))
                    if slots_addr is None else slots_addr)
    n_name_slots = (max(n_named, len(exports))
                    if slots_names is None else slots_names)
    addrs_off = dir_off + 40
    names_off = addrs_off + 4 * n_addr_slots
    ords_off = names_off + 4 * n_name_slots
    str_off = ords_off + 2 * n_name_slots

    strs = bytearray()
    name_rvas = []
    for name, _idx in exports:
        name_rvas.append(0x2000 + str_off + len(strs))
        strs += name.encode("latin1") + b"\0"

    addrs = bytearray()
    for _name, idx in exports:
        addrs += struct.pack("<I", text_rva + idx * 0x10)

    names_arr = b"".join(struct.pack("<I", r) for r in name_rvas)
    ords_arr = b"".join(struct.pack("<H", idx) for _n, idx in exports)

    ed = struct.pack(
        "<IIHHIIIIIII",
        0,                  # Characteristics
        0,                  # TimeDateStamp
        0, 0,               # MajorVersion, MinorVersion
        0x2000 + str_off,   # Name
        1,                  # Base (ordinal base)
        n_funcs,            # NumberOfFunctions
        n_named,            # NumberOfNames
        0x2000 + addrs_off,  # AddressOfFunctions
        0x2000 + names_off,  # AddressOfNames
        0x2000 + ords_off,   # AddressOfNameOrdinals
    )

    rdata = bytearray(b"\0" * dir_off) + ed + addrs
    rdata += b"\0" * (names_off - len(rdata)) + names_arr
    rdata += b"\0" * (ords_off - len(rdata)) + ords_arr
    rdata += b"\0" * (str_off - len(rdata)) + bytes(strs)

    rdata_rva = 0x2000

    # ---- lay the file out ----------------------------------------------
    coff = E_LFANEW + 4
    opt = coff + 20
    sec_table = opt + opt_size
    text_raw = _align(sec_table + 40 * 2, FILE_ALIGN)
    rdata_raw = _align(text_raw + len(text), FILE_ALIGN)

    exp_dir_rva = (rdata_rva + dir_off) if (exports or n_names or n_addr) else 0

    buf = bytearray(rdata_raw + len(rdata) + len(trailing))
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, E_LFANEW)
    buf[E_LFANEW:E_LFANEW + 4] = b"PE\0\0"

    struct.pack_into("<HHIIIHH", buf, coff,
                     0x014C,          # Machine: i386
                     2,               # NumberOfSections
                     0, 0, 0,         # timestamp, symbol table, symbols
                     opt_size,
                     0x0102)          # Characteristics

    struct.pack_into("<H", buf, opt, magic)
    struct.pack_into("<I", buf, opt + 16, text_rva)          # entry point
    if magic == 0x10B:
        struct.pack_into("<I", buf, opt + 24, text_rva)      # BaseOfCode
        struct.pack_into("<I", buf, opt + 28, image_base)
        dd = opt + 96
    else:
        struct.pack_into("<I", buf, opt + 20, text_rva)      # BaseOfCode
        struct.pack_into("<Q", buf, opt + 24, image_base)
        dd = opt + 112
    struct.pack_into("<II", buf, dd + 0 * 8, exp_dir_rva, 40)

    def section(off, name, vaddr, vsize, rawptr, rawsize):
        buf[off:off + 8] = name.encode("latin1").ljust(8, b"\0")
        struct.pack_into("<IIII", buf, off + 8, vsize, vaddr, rawsize, rawptr)

    section(sec_table, ".text", text_rva, len(text), text_raw, len(text))
    section(sec_table + 40, ".rdata", rdata_rva, len(rdata),
            rdata_raw, len(rdata) + overdeclare_raw)

    buf[text_raw:text_raw + len(text)] = text
    buf[rdata_raw:rdata_raw + len(rdata)] = rdata
    buf[rdata_raw + len(rdata):] = trailing
    return bytes(buf)