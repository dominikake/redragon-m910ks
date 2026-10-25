"""
Tests for tools/re_pe.py -- the PE header arithmetic every address in
docs/GUI-ANALYSIS.md depends on.

Stdlib unittest only: this repo is zero-dependency by policy.

    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import io
import os
import struct
import sys
import tempfile
import unittest
from contextlib import redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))

import pebuild                                              # noqa: E402
import re_pe                                                # noqa: E402


class _TmpPE:
    """Write bytes to a temp file and hand back a PE parsed from it."""

    def __init__(self, data: bytes):
        fd, self.path = tempfile.mkstemp(suffix=".bin")
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        self.pe = re_pe.PE(self.path)

    def close(self) -> None:
        os.unlink(self.path)

    def __enter__(self):
        return self.pe

    def __exit__(self, *exc):
        self.close()


class TestHeaderArithmetic(unittest.TestCase):
    """The PE32/PE32+ field offsets, pinned both ways."""

    def test_pe32_image_base_is_at_optional_header_plus_28(self):
        # PE32 has a 4-byte BaseOfData at 24, which pushes ImageBase to 28.
        # Getting this wrong shifts every VA the tool reports.
        with _TmpPE(pebuild.build_pe(magic=0x10B, image_base=0x10000000)) as pe:
            self.assertEqual(pe.magic, 0x10B)
            self.assertEqual(pe.image_base, 0x10000000)
            self.assertEqual(pe._num_dd_offset % 2, 0)

    def test_pe32plus_image_base_is_8_bytes_at_24(self):
        # PE32+ drops BaseOfData and widens ImageBase to 8 bytes at 24.
        with _TmpPE(pebuild.build_pe(magic=0x20B, image_base=0x140000000)) as pe:
            self.assertEqual(pe.magic, 0x20B)
            self.assertEqual(pe.image_base, 0x140000000)

    def test_sections_parsed_with_names(self):
        with _TmpPE(pebuild.build_pe()) as pe:
            self.assertEqual([s["name"] for s in pe.sections],
                             [".text", ".rdata"])

    def test_va_offset_roundtrip_both_directions(self):
        for magic in (0x10B, 0x20B):
            with self.subTest(magic=hex(magic)):
                with _TmpPE(pebuild.build_pe(magic=magic)) as pe:
                    for rva in (0x1000, 0x1002, 0x1004, 0x2000, 0x2004):
                        off = pe.rva_to_offset(rva)
                        self.assertIsNotNone(off)
                        self.assertEqual(pe.offset_to_rva(off), rva)

    def test_va_offset_roundtrip_through_va_helpers(self):
        with _TmpPE(pebuild.build_pe()) as pe:
            va = pe.image_base + 0x1000
            off = pe.va_to_offset(va)
            self.assertIsNotNone(off)
            self.assertEqual(pe.offset_to_va(off), va)
            self.assertEqual(pe.section_of_va(va), ".text")

    def test_unmapped_rva_returns_none(self):
        with _TmpPE(pebuild.build_pe()) as pe:
            self.assertIsNone(pe.rva_to_offset(0x900000))

    def test_rva_past_rawsize_is_unmapped(self):
        # .text declares vsize > rawsize is not built here, but a delta that
        # lands past the end of the raw data must be refused, not read.
        with _TmpPE(pebuild.build_pe()) as pe:
            text = pe.sections[0]
            beyond = text["vaddr"] + text["rawsize"]
            self.assertIsNone(pe.rva_to_offset(beyond))


class TestExports(unittest.TestCase):
    def test_exports_resolve_name_ordinal_and_va(self):
        blob = pebuild.build_pe(exports=(("Alpha", 0), ("Beta", 1), ("Gamma", 2)))
        with _TmpPE(blob) as pe:
            exps = pe.exports()
        self.assertEqual(len(exps), 3)
        by_name = {n: (o, v) for n, o, v in exps}
        self.assertEqual(by_name["Alpha"][0], 1)          # ordinal base is 1
        self.assertEqual(by_name["Gamma"][0], 3)
        # function_index * 0x10 into .text, plus image base
        self.assertEqual(by_name["Beta"][1], 0x10000000 + 0x1000 + 0x10)

    def test_no_export_directory_yields_empty_list(self):
        with _TmpPE(pebuild.build_pe()) as pe:
            self.assertEqual(pe.exports(), [])

    def test_ordinal_index_beyond_number_of_functions_is_skipped(self):
        """
        An ordinal indexes the *functions* array, whose length is
        NumberOfFunctions -- not NumberOfNames. Reading past it is reachable
        on a structurally valid PE, so it must be rejected, not just avoided
        on corrupt ones.
        """
        blob = pebuild.build_pe(
            exports=(("Good", 0), ("Bad", 9)),
            n_addr=1,          # only one function exists
        )
        with _TmpPE(blob) as pe:
            buf = io.StringIO()
            with redirect_stderr(buf):
                exps = pe.exports()
            self.assertEqual([n for n, _, _ in exps], ["Good"])
            self.assertIn("skipped", buf.getvalue())

    def test_name_count_larger_than_the_array_it_points_at(self):
        """NumberOfNames indexes both pointer arrays; check them up front."""
        blob = pebuild.build_pe(exports=(("Only", 0),), n_names=64,
                                slots_names=1)
        with self.assertRaises(re_pe.PEError) as cm:
            with _TmpPE(blob) as pe:
                pe.exports()
        self.assertIn("truncated", str(cm.exception))

    def test_function_array_shorter_than_the_declared_count(self):
        """NumberOfFunctions bounds the array the ordinals index into."""
        blob = pebuild.build_pe(exports=(("Only", 0),), n_addr=4096,
                                slots_addr=1)
        with self.assertRaises(re_pe.PEError) as cm:
            with _TmpPE(blob) as pe:
                pe.exports()
        self.assertIn("truncated", str(cm.exception))


class TestMalformedInput(unittest.TestCase):
    """Every failure must be a PEError, never a traceback.

    This tool's whole job is ingesting arbitrary binaries out of vendor/,
    which may be truncated or not a PE at all.
    """

    def _parse_raises(self, data: bytes, needle: str = ""):
        with self.assertRaises(re_pe.PEError) as cm:
            with _TmpPE(data):
                pass
        if needle:
            self.assertIn(needle, str(cm.exception))
        return cm

    def test_empty_file(self):
        self._parse_raises(b"", "no MZ")

    def test_shorter_than_the_dos_header(self):
        self._parse_raises(b"MZ" + b"\0" * 20, "e_lfanew")

    def test_not_a_pe(self):
        self._parse_raises(b"\x7fELF" + b"\0" * 512, "no MZ")

    def test_bad_pe_signature(self):
        d = bytearray(pebuild.build_pe())
        struct.pack_into("<I", d, 0x3C, 0x80)
        d[0x80:0x84] = b"XX\0\0"
        self._parse_raises(bytes(d), "bad PE signature")

    def test_unknown_optional_header_magic(self):
        d = bytearray(pebuild.build_pe())
        opt = 0x80 + 4 + 20
        struct.pack_into("<H", d, opt, 0x9999)
        self._parse_raises(bytes(d), "magic")

    def test_truncated_before_optional_header_completes(self):
        self._parse_raises(pebuild.build_pe()[:0x120], "truncated")

    def test_truncated_mid_section_table(self):
        self._parse_raises(pebuild.build_pe()[:0x110], "truncated")

    def test_missing_file_is_a_pe_error(self):
        with self.assertRaises(re_pe.PEError) as cm:
            re_pe.PE("/nonexistent/definitely/not/here.dll")
        self.assertIn("cannot read", str(cm.exception))

    def test_directory_past_the_optional_header_is_zero_not_a_crash(self):
        # NumberOfRvaAndSizes is attacker-controlled; a directory index past
        # the declared optional header must read as absent, not read past it.
        with _TmpPE(pebuild.build_pe(exports=(("A", 0),))) as pe:
            exp_rva, exp_size = pe.directory(0)
            self.assertNotEqual(exp_rva, 0)
            self.assertEqual(pe.section_of_va(pe.image_base + exp_rva), ".rdata")
            self.assertEqual(pe.directory(1), (0, 0))
            self.assertEqual(pe.directory(99), (0, 0))


class TestHexdump(unittest.TestCase):
    def test_hexdump_reports_va_per_line(self):
        with _TmpPE(pebuild.build_pe()) as pe:
            off = pe.va_to_offset(pe.image_base + 0x1000)
            text = pe.hexdump(off, 16)
        self.assertIn(f"{pe.image_base + 0x1000:08x}", text)
        self.assertIn("55 48 89 e5", text)

    def test_dump_running_past_mapped_data_does_not_crash(self):
        """
        A file may carry an overlay: bytes past the last section that no
        section maps. offset_to_va returns None there, which must render as a
        placeholder rather than raise on a format spec.
        """
        blob = pebuild.build_pe(trailing=b"\xde\xad\xbe\xef" * 64)
        with _TmpPE(blob) as pe:
            off = pe.va_to_offset(pe.image_base + 0x2000)
            text = pe.hexdump(off, 0x400)
        self.assertIn("--------", text)
        self.assertIn("de ad be ef", text)

    def test_dump_is_clamped_to_the_file_length(self):
        with _TmpPE(pebuild.build_pe()) as pe:
            off = pe.va_to_offset(pe.image_base + 0x1000)
            huge = pe.hexdump(off, 1 << 20)
        self.assertGreater(len(huge.splitlines()), 0)


class TestCliArgParsing(unittest.TestCase):
    """Bad --where/--data must be a usage error, not a ValueError traceback."""

    def _run(self, argv):
        from re_pe import _int_arg, _data_arg
        ap_int = _int_arg
        if argv[0] == "--data":
            return _data_arg(argv[1])
        return ap_int(argv[1])

    def test_where_accepts_hex_and_decimal(self):
        self.assertEqual(self._run(["--where", "0x40b680"]), 0x40B680)
        self.assertEqual(self._run(["--where", "4237952"]), 4237952)

    def test_where_rejects_garbage(self):
        import argparse
        with self.assertRaises(argparse.ArgumentTypeError):
            self._run(["--where", "0xZZZ"])

    def test_data_requires_the_length_part(self):
        import argparse
        with self.assertRaises(argparse.ArgumentTypeError):
            self._run(["--data", "0x5a1a6c"])

    def test_data_parses_va_and_length(self):
        self.assertEqual(self._run(["--data", "0x5a1a6c:64"]), (0x5A1A6C, 64))

    def test_data_rejects_negative_length(self):
        import argparse
        with self.assertRaises(argparse.ArgumentTypeError):
            self._run(["--data", "0x5a1a6c:-1"])


if __name__ == "__main__":
    unittest.main()