"""
Tests for tools/decode_general_block.py.

The decode is only as good as the offsets it uses, so the fixture here is the
general block from a real dongle reply (`captures/vendor-0x21-dongle.bin`,
byte-identical to reads taken eight days apart). The synthetic cases exist to
exercise the branches the real blob happens to leave alone: the Y-axis DPI
table and the packed-level cursor.

    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))

import decode_general_block as dgb                          # noqa: E402

# blobs[8..0x99] from captures/vendor-0x21-dongle.bin, verbatim.
REAL_GENERAL = bytes.fromhex(
    "64130425000200040008000c0010000000000000000000000000000000000000"
    "0000000000ff00000000ff00ff00ff00ffffff0000ffffffffffff4600014201"
    "40ff00004207ff000000ff000000ffff00ffffff00ff800000ffff024240ff00"
    "0000ff000000ffff00ffffff00ffff0000000000000000000000000042ff0000"
    "00ff00424202ff000000000102ff0000a500"
)


def make_blob(general: bytes = REAL_GENERAL) -> bytes:
    assert len(general) == dgb.GENERAL_LEN, len(general)
    head = bytes([dgb.REPORT_ID, 0x21, 0, 0, 0, 0, 0, 0])
    blob = head + general
    return blob + bytes(dgb.BLOB_LEN - len(blob))


class TestRealBlob(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = dgb.decode_general(make_blob())

    def test_report_rate(self):
        self.assertEqual(self.d["report_rate_code"], 4)
        self.assertEqual(self.d["report_rate_hz"], 1000)

    def test_levels_and_active(self):
        self.assertEqual(self.d["levels_enabled"], 5)
        self.assertEqual(self.d["active_level"], 2)

    def test_dpi_ladder(self):
        self.assertEqual(self.d["dpi_x"], [500, 1000, 2000, 3000, 4000])

    def test_no_second_axis(self):
        self.assertFalse(self.d["dual_dpi_axis"])
        self.assertIsNone(self.d["dpi_y"])

    def test_level_colours(self):
        self.assertEqual(self.d["level_colours"], [
            (255, 0, 0), (0, 0, 255), (0, 255, 0),
            (255, 0, 255), (255, 255, 0),
        ])

    def test_terminator_and_constant(self):
        self.assertEqual(self.d["constant_100"], 100)
        self.assertEqual(self.d["terminator"], 0x00A5)
        self.assertEqual(self.d["echoed"]["0x91"], 0x00)

    def test_led_mode_colours(self):
        modes = {m["mode"]: m for m in self.d["led_modes"]}
        self.assertEqual(modes[2]["colours"], [(255, 0, 0)])
        self.assertEqual(len(modes[3]["colours"]), 7)
        self.assertEqual(modes[3]["colours"][-1], (0, 255, 255))
        self.assertEqual(modes[6]["colours"][:2],
                         [(255, 0, 0), (0, 255, 0)])
        self.assertEqual(modes[7]["colours"],
                         [(255, 0, 0), (0, 255, 0)])
        self.assertEqual(modes[1]["colours"], [])

    def test_mode_nibbles(self):
        modes = {m["mode"]: m for m in self.d["led_modes"]}
        self.assertEqual((modes[1]["light"], modes[1]["speed"]), (4, 2))
        self.assertTrue(modes[1]["random_is_3"])
        self.assertEqual((modes[2]["light"], modes[2]["speed"]), (4, 0))
        self.assertEqual((modes[10]["light"], modes[10]["speed"]), (0, 2))


class TestPacking(unittest.TestCase):
    def _blank(self) -> bytearray:
        g = bytearray(dgb.GENERAL_LEN)
        g[0x00] = 0x64
        g[0x90] = 0xA5
        return g

    def test_levels_are_packed_not_slotted(self):
        """Disabled levels do not consume a DPI slot."""
        g = self._blank()
        g[0x03] = 0x31                    # 1 enabled, active #1
        g[0x02] = 0x04
        g[0x05:0x07] = (0x0C).to_bytes(2, "little")
        d = dgb.decode_general(make_blob(bytes(g)))
        self.assertEqual(d["levels_enabled"], 1)
        self.assertEqual(d["dpi_x"], [3000])

    def test_second_axis(self):
        g = self._blank()
        g[0x02] = 0x84                    # 1000 Hz + Y axis present
        g[0x03] = 0x22                    # 2 enabled, active #2
        g[0x05:0x09] = b"\x02\x00\x04\x00"
        g[0x15:0x19] = b"\x08\x00\x10\x00"
        d = dgb.decode_general(make_blob(bytes(g)))
        self.assertTrue(d["dual_dpi_axis"])
        self.assertEqual(d["dpi_x"], [500, 1000])
        self.assertEqual(d["dpi_y"], [2000, 4000])

    def test_mode3_count_is_clamped_to_its_field(self):
        """Case 3 stores a count but only has room for seven triples."""
        g = self._blank()
        g[0x45] = 8
        d = dgb.decode_general(make_blob(bytes(g)))
        modes = {m["mode"]: m for m in d["led_modes"]}
        self.assertEqual(len(modes[3]["colours"]), 7)

    def test_unknown_rate_code(self):
        g = self._blank()
        g[0x02] = 0x07
        d = dgb.decode_general(make_blob(bytes(g)))
        self.assertIsNone(d["report_rate_hz"])
        self.assertEqual(d["report_rate_code"], 7)

    def test_rejects_wrong_shape(self):
        with self.assertRaises(ValueError):
            dgb.decode_general(b"\x08" * 100)
        bad = bytearray(make_blob())
        bad[0] = 0x09
        with self.assertRaises(ValueError):
            dgb.decode_general(bytes(bad))


class TestFormat(unittest.TestCase):
    def test_report_mentions_the_headline_fields(self):
        text = dgb.format_report(dgb.decode_general(make_blob()))
        self.assertIn("1000 Hz", text)
        self.assertIn("500 dpi", text)
        self.assertIn("0x00a5", text)


if __name__ == "__main__":
    unittest.main()
