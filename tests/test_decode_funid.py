"""
Tests for tools/decode_funid.py.

#8 was a static-analysis issue: the FunID -> action mapping had to come from
the dispatch at `0x40b010` and the context-menu label lookup at `0x43b9b8`,
because the live confirmation never happened (physical buttons do not reach
the host in this mouse model).

    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))

import decode_funid as df                              # noqa: E402


class TestButtonActions(unittest.TestCase):
    def test_left(self):
        row = df.decode_funid(0x11)
        self.assertEqual(row["action"], "Left button")
        self.assertEqual(row["category"], "mouse")
        self.assertEqual(row["case"], 1)
        self.assertEqual(row["encoded"], 0x01)
        self.assertEqual(row["size"], 6)

    def test_middle(self):
        row = df.decode_funid(0x12)
        self.assertEqual(row["action"], "Middle button")
        self.assertEqual(row["encoded"], 0x04)
        self.assertEqual(row["size"], 6)

    def test_right(self):
        row = df.decode_funid(0x13)
        self.assertEqual(row["action"], "Right button")
        self.assertIsNone(row["case"])
        self.assertIsNone(row["encoded"])

    def test_builder_special_cases(self):
        # case table at 0x40b284
        cases = {
            0x10: ("Right button", 0, 0x02, 6),
            0xa0: ("Right button", 0, 0x02, 6),
            0xa1: ("Right button", 0, 0x02, 6),
            0xa2: ("Left button", 1, 0x01, 6),
            0xa3: ("Left button", 1, 0x01, 6),
            0xa4: ("Middle button", 2, 0x04, 6),
            0xa5: ("Middle button", 2, 0x04, 6),
            0x5b: ("Forward", 3, 0x08, 6),
            0x5c: ("Forward", 3, 0x08, 6),
        }
        for funid, (action, case, encoded, size) in cases.items():
            row = df.decode_funid(funid)
            self.assertEqual(row["action"], action, hex(funid))
            self.assertEqual(row["case"], case, hex(funid))
            self.assertEqual(row["encoded"], encoded, hex(funid))
            self.assertEqual(row["size"], size, hex(funid))
            self.assertFalse(row["default"], hex(funid))


class TestHardwareFamily(unittest.TestCase):
    def test_buttons(self):
        cases = {
            0xF0: ("Left button", 0x01, 1),
            0xF1: ("Right button", 0x02, 1),
            0xF2: ("Middle button", 0x04, 1),
            0xF3: ("Forward", 0x08, 1),
            0xF4: ("Back", 0x10, 1),
        }
        for funid, (action, encoded, size) in cases.items():
            row = df.decode_funid(funid)
            self.assertEqual(row["action"], action, hex(funid))
            self.assertEqual(row["encoded"], encoded, hex(funid))
            self.assertEqual(row["size"], size, hex(funid))
            self.assertFalse(row["default"])

    def test_scroll_and_events(self):
        self.assertEqual(df.decode_funid(0xF5)["action"], "Scroll Up")
        self.assertEqual(df.decode_funid(0xF6)["action"], "Scroll Down")
        self.assertEqual(df.decode_funid(0xF7)["action"], "Key Down")
        self.assertEqual(df.decode_funid(0xF8)["action"], "Key Up")
        self.assertEqual(df.decode_funid(0xF9)["action"], "Delay")
        self.assertEqual(df.decode_funid(0xFA)["action"], "Delay")

    def test_hardware_encoded_is_lookup(self):
        for funid in range(0xF5, 0xFB):
            row = df.decode_funid(funid)
            self.assertIsNone(row["encoded"], hex(funid))


class TestMediaAndMacro(unittest.TestCase):
    def test_media(self):
        self.assertEqual(df.decode_funid(0x21)["action"], "Media Player")
        self.assertEqual(df.decode_funid(0x22)["action"], "Play/Pause")
        self.assertEqual(df.decode_funid(0x28)["action"], "Mute")

    def test_macro_buttons(self):
        cases = {
            0xA8: "Macro button (K6)",
            0xA9: "Macro button (K7)",
            0xAC: "Macro button (K10)",
            0xAE: "Macro button (K8)",
        }
        for funid, action in cases.items():
            self.assertEqual(df.decode_funid(funid)["action"], action, hex(funid))

    def test_web_range(self):
        expected = ["Favorites", "Calculator", "Explorer", "Search", "Home",
                    "Email", "Web Forward", "Web Stop", "Web Refresh",
                    "Web Favorites"]
        for i, name in enumerate(expected):
            row = df.decode_funid(0x30 + i)
            self.assertEqual(row["action"], name, hex(0x30 + i))
            self.assertEqual(row["category"], "web", hex(0x30 + i))
            self.assertFalse(row["default"], hex(0x30 + i))


class TestDefault(unittest.TestCase):
    def test_unknown_falls_to_default(self):
        row = df.decode_funid(0x99)
        self.assertTrue(row["default"])
        self.assertEqual(row["case"], 15)

    def test_every_documented_special_is_non_default(self):
        specials = ([0x10, 0x11, 0x12] + list(range(0x13, 0x19))
                    + list(range(0x21, 0x29)) + list(range(0x30, 0x3A))
                    + [0x5b, 0x5c] + [0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5]
                    + [0xa8, 0xa9, 0xac, 0xae] + list(range(0xF0, 0xFB)))
        for funid in specials:
            row = df.decode_funid(funid)
            self.assertFalse(row["default"], hex(funid))


if __name__ == "__main__":
    unittest.main()
