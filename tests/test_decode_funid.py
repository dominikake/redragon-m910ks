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


class TestMediaAndMacro(unittest.TestCase):
    def test_media(self):
        self.assertEqual(df.decode_funid(0x21)["action"], "Media Player")
        self.assertEqual(df.decode_funid(0x22)["action"], "Play/Pause")
        self.assertEqual(df.decode_funid(0x28)["action"], "Mute")

    def test_macro_buttons(self):
        self.assertEqual(df.decode_funid(0xA8)["action"], "Macro button (K6)")


class TestDefault(unittest.TestCase):
    def test_unknown_falls_to_default(self):
        row = df.decode_funid(0x99)
        self.assertTrue(row["default"])
        self.assertEqual(row["case"], 15)


if __name__ == "__main__":
    unittest.main()
