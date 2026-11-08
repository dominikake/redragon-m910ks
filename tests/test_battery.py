"""
Tests for the battery reader, its charging semantics, and the bar renderer.

The 0x90 reply layout and the meaning of byte 2 are not guesses: the vendor
app's ReadPower at OemDrv.exe 0x40a590 writes 1 into `nUsbConnect` when byte 2
is 0x10, 0 into it when byte 2 is 0x11, and returns failure for anything else,
while byte 3 is copied into `nPower` in both branches. The fixtures below are
the real captures taken with the cable in and out.

    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))

import battery                                              # noqa: E402
import history                                              # noqa: E402
import omarchy_bar_module as bar                            # noqa: E402

# Captured live while the cable was attached: wired node, 1% and charging.
WIRED_CHARGING = bytes.fromhex("0590100100000000")
# Wired node before the gauge reports: link is USB, level still 0x00.
WIRED_PENDING = bytes.fromhex("0590100000000000")
# Dongle with a live wireless mouse at 87%.
WIRELESS_OK = bytes.fromhex("0590115700000000")
# Dongle while the mouse sleeps / is out of range.
WIRELESS_ASLEEP = bytes.fromhex("0590110000000000")


class TestParse(unittest.TestCase):
    def test_wireless_reading(self):
        info = battery.parse(WIRELESS_OK, "dongle")
        self.assertTrue(info["ok"])
        self.assertEqual(info["percent"], 87)
        self.assertEqual(info["state"], "ok")
        self.assertFalse(info["charging"])
        self.assertEqual(info["source"], "dongle")
        self.assertEqual(info["link"], "wireless (2.4GHz)")

    def test_wireless_zero_is_asleep_not_zero_percent(self):
        info = battery.parse(WIRELESS_ASLEEP)
        self.assertEqual(info["state"], "asleep")
        self.assertIsNone(info["percent"])
        self.assertFalse(info["charging"])

    def test_wired_reading_is_charging(self):
        info = battery.parse(WIRED_CHARGING, "wired")
        self.assertTrue(info["ok"])
        self.assertEqual(info["percent"], 1)
        self.assertEqual(info["state"], "ok")
        self.assertTrue(info["charging"])
        self.assertEqual(info["link"], "wired (USB)")

    def test_wired_zero_is_pending_not_asleep(self):
        info = battery.parse(WIRED_PENDING, "wired")
        self.assertEqual(info["state"], "pending")
        self.assertIsNone(info["percent"])
        self.assertTrue(info["charging"])

    def test_unknown_link_matches_vendor_failure(self):
        info = battery.parse(bytes.fromhex("0590120500000000"))
        self.assertFalse(info["ok"])
        self.assertEqual(info["state"], "unknown-link")
        self.assertIsNone(info["charging"])

    def test_no_reply(self):
        info = battery.parse(None)
        self.assertFalse(info["ok"])
        self.assertEqual(info["state"], "no-reply")
        self.assertIsNone(info["charging"])


class TestReadBattery(unittest.TestCase):
    def test_wired_wins_over_dongle(self):
        with mock.patch.object(battery, "find_wired_vendor_node",
                               return_value="/dev/hidraw3"), \
             mock.patch.object(battery, "find_dongle_vendor_node",
                               return_value="/dev/hidraw1"), \
             mock.patch.object(battery, "query_node",
                               return_value=battery.parse(WIRED_CHARGING,
                                                          "wired")) as q:
            info = battery.read_battery()
        self.assertTrue(info["charging"])
        self.assertEqual(info["percent"], 1)
        q.assert_called_once_with("/dev/hidraw3", "wired")

    def test_wired_present_but_silent_still_charging(self):
        silent = {"ok": False, "percent": None, "state": "no-reply",
                  "charging": None, "source": "wired", "raw": ""}
        with mock.patch.object(battery, "find_wired_vendor_node",
                               return_value="/dev/hidraw3"), \
             mock.patch.object(battery, "find_dongle_vendor_node",
                               return_value="/dev/hidraw1"), \
             mock.patch.object(battery, "query_node", return_value=silent):
            info = battery.read_battery()
        self.assertTrue(info["charging"])
        self.assertEqual(info["state"], "pending")
        self.assertIsNone(info["percent"])

    def test_dongle_used_when_no_cable(self):
        with mock.patch.object(battery, "find_wired_vendor_node",
                               return_value=None), \
             mock.patch.object(battery, "find_dongle_vendor_node",
                               return_value="/dev/hidraw1"), \
             mock.patch.object(battery, "query_node",
                               return_value=battery.parse(WIRELESS_OK,
                                                          "dongle")) as q:
            info = battery.read_battery()
        self.assertFalse(info["charging"])
        self.assertEqual(info["percent"], 87)
        q.assert_called_once_with("/dev/hidraw1", "dongle")

    def test_no_device(self):
        with mock.patch.object(battery, "find_wired_vendor_node",
                               return_value=None), \
             mock.patch.object(battery, "find_dongle_vendor_node",
                               return_value=None):
            info = battery.read_battery()
        self.assertEqual(info["state"], "no-device")


class TestMerge(unittest.TestCase):
    def test_live_charging_drops_stale_percent(self):
        cached = {"state": "ok", "percent": 41, "link": "wireless (2.4GHz)",
                  "age": 4 * 86400, "freshness": "flat", "charging": False}
        live = battery.parse(WIRED_PENDING, "wired")
        info = bar.merge(live, cached)
        self.assertTrue(info["charging"])
        self.assertIsNone(info["percent"])
        self.assertEqual(info["freshness"], "fresh")

    def test_live_asleep_keeps_last_known(self):
        cached = {"state": "ok", "percent": 41, "link": "wireless (2.4GHz)",
                  "age": 60, "freshness": "fresh", "charging": False}
        live = battery.parse(WIRELESS_ASLEEP, "dongle")
        info = bar.merge(live, cached)
        self.assertEqual(info["percent"], 41)
        self.assertFalse(info["charging"])
        self.assertEqual(info["freshness"], "fresh")

    def test_unplugging_clears_cached_charging(self):
        cached = {"state": "ok", "percent": 60, "link": "wired (USB)",
                  "age": 30, "freshness": "fresh", "charging": True}
        live = battery.parse(WIRELESS_ASLEEP, "dongle")
        info = bar.merge(live, cached)
        self.assertFalse(info["charging"])

    def test_live_percentage_wins(self):
        cached = {"state": "ok", "percent": 41, "link": "wireless (2.4GHz)",
                  "age": 900, "freshness": "stale", "charging": False}
        live = battery.parse(WIRELESS_OK, "dongle")
        info = bar.merge(live, cached)
        self.assertEqual(info["percent"], 87)
        self.assertEqual(info["freshness"], "fresh")


class TestRender(unittest.TestCase):
    def render(self, info):
        buf = io.StringIO()
        with redirect_stdout(buf):
            bar.render(info)
        return json.loads(buf.getvalue().strip())

    def test_charging_shows_percent(self):
        out = self.render({"state": "ok", "percent": 1, "link": "wired (USB)",
                           "age": None, "freshness": "fresh",
                           "charging": True})
        self.assertEqual(out["text"], "M+ 1%")
        self.assertEqual(out["class"], "charging")
        self.assertIn("charging over USB", out["tooltip"])

    def test_charging_without_level(self):
        out = self.render({"state": "pending", "percent": None,
                           "link": "wired (USB)", "age": None,
                           "freshness": "fresh", "charging": True})
        self.assertEqual(out["text"], "M+")
        self.assertEqual(out["class"], "charging")

    def test_charging_beats_flat(self):
        out = self.render({"state": "ok", "percent": 5, "link": "wired (USB)",
                           "age": 4 * 86400, "freshness": "flat",
                           "charging": True})
        self.assertEqual(out["text"], "M+ 5%")
        self.assertNotIn("flat", out["tooltip"])

    def test_flat_without_charging_unchanged(self):
        out = self.render({"state": "ok", "percent": 41,
                           "link": "wireless (2.4GHz)", "age": 4 * 86400,
                           "freshness": "flat", "charging": False})
        self.assertEqual(out["text"], "M!!")
        self.assertEqual(out["class"], "unavailable")

    def test_stale_unchanged(self):
        out = self.render({"state": "ok", "percent": 41,
                           "link": "wireless (2.4GHz)", "age": 3600,
                           "freshness": "stale", "charging": False})
        self.assertEqual(out["text"], "M?")
        self.assertEqual(out["class"], "unknown")

    def test_normal_reading_unchanged(self):
        out = self.render({"state": "ok", "percent": 87,
                           "link": "wireless (2.4GHz)", "age": None,
                           "freshness": "fresh", "charging": False})
        self.assertEqual(out["text"], "M 87%")
        self.assertEqual(out["class"], "ok")

    def test_charged_at_hundred(self):
        out = self.render({"state": "ok", "percent": 100,
                           "link": "wired (USB)", "age": None,
                           "freshness": "fresh", "charging": True})
        self.assertEqual(out["text"], "M+ 100%")
        self.assertIn("charged", out["tooltip"])

    def test_no_reading(self):
        out = self.render(None)
        self.assertEqual(out["text"], "M--")
        self.assertEqual(out["class"], "unavailable")


class TestHistoryCharging(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.patches = [
            mock.patch.object(history, "STATE_DIR", self.tmp.name),
            mock.patch.object(history, "HISTORY_FILE",
                             os.path.join(self.tmp.name, "history.jsonl")),
            mock.patch.object(history, "LAST_FILE",
                             os.path.join(self.tmp.name, "last.json")),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def test_charging_round_trip(self):
        history.record(1, "wired (USB)", "05901001", True)
        st = history.staleness()
        self.assertEqual(st["percent"], 1)
        self.assertTrue(st["charging"])
        self.assertEqual(st["status"], "fresh")

    def test_legacy_entry_without_charging(self):
        with open(history.LAST_FILE, "w") as fh:
            json.dump({"ts": history._now(), "percent": 41,
                       "link": "wireless (2.4GHz)"}, fh)
        st = history.staleness()
        self.assertEqual(st["percent"], 41)
        self.assertIsNone(st["charging"])

    def test_cached_charging_needs_the_cable(self):
        history.record(60, "wired (USB)", "0590103c", True)
        with mock.patch.object(bar, "wired_present", return_value=True):
            info = bar.read_cached()
        self.assertTrue(info["charging"])

        with mock.patch.object(bar, "wired_present", return_value=False):
            info = bar.read_cached()
        self.assertIsNone(info["charging"])
        self.assertEqual(info["percent"], 60)


class TestUpowerState(unittest.TestCase):
    def test_states(self):
        import upower_bridge as up
        self.assertEqual(up.upower_state({"percent": 41, "charging": True}),
                         up.STATE_CHARGING)
        self.assertEqual(up.upower_state({"percent": 100, "charging": True}),
                         up.STATE_FULLY_CHARGED)
        self.assertEqual(up.upower_state({"percent": 41, "charging": False}),
                         up.STATE_DISCHARGING)
        self.assertEqual(up.upower_state({"percent": None, "charging": None}),
                         up.STATE_UNKNOWN)
        self.assertEqual(up.upower_state({"percent": None, "charging": True}),
                         up.STATE_CHARGING)


if __name__ == "__main__":
    unittest.main()
