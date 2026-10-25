"""
Tests for tools/re_cmds.py, over a small committed objdump excerpt.

The regression that matters here is the address-discontinuity boundary: this
tool exists because objdump "loses instruction alignment in data regions near
0x40b000 and never recovers", and in such a region the recovered text contains
no genuine ret/int3 to stop on. A walk bounded only by those runs the whole
window through unrelated code and attributes every movb immediate it passes to
one call site.

    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))

import re_cmds                                              # noqa: E402

SEND = 0x409F80
GET = 0x40A150

# Fixtures below are copied from the shape `objdump -d` actually emits for
# this binary (tabs after the address and after the byte column, an explicit
# 0x on call targets, no symbol suffix, `(bad)` for undecodable bytes).

# A well-behaved call site: three movb immediates building the 5-byte struct,
# contiguous, then the call.
CLEAN = """\
  40a300:\t55                   \tpush   %ebp
  40a301:\t89 e5                \tmov    %esp,%ebp
  40a303:\tc6 44 24 18 01       \tmovb   $0x1,0x18(%esp)
  40a308:\tc6 44 24 19 21       \tmovb   $0x21,0x19(%esp)
  40a30d:\tc6 44 24 1a 00       \tmovb   $0x0,0x1a(%esp)
  40a312:\te8 69 fc ff ff       \tcall   0x409f80
  40a317:\tc9                   \tleave
  40a318:\tc3                   \tret
"""

# objdump has lost sync: an address repeats instead of advancing by the
# instruction's length. The movb at 0x40a3fe starts one byte past where the
# previous instruction ended, so the run before the gap is unreachable from
# the call and must not be attributed to it.
DISCONTINUOUS = """\
  40a3f0:\t55                   \tpush   %ebp
  40a3f1:\t89 e5                \tmov    %esp,%ebp
  40a3f3:\tc6 44 24 18 01       \tmovb   $0x1,0x18(%esp)
  40a3f8:\tc6 44 24 19 21       \tmovb   $0x21,0x19(%esp)
  40a3fe:\tc6 44 24 20 5b       \tmovb   $0x5b,0x20(%esp)
  40a403:\te8 78 fc ff ff       \tcall   0x409f80
  40a408:\te8 43 fa ff ff       \tcall   0x40a150
  40a40d:\tc9                   \tleave
  40a40e:\tc3                   \tret
"""

# objdump emitting garbage rather than instructions.
HAS_BAD = """\
  40a500:\t55                   \tpush   %ebp
  40a501:\t0f                   \t(bad)
  40a502:\tc6 44 24 18 07       \tmovb   $0x7,0x18(%esp)
  40a507:\te8 74 fc ff ff       \tcall   0x409f80
  40a50c:\tc9                   \tleave
  40a50d:\tc3                   \tret
"""

# A line objdump emitted with no byte column, so no length can be derived and
# it does not parse as an instruction at all. The surrounding addresses still
# jump, which the contiguity check catches.
NO_BYTES = """\
  40a600:\tpush   %ebp
  40a601:\tc6 44 24 18 03       \tmovb   $0x3,0x18(%esp)
  40a606:\tcall   0x409f80
"""

# objdump caps the byte column at 7 bytes and spills the rest onto a
# continuation line: an address and bytes, but no mnemonic. The movl here is 8
# bytes, so it is printed on two lines. Read the spill as its own instruction
# and the real one comes out 7 bytes long, the next address overshoots by one,
# and the walk stops on a gap that does not exist -- dropping the 0x90 movb
# that the command table depends on.
WRAPPED = """\
  40a5c0:\tc6 44 24 14 90       \tmovb   $0x90,0x14(%esp)
  40a5c5:\tc7 44 24 15 00 00 00 \tmovl   $0x0,0x15(%esp)
  40a5cc:\t00 
  40a5cd:\te8 ae f9 ff ff       \tcall   0x409f80
"""


def rows(text: str):
    fd, path = tempfile.mkstemp(suffix=".asm", text=True)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    try:
        return re_cmds.parse(path)
    finally:
        os.unlink(path)


class TestInsnLength(unittest.TestCase):
    def test_length_is_the_number_of_byte_pairs(self):
        self.assertEqual(re_cmds.insn_length("55 "), 1)
        self.assertEqual(re_cmds.insn_length("89 e5 "), 2)
        self.assertEqual(re_cmds.insn_length("e8 6b 0f 00 00 "), 5)

    def test_every_parsed_row_has_a_length(self):
        # INSN only matches a complete space-terminated byte group, so the
        # contiguity check never has to cope with an unknown length.
        for fixture in (CLEAN, DISCONTINUOUS, HAS_BAD, WRAPPED):
            for _addr, _op, _arg, n in rows(fixture):
                self.assertIsInstance(n, int)


class TestObjdumpContinuationRows(unittest.TestCase):
    def test_spill_line_is_folded_into_the_instruction_length(self):
        r = rows(WRAPPED)
        # Three real instructions, not four: the spill is not an instruction.
        self.assertEqual([a for a, _op, _arg, _n in r],
                         [0x40A5C0, 0x40A5C5, 0x40A5CD])
        self.assertEqual(r[1][3], 8)        # 7 bytes + the 1 that spilled
        self.assertEqual(r[1][1], "movl")   # still a movl, not "00"

    def test_a_wrapped_instruction_is_not_a_gap(self):
        hits = re_cmds.extract(rows(WRAPPED), SEND, GET)
        self.assertEqual(len(hits), 1)
        self.assertEqual([v for _, v in hits[0]["bytes"]], [0x90])
        self.assertNotIn("address gap", hits[0]["stop"])

    def test_spill_line_never_becomes_a_mnemonic(self):
        # Regression guard for the parse bug itself: a byte pair in the
        # mnemonic slot is what made the false gap possible.
        for _addr, op, _arg, _n in rows(WRAPPED):
            self.assertNotRegex(op, r"^[0-9a-f]{2}$")


class TestParse(unittest.TestCase):
    def test_captures_address_mnemonic_operands_and_length(self):
        r = rows(CLEAN)
        self.assertEqual(r[0][:4], (0x40A300, "push", "%ebp", 1))
        self.assertEqual(r[1][:4], (0x40A301, "mov", "%esp,%ebp", 2))
        self.assertEqual(r[4][:4], (0x40A30D, "movb", "$0x0,0x1a(%esp)", 5))
        self.assertEqual(r[5][:4], (0x40A312, "call", "0x409f80", 5))

    def test_byte_column_is_no_longer_part_of_the_mnemonic(self):
        # The old regex swallowed the bytes into group 2, so `op` was "c6".
        for _addr, op, arg, _n in rows(CLEAN):
            self.assertNotRegex(op, r"^[0-9a-f]{2}$")


class TestExtractContiguity(unittest.TestCase):
    def test_contiguous_run_collects_every_immediate(self):
        hits = re_cmds.extract(rows(CLEAN), SEND, GET)
        self.assertEqual(len(hits), 1)
        self.assertEqual([v for _, v in hits[0]["bytes"]], [0x01, 0x21, 0x00])
        self.assertEqual(hits[0]["fn"], "SendCmd")

    def test_address_discontinuity_stops_the_walk(self):
        """
        The run before the gap is unreachable from the call. Without a
        contiguity check a 60-instruction walk would sweep it up along with
        everything between it and the call, and attribute all of it to one
        command byte.
        """
        hits = re_cmds.extract(rows(DISCONTINUOUS), SEND, GET)
        by_call = {h["call"]: h for h in hits}

        send = by_call[0x40A403]
        self.assertEqual([v for _, v in send["bytes"]], [0x5B])
        # The immediates on the far side of the gap must be absent.
        self.assertNotIn(0x01, [v for _, v in send["bytes"]])
        self.assertNotIn(0x21, [v for _, v in send["bytes"]])
        self.assertIn("address gap", send["stop"])
        self.assertIn("0x0040a3f8", send["stop"])

    def test_bad_line_is_a_boundary(self):
        hits = re_cmds.extract(rows(HAS_BAD), SEND, GET)
        self.assertEqual(len(hits), 1)
        self.assertEqual([v for _, v in hits[0]["bytes"]], [0x07])
        self.assertIn("(bad)", hits[0]["stop"])

    def test_unparsed_line_leaves_an_address_jump(self):
        # The no-byte-column line does not parse, so the addresses either side
        # of it jump -- which is exactly the signal the check looks for.
        self.assertEqual(re_cmds.extract(rows(NO_BYTES), SEND, GET), [])

    def test_stop_reason_is_recorded_for_every_hit(self):
        hits = re_cmds.extract(rows(CLEAN), SEND, GET)
        self.assertTrue(all("stop" in h for h in hits))
        # Nothing between the movbs and the call stops the walk, so it runs
        # out of window.
        self.assertIn("window of", hits[0]["stop"])

    def test_a_ret_boundary_is_reported(self):
        rc = rows("""\
  40a700:\tc3                   \tret
  40a701:\tc6 44 24 18 06       \tmovb   $0x6,0x18(%esp)
  40a706:\te8 75 fc ff ff       \tcall   0x409f80
""")
        hits = re_cmds.extract(rc, SEND, GET)
        self.assertEqual([v for _, v in hits[0]["bytes"]], [0x06])
        self.assertIn("ret", hits[0]["stop"])

    def test_a_ret_boundary_yields_no_hit_when_nothing_follows_it(self):
        rc = rows("""\
  40a700:\tc6 44 24 18 04       \tmovb   $0x4,0x18(%esp)
  40a705:\tc3                   \tret
  40a706:\te8 75 fc ff ff       \tcall   0x409f80
""")
        self.assertEqual(re_cmds.extract(rc, SEND, GET), [])

    def test_default_window_is_deep_enough_for_every_call_site(self):
        # 14 looked sufficient because the short query routines fit, but
        # GetCmd at 0x40a727 and 0x40a7fb build a larger frame first. At 14
        # a bare run reports 3 of the 6 real call sites; the docs quote all
        # six, so the default has to reach them.
        self.assertEqual(re_cmds.DEFAULT_WINDOW, 60)

    def test_a_deep_call_site_survives_the_default_window(self):
        # A function that builds its argument struct well before the call:
        # the movb is 20 instructions back, past a window of 14.
        nops = "".join(f"  {i:04x}:\t90                   \tnop\n"
                       for i in range(0x40A714, 0x40A728))
        text = ("  40a70f:\tc6 44 24 18 30       \tmovb   $0x30,0x18(%esp)\n"
                + nops
                + "  40a728:\te8 53 f8 ff ff       \tcall   0x409f80\n")
        hits = re_cmds.extract(rows(text), SEND, GET)
        self.assertEqual(len(hits), 1)
        self.assertEqual([v for _, v in hits[0]["bytes"]], [0x30])
        self.assertIn("window of", hits[0]["stop"])


class TestWindowing(unittest.TestCase):
    def test_narrow_window_truncates_the_attributed_run(self):
        hits = re_cmds.extract(rows(CLEAN), SEND, GET, window=1)
        self.assertEqual([v for _, v in hits[0]["bytes"]], [0x00])

    def test_window_larger_than_the_function_is_harmless(self):
        hits = re_cmds.extract(rows(CLEAN), SEND, GET, window=500)
        self.assertEqual([v for _, v in hits[0]["bytes"]], [0x01, 0x21, 0x00])

    def test_other_call_targets_are_ignored(self):
        self.assertEqual(re_cmds.extract(rows(CLEAN), 0xDEAD, 0xBEEF), [])


if __name__ == "__main__":
    unittest.main()