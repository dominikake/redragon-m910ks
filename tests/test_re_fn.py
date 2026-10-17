"""
Tests for tools/re_fn.py, over a small committed objdump excerpt.

    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))

import re_fn                                                # noqa: E402


def write_disasm(text: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".asm", text=True)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    return path


# A function containing TWO separate int3 gaps and no ret between them.
# `pad` has to be cleared by a real instruction: left cumulative, the four
# int3s of the second gap push it past the limit and the dump stops -- which
# is exactly when it matters most, because inter-block padding is CC CC CC
# and two gaps inside one function is routine.
TWO_INT3_GAPS = """\
Disassembly of section .text:

000000000040b010 <_main>:
  40b010:\t55                   \tpush   %rbp
  40b011:\t48 89 e5             \tmov    %rsp,%rbp
  40b014:\te8 6b 0f 00 00       \tcall   409f80 <_SendCmd>
  40b019:\t8b 45 08             \tmov    0x8(%rbp),%eax
  40b01c:\tcc cc cc             \tint3
  40b01f:\tcc cc cc             \tint3
  40b022:\tcc cc cc             \tint3
  40b025:\t55                   \tpush   %rbp
  40b026:\t48 89 e5             \tmov    %rsp,%rbp
  40b029:\t90                   \tnop
  40b02a:\tcc cc cc             \tint3
  40b02d:\tcc cc cc             \tint3
  40b030:\tcc cc cc             \tint3
  40b033:\te8 d8 fe ff ff       \tcall   40a150 <_GetCmd>
  40b038:\tc9                   \tleave
  40b039:\tc3                   \tret
"""

# A single run of four int3s, which is a real end-of-function marker.
ONE_INT3_GAP = """\
  40b010:\t55                   \tpush   %rbp
  40b011:\t48 89 e5             \tmov    %rsp,%rbp
  40b014:\tc3                   \tret
  40b015:\tcc cc cc             \tint3
  40b018:\tcc cc cc             \tint3
  40b01b:\tcc cc cc             \tint3
  40b01e:\tcc                   \tint3
  40b01f:\t90                   \tnop
  40b020:\t55                   \tpush   %rbp
"""

NOT_A_DISASSEMBLY = """\
some grep output that is not objdump at all
no instructions here
"""


class TestParse(unittest.TestCase):
    def test_parses_address_mnemonic_and_operands(self):
        path = write_disasm(TWO_INT3_GAPS)
        try:
            rows = re_fn.parse(path)
        finally:
            os.unlink(path)
        self.assertEqual(rows[0][0], 0x40B010)
        self.assertEqual(rows[0][1], "push")
        self.assertEqual(rows[0][2], "%rbp")

    def test_non_disassembly_yields_no_rows(self):
        path = write_disasm(NOT_A_DISASSEMBLY)
        try:
            self.assertEqual(re_fn.parse(path), [])
        finally:
            os.unlink(path)


class TestMissingAddress(unittest.TestCase):
    """A3: an empty parse must not reach min() on an empty sequence."""

    def _run(self, text, va="0x40b010"):
        path = write_disasm(text)
        old_argv, old_err = sys.argv, sys.stderr
        import io
        buf = io.StringIO()
        try:
            sys.argv = ["re_fn.py", path, va]
            sys.stderr = buf
            rc = re_fn.main()
        finally:
            sys.argv, sys.stderr = old_argv, old_err
            os.unlink(path)
        return rc, buf.getvalue()

    def test_empty_input_reports_no_instructions_parsed(self):
        rc, err = self._run(NOT_A_DISASSEMBLY)
        self.assertEqual(rc, 1)
        self.assertIn("no instructions parsed", err)

    def test_address_absent_reports_nearest(self):
        rc, err = self._run(TWO_INT3_GAPS, va="0x40b999")
        self.assertEqual(rc, 1)
        self.assertIn("not found", err)
        self.assertIn("nearest", err)


class TestInt3PaddingCounter(unittest.TestCase):
    """A2: `pad` must count a consecutive run, not a cumulative total."""

    def _dump(self, text, va="0x40b010", extra=()):
        import io
        path = write_disasm(text)
        old_argv, old_out = sys.argv, sys.stdout
        buf = io.StringIO()
        try:
            sys.argv = ["re_fn.py", path, va, *extra]
            sys.stdout = buf
            rc = re_fn.main()
        finally:
            sys.argv, sys.stdout = old_argv, old_out
            os.unlink(path)
        return rc, buf.getvalue()

    def test_second_gap_does_not_truncate_the_dump(self):
        rc, out = self._dump(TWO_INT3_GAPS, va="0x40b010", extra=("--count", "60"))
        self.assertEqual(rc, 0)
        flat = out.replace(" ", "").replace("\t", "")
        # The call after the *second* gap must survive. If pad were cumulative
        # the four int3s there would trip it and the dump would stop early.
        self.assertIn("40b033", flat)
        self.assertIn("40b039", flat)

    def test_first_gap_still_stops_the_dump(self):
        rc, out = self._dump(ONE_INT3_GAP, va="0x40b010", extra=("--count", "60"))
        self.assertEqual(rc, 0)
        self.assertNotIn("40b020", out.replace(" ", "").replace("\t", ""))

    def test_keep_int3_disables_the_gap_stop(self):
        rc, out = self._dump(ONE_INT3_GAP, va="0x40b010",
                             extra=("--count", "60", "--keep-int3"))
        self.assertEqual(rc, 0)
        self.assertIn("40b020", out.replace(" ", "").replace("\t", ""))


class TestUsageDocstringMatchesArgparse(unittest.TestCase):
    """A1: every flag in the documented usage line must actually parse."""

    @staticmethod
    def _usage_flags() -> list[tuple[str, list[str]]]:
        """[(flag, extra argv)] for each optional in the usage line.

        `[--count N]` takes a value, `[--calls]` does not -- so parse the
        bracket contents rather than assuming.
        """
        import re
        doc = re_fn.__doc__
        usage_line = [ln for ln in doc.splitlines() if "re_fn.py" in ln][-1]
        out = []
        for group in re.findall(r"\[--[a-z0-9-]+[^\]]*\]", usage_line):
            toks = group[1:-1].split()
            # `[--count N]` is a placeholder, not a literal value.
            extra = ["5" if re.fullmatch(r"[A-Z][A-Z0-9_]*", t) else t
                     for t in toks[1:]]
            out.append((toks[0], extra))
        return out

    def _accepts(self, flag: str, extra: list[str]) -> tuple[bool, str]:
        """Run main() with `flag` and report whether argparse accepted it."""
        import io
        path = write_disasm(TWO_INT3_GAPS)
        old_argv, old_out, old_err = sys.argv, sys.stdout, sys.stderr
        buf, err = io.StringIO(), io.StringIO()
        try:
            sys.argv = ["re_fn.py", path, "0x40b010", flag, *extra]
            sys.stdout, sys.stderr = buf, err
            try:
                re_fn.main()
            except SystemExit as exc:
                return exc.code in (0, None), err.getvalue()
            return True, ""
        finally:
            sys.argv, sys.stdout, sys.stderr = old_argv, old_out, old_err
            os.unlink(path)

    def test_documented_flags_all_parse(self):
        flags = self._usage_flags()
        self.assertTrue(flags, "no flags found in the usage line")
        for flag, extra in flags:
            with self.subTest(flag=flag):
                ok, err = self._accepts(flag, extra)
                self.assertTrue(ok, f"{flag} documented but rejected: {err}")

    def test_the_old_stale_flag_is_not_documented(self):
        # --no-int3 was the name the docstring used; argparse registers
        # --keep-int3. Documenting the wrong one made the tool unusable.
        self.assertNotIn("--no-int3", re_fn.__doc__)
        self.assertIn("--keep-int3", re_fn.__doc__)

    def test_stale_flag_really_is_rejected(self):
        # Guards the other direction: the test above must not pass merely
        # because nothing is documented.
        ok, err = self._accepts("--no-int3", [])
        self.assertFalse(ok)
        self.assertIn("unrecognized", err)


if __name__ == "__main__":
    unittest.main()