"""Catch the damage a shell heredoc does to a backslash on its way into a regex.

Two failure modes, both invisible at a glance:

  `\\b` becomes a literal backspace (0x08). The regex still compiles and silently never
  matches, so nothing fails and the rule is simply dead. Found by looking at the bytes.

  `\\n` becomes a real newline, which ends the string literal it was in. That one *is* a
  SyntaxError, but only in the file it happened to, and if that file is imported lazily
  the test suite reports it as a confusing failure somewhere else. Found by parsing.

Run this after any edit that touches a pattern. Fifth and sixth occurrence in this
project; the standing instruction is to use the editor tools for regexes, not a heredoc.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ALLOWED = {0x09, 0x0A, 0x0D}       # tab, newline, carriage return
NAMES = {0x07: "\\a bell", 0x08: "\\b backspace", 0x0B: "\\v vertical tab",
         0x0C: "\\f form feed", 0x1B: "\\e escape", 0x00: "NUL"}

bad = 0
checked = 0
for path in sorted(ROOT.rglob("*.py")):
    if "data" in path.parts or ".git" in path.parts:
        continue
    raw = path.read_bytes()
    checked += 1
    for lineno, line in enumerate(raw.split(b"\n"), start=1):
        for byte in set(line):
            if byte < 0x20 and byte not in ALLOWED:
                print(str(path.relative_to(ROOT)) + ":" + str(lineno)
                      + "  contains " + NAMES.get(byte, hex(byte)))
                print("    " + repr(line[:160]))
                bad += 1
                break
    # A collapsed \n leaves a string literal open. Parsing is the only way to see it, and
    # it is cheap: every file in this tree together is a fraction of a second.
    try:
        ast.parse(raw.decode("utf-8", "replace"), filename=str(path))
    except SyntaxError as exc:
        print(str(path.relative_to(ROOT)) + ":" + str(exc.lineno or 0)
              + "  does not parse: " + str(exc.msg))
        print("    " + repr((exc.text or "")[:160]))
        bad += 1

print()
if bad:
    print("FOUND " + str(bad) + " problem(s) in " + str(checked) + " files")
    sys.exit(1)
print("no collapsed escapes and no syntax errors in " + str(checked) + " source files")
