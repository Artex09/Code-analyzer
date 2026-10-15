"""Every regex in every language spec must compile, and mean roughly what it says.

This exists because a collapsed backslash turned `(^|\\\\)Request$` into `(^|\\)Request$`,
an unterminated group, which made the whole PHP analysis fail silently - `ok: False` with a
PatternError nobody was looking at. A spec is data, and data gets validated.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from repoxray import rules                                   # noqa: E402
from repoxray.analysis import actions, langs                 # noqa: E402
from repoxray.analysis.model import PAYLOAD_VALUES, VALUE_KINDS  # noqa: E402

problems: list = []


CONTROL_CHARS = "".join(chr(c) for c in list(range(0, 9)) + list(range(11, 32)))


def check(pattern: str, where: str) -> None:
    # A control character in a pattern means an escape sequence was eaten somewhere between
    # the editor and the file: `\b` became 0x08. It compiles, it never matches, and nothing
    # else notices. Five rules were dead this way, including three path terminators.
    for ch in pattern:
        if ch in CONTROL_CHARS:
            problems.append(where + ": literal control byte 0x%02x in the pattern - an "
                            "escape was collapsed  <<%s>>" % (ord(ch), repr(pattern[:60])))
            return
    try:
        re.compile(pattern)
    except re.error as exc:
        problems.append(where + ": " + str(exc) + "  <<" + pattern[:70] + ">>")
        return
    # A pattern that matches the empty string will match every parameter with no declared
    # type, which is how a never-list quietly becomes "never anything".
    if re.compile(pattern).match(""):
        problems.append(where + ": matches the empty string  <<" + pattern[:70] + ">>")


def main() -> int:
    seen_specs = set()
    for lang, spec in langs.SPECS.items():
        if id(spec) in seen_specs:
            continue
        seen_specs.add(id(spec))
        tag = "[" + spec.lang + "]"
        for src in spec.sources:
            check(src.pattern, tag + " source " + src.id)
            if src.value not in VALUE_KINDS:
                problems.append(tag + " source " + src.id + ": unknown value kind "
                                + src.value)
        for sink in spec.sinks:
            check(sink.pattern, tag + " sink " + sink.id)
            if sink.cat not in rules.CATEGORIES:
                problems.append(tag + " sink " + sink.id + ": category " + sink.cat
                                + " is not in rules.CATEGORIES")
            if sink.roles and not sink.danger_roles:
                problems.append(tag + " sink " + sink.id + ": roles given but no "
                                "danger_roles, so nothing is reportable")
            for role in sink.danger_roles:
                if sink.roles and role not in sink.roles:
                    problems.append(tag + " sink " + sink.id + ": danger role " + role
                                    + " is not one of its roles")
            if sink.shell == "conditional" and not sink.shell_kwarg:
                problems.append(tag + " sink " + sink.id + ": conditional shell with no "
                                "flag to read")
            if sink.shell not in ("never", "always", "argv", "conditional"):
                problems.append(tag + " sink " + sink.id + ": unknown shell mode "
                                + sink.shell)
        for san in spec.sanitizers:
            check(san.pattern, tag + " sanitizer " + san.id)
            if san.partial and not san.removes:
                problems.append(tag + " sanitizer " + san.id + ": partial but does not say "
                                "what it removes")
            if san.removes and not san.partial:
                problems.append(tag + " sanitizer " + san.id + ": lists removals but is "
                                "not marked partial")
        for prop in spec.propagators:
            check(prop.pattern, tag + " propagator " + prop.id)
        for guard in spec.guards:
            check(guard.pattern, tag + " guard " + guard.id)
            if guard.literal:
                check(guard.literal, tag + " guard literal " + guard.id)
        for barrier in spec.barriers:
            check(barrier.pattern, tag + " barrier " + barrier.id)
        for ps in spec.param_sources:
            if ps.type_pattern:
                check(ps.type_pattern, tag + " param source type " + ps.id)
            if ps.name_pattern:
                check(ps.name_pattern, tag + " param source name " + ps.id)
            if not ps.type_pattern and not ps.name_pattern:
                problems.append(tag + " param source " + ps.id + ": matches nothing")
            if ps.value not in VALUE_KINDS:
                problems.append(tag + " param source " + ps.id + ": unknown value kind")
        for pattern in spec.never_params:
            check(pattern, tag + " never_params")
        for pattern in spec.handler_registrars:
            check(pattern, tag + " handler_registrars")
        for pattern in spec.shells:
            check(pattern, tag + " shells")
        for pattern in spec.exports:
            check(pattern, tag + " exports")
        for pattern in spec.bindings:
            check(pattern, tag + " bindings")
        for rule in spec.imports:
            check(rule.pattern, tag + " import " + rule.id)
            if "(?P<spec>" not in rule.pattern:
                problems.append(tag + " import " + rule.id + ": no named `spec` group, so "
                                "nothing can be resolved")

    # the workflow model keeps its field tables as regexes too
    for name in ("TEXT_FIELDS", "ID_FIELDS", "SLUG_FIELDS", "ENUM_FIELDS",
                 "TRUSTED_FIELDS", "AUTHORED_FIELDS", "DERIVED_FIELDS", "ANYONE_FIELDS"):
        for pattern in getattr(actions, name):
            check(pattern, "[actions] " + name)
    for pattern, _label, _blocks in actions.GUARD_PATTERNS:
        check(pattern, "[actions] GUARD_PATTERNS")

    # the pattern rule base and the adapters go through the same check
    for lang, spec in langs.SPECS.items():
        for pattern in spec.adapter.terminator_calls:
            check(pattern, "[" + spec.lang + "] terminator_calls")
    for rule in rules.COMPILED_RULES:
        check(rule["rx"].pattern, "[rules] " + rule["id"])
        if rule["tier"] == "signal" and rule["cwe"]:
            problems.append("[rules] " + rule["id"] + ": a signal must not carry a CWE")
        if rule["cat"] not in rules.CATEGORIES:
            problems.append("[rules] " + rule["id"] + ": unknown category")

    if "text" not in PAYLOAD_VALUES:
        problems.append("[model] text must be able to carry a payload")

    if problems:
        print("  %d problem(s):" % len(problems))
        for problem in problems:
            print("    " + problem)
        return 1
    print("  all spec patterns compile; sinks, sanitizers and param sources are coherent")
    print("  checked %d language specs" % len(seen_specs))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
