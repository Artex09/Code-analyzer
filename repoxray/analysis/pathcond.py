"""Path sensitivity: turn branch conditions into SMT formulas and ask Z3 what is possible.

A may-analysis reports every sink that *could* be reached, because it merges the state of
both arms of every branch. That is where a large share of the remaining false positives come
from: the code already checks the value, and the check is simply invisible to a flow analysis.

This module closes that gap in two ways, and the second is the one that matters in practice.

1. Contradictory paths. Conditions are collected along the CFG edges that lead to the sink -
   the classic `if (x > 5) { if (x < 2) { sink(x) } }`. If Z3 says the conjunction is UNSAT
   the path cannot be taken at all and the finding is discarded.

2. Validated values - far more common in real code. The path condition is conjoined with a
   *danger predicate* for the vulnerability class: for command injection, "the value contains
   one of ; | & ` $( or a newline". If `path condition AND danger` is UNSAT then every value
   that survives the guards is harmless, so the finding is dropped with a reason. If it is
   SAT, Z3 hands back a model - a concrete string that passes every check and still carries a
   payload. That witness goes into the finding, which is the difference between "look at this
   line" and "send this value".

Soundness direction: anything the encoder does not understand becomes an unconstrained atom.
Fewer constraints can only make the solver *more* permissive, so an untranslatable guard can
never silence a true finding - it just stops us claiming the value was validated.

Z3 is optional. Without it the engine behaves exactly as before and says so.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass

try:                                   # pragma: no cover - import probe
    import z3
except Exception:                      # pragma: no cover
    z3 = None

MAX_PATHS = 24            # distinct routes entry -> sink we are willing to enumerate
MAX_PATH_LEN = 80
QUERY_MS = 150            # per solver call
FILE_BUDGET_MS = 2500     # per file, across all queries
MAX_COND_DEPTH = 14


def available() -> bool:
    return z3 is not None


def version() -> str:
    if z3 is None:
        return ""
    try:
        return z3.get_version_string()
    except Exception:                  # pragma: no cover
        return "?"


# --------------------------------------------------------------- danger models

# What an exploit payload must contain for each vulnerability class. Deliberately the
# *weakest* useful claim: a value that cannot contain any of these cannot be a payload.
DANGER_SUBSTRINGS = {
    "cmd": (";", "|", "&", "`", "$(", "\n", "\r", ">", "<"),
    "code": (";", "(", "`", "[", "=", "\n"),
    "sqli": ("'", "\"", "--", "/*", ";", " or ", " union "),
    "nosql": ("$", "{", "["),
    "xss": ("<", ">", "javascript:", "onerror", "&#"),
    "tmpl": ("{{", "${", "<%", "#{", "{%"),
    "deser": ("!!", "cos\n", "__reduce__", "rO0", "O:"),
    # For a URL the payload markers are the confusion tricks, not "it looks like a URL":
    # an allow-list of literal endpoints contains "https://" too, and listing that as
    # dangerous would make every allow-list look exploitable.
    "ssrf": ("@", "\\", "..", "%2f", "%40", "\r", "\n", "file:", "gopher:", "dict:",
             "localhost", "127.0", "0.0.0.0", "169.254", "[::", "metadata"),
    "redirect": ("@", "\\", "%2f", "\r", "\n", "javascript:", "data:"),
    "crlf": ("\r", "\n", "%0d", "%0a"),
}
# Classes where the question is "can the value name an origin the author did not write?".
# For these, being different from every literal in the guards is itself dangerous, which is
# what separates `url === ALLOWED[0]` (safe) from `url.startsWith("https://")` (not safe).
ORIGIN_CATS = ("ssrf", "redirect")
# Markers that only mean something at the start of the value. `//evil.com` is the classic
# open redirect, while an allow-listed `https://a.example.com` merely *contains* "//".
DANGER_PREFIXES = {
    "redirect": ("//", "\\", "javascript:", "data:", "vbscript:"),
    "ssrf": ("//", "file:", "gopher:", "dict:", "jar:"),
    "path": ("/", "\\", "~"),
}
# path traversal is a shape, not a substring list, so it gets its own predicate
PATH_CATS = ("path", "upload")
PATH_SUBSTRINGS = ("..", "\\", "%2e", "\x00")

_danger_cache: dict = {}


def _full():
    return z3.Full(z3.ReSort(z3.StringSort()))


def _anywhere(lit: str):
    return z3.Concat(_full(), z3.Re(lit), _full())


def danger_regex(cat: str, removed: tuple = ()):
    """A regex over every string that could still be a payload for this class.

    Expressed as one regex rather than a disjunction of Contains(), deliberately: Z3 decides
    regex intersection with automata and answers in under a millisecond, while the equivalent
    string-constraint form hits the timeout and returns `unknown` - which would make the whole
    check worthless. Measured on `^[a-z]+$` against the command-injection payload set:
    0.01s unsat as regexes, 3s unknown as Contains().
    """
    key = (cat, tuple(sorted(removed)))
    if key in _danger_cache:
        return _danger_cache[key]

    def survives(marker: str) -> bool:
        """A partial filter removes some characters; a payload needing one is now impossible.

        `strings.ReplaceAll(url, "&", "^&")` takes out `&` and leaves `|`, `>`, `<` and `"`
        alone. Treating that as full sanitisation hides the bug; ignoring it entirely offers
        a witness the code cannot actually produce. Narrowing the payload set is the honest
        answer, and it is a question the solver can be asked precisely.
        """
        return not any(gone and gone in marker for gone in removed)

    parts = []
    subs = PATH_SUBSTRINGS if cat in PATH_CATS else DANGER_SUBSTRINGS.get(cat)
    if subs:
        parts = [_anywhere(s) for s in subs if survives(s)]
    for pre in DANGER_PREFIXES.get(cat, ()):
        if survives(pre):
            parts.append(z3.Concat(z3.Re(pre), _full()))
    out = None if not parts else (parts[0] if len(parts) == 1 else z3.Union(*parts))
    _danger_cache[key] = out
    return out


def _danger(cat: str, var, literals=(), removed=()):
    """Z3 predicate: `var` can still carry a payload for this vulnerability class."""
    clauses = []
    rx = danger_regex(cat, removed)
    if rx is None and removed and danger_regex(cat, ()) is not None:
        # the class *is* modelled, and the filters took out every marker it needs: no value
        # that survives them can be a payload, which is an answer rather than an absence
        return z3.BoolVal(False)
    if rx is not None:
        clauses.append(z3.InRe(var, rx))
    if cat in ORIGIN_CATS:
        if literals:
            clauses.append(z3.And(*[var != z3.StringVal(s) for s in literals]))
        else:
            clauses.append(z3.BoolVal(True))     # nothing was approved by name
    if not clauses:
        return None
    return clauses[0] if len(clauses) == 1 else z3.Or(*clauses)


def _printable():
    """One or more characters a person can paste into a request."""
    return z3.Plus(z3.Range(" ", "~"))


def _numeric_regex():
    return z3.Concat(z3.Option(z3.Re("-")), z3.Plus(z3.Range("0", "9")),
                     z3.Option(z3.Concat(z3.Re("."), z3.Plus(z3.Range("0", "9")))))


def _substrings_of(literal: str):
    """Regex over every substring of a literal: encodes `x in "abc"`.

    Enumerated rather than written as Contains(literal, x) so the formula stays inside the
    regex theory, where it combines cheaply with the payload check. Long literals are not
    worth the expansion and the caller treats a None as an unconstrained guard.
    """
    if not literal or len(literal) > 32:
        return None
    subs = {literal[i:j] for i in range(len(literal)) for j in range(i + 1, len(literal) + 1)}
    subs.add("")
    parts = [z3.Re(s) for s in sorted(subs)]
    return parts[0] if len(parts) == 1 else z3.Union(*parts)


def _conj(*parts):
    live = [p for p in parts if p is not None]
    if not live:
        return None
    return live[0] if len(live) == 1 else z3.And(*live)


def modelled_categories() -> list:
    return sorted(set(DANGER_SUBSTRINGS) | set(PATH_CATS))


_PRINTABLE = None if z3 is None else _printable()


# ------------------------------------------------------------ regex -> Z3 ReSort

class RegexUnsupported(Exception):
    pass


def _any_char():
    return z3.AllChar(z3.ReSort(z3.StringSort()))


def _class_escape(ch: str):
    if ch == "d":
        return z3.Range("0", "9")
    if ch == "w":
        return z3.Union(z3.Range("a", "z"), z3.Range("A", "Z"), z3.Range("0", "9"),
                        z3.Re("_"))
    if ch == "s":
        return z3.Union(z3.Re(" "), z3.Re("\t"), z3.Re("\n"), z3.Re("\r"), z3.Re("\f"))
    if ch == "D":
        return z3.Intersect(_any_char(), z3.Complement(z3.Range("0", "9")))
    if ch == "W":
        return z3.Intersect(_any_char(), z3.Complement(_class_escape("w")))
    if ch == "S":
        return z3.Intersect(_any_char(), z3.Complement(_class_escape("s")))
    if ch == "n":
        return z3.Re("\n")
    if ch == "t":
        return z3.Re("\t")
    if ch == "r":
        return z3.Re("\r")
    return None


class _RegexParser:
    """Recursive descent over the subset of PCRE that Z3's regex theory can express.

    Anything else - lookaround, back references, named groups, possessive quantifiers -
    raises, and the caller falls back to an unconstrained atom.
    """

    def __init__(self, pattern: str, ignorecase: bool = False):
        self.p = pattern
        self.i = 0
        self.ic = ignorecase
        self.anchored_start = False
        self.anchored_end = False

    def parse(self):
        if self.p.startswith("^"):
            self.anchored_start = True
            self.i = 1
        node = self._alt()
        if self.i < len(self.p):
            raise RegexUnsupported("trailing " + self.p[self.i:])
        return node

    def _alt(self):
        parts = [self._seq()]
        while self.i < len(self.p) and self.p[self.i] == "|":
            self.i += 1
            parts.append(self._seq())
        if len(parts) == 1:
            return parts[0]
        return z3.Union(*parts)

    def _seq(self):
        items = []
        while self.i < len(self.p) and self.p[self.i] not in "|)":
            items.append(self._quantified())
        if not items:
            return z3.Re("")
        if len(items) == 1:
            return items[0]
        return z3.Concat(*items)

    def _quantified(self):
        atom = self._atom()
        while self.i < len(self.p):
            ch = self.p[self.i]
            if ch == "*":
                self.i += 1
                atom = z3.Star(atom)
            elif ch == "+":
                self.i += 1
                atom = z3.Plus(atom)
            elif ch == "?":
                self.i += 1
                atom = z3.Option(atom)
            elif ch == "{":
                close = self.p.find("}", self.i)
                if close == -1:
                    break
                body = self.p[self.i + 1:close]
                if not re.fullmatch(r"\d+(,\d*)?", body):
                    break
                self.i = close + 1
                if "," not in body:
                    n = int(body)
                    atom = z3.Loop(atom, n, n)
                else:
                    lo, _, hi = body.partition(",")
                    lo_n = int(lo or 0)
                    if hi:
                        atom = z3.Loop(atom, lo_n, int(hi))
                    else:
                        atom = z3.Concat(z3.Loop(atom, lo_n, lo_n), z3.Star(atom))
            else:
                break
            if self.i < len(self.p) and self.p[self.i] == "?":
                self.i += 1      # lazy quantifier: same language
        return atom

    def _atom(self):
        if self.i >= len(self.p):
            raise RegexUnsupported("empty atom")
        ch = self.p[self.i]
        if ch == "(":
            self.i += 1
            if self.p[self.i:self.i + 2] == "?:":
                self.i += 2
            elif self.i < len(self.p) and self.p[self.i] == "?":
                raise RegexUnsupported("lookaround or named group")
            inner = self._alt()
            if self.i >= len(self.p) or self.p[self.i] != ")":
                raise RegexUnsupported("unbalanced group")
            self.i += 1
            return inner
        if ch == "[":
            return self._charclass()
        if ch == ".":
            self.i += 1
            return _any_char()
        if ch == "$":
            if self.i == len(self.p) - 1:
                self.anchored_end = True
                self.i += 1
                return z3.Re("")
            raise RegexUnsupported("$ in the middle")
        if ch == "\\":
            self.i += 1
            if self.i >= len(self.p):
                raise RegexUnsupported("trailing backslash")
            esc = self.p[self.i]
            self.i += 1
            if esc in "bBAZzGk1234567890":
                raise RegexUnsupported("anchor or backref \\" + esc)
            cls = _class_escape(esc)
            if cls is not None:
                return cls
            return self._lit(esc)
        if ch in "*+?":
            raise RegexUnsupported("dangling quantifier")
        self.i += 1
        return self._lit(ch)

    def _lit(self, ch: str):
        if self.ic and ch.isalpha():
            return z3.Union(z3.Re(ch.lower()), z3.Re(ch.upper()))
        return z3.Re(ch)

    def _charclass(self):
        self.i += 1                     # consume [
        negate = False
        if self.i < len(self.p) and self.p[self.i] == "^":
            negate = True
            self.i += 1
        parts = []
        first = True
        while self.i < len(self.p) and (self.p[self.i] != "]" or first):
            first = False
            ch = self.p[self.i]
            if ch == "\\":
                self.i += 1
                esc = self.p[self.i]
                self.i += 1
                cls = _class_escape(esc)
                parts.append(cls if cls is not None else z3.Re(esc))
                continue
            # a range a-z, but a trailing '-' is a literal
            if (self.i + 2 < len(self.p) and self.p[self.i + 1] == "-"
                    and self.p[self.i + 2] != "]"):
                lo, hi = ch, self.p[self.i + 2]
                self.i += 3
                if self.ic and lo.isalpha() and hi.isalpha():
                    parts.append(z3.Union(z3.Range(lo.lower(), hi.lower()),
                                          z3.Range(lo.upper(), hi.upper())))
                else:
                    parts.append(z3.Range(lo, hi))
                continue
            self.i += 1
            parts.append(self._lit(ch))
        if self.i >= len(self.p):
            raise RegexUnsupported("unterminated class")
        self.i += 1                     # consume ]
        if not parts:
            raise RegexUnsupported("empty class")
        union = parts[0] if len(parts) == 1 else z3.Union(*parts)
        if negate:
            return z3.Intersect(_any_char(), z3.Complement(union))
        return union


def regex_constraint(var, pattern: str, flags: str = ""):
    """Z3 predicate for "var matches this pattern", honouring anchors."""
    p = _RegexParser(pattern, ignorecase="i" in flags)
    body = p.parse()
    full = z3.Full(z3.ReSort(z3.StringSort()))
    if not p.anchored_start:
        body = z3.Concat(full, body)
    if not p.anchored_end:
        body = z3.Concat(body, full)
    return z3.InRe(var, body)


# ------------------------------------------------------------------ conditions

# What kind of check a condition is. An `if` is not automatically a security guard, and the
# three kinds that are have different consequences: a value check can make a payload
# impossible, an authorization check decides who can reach the path, and an opaque validator
# means the question is simply open and should be said to be open.
VALIDATOR_CALLS = re.compile(
    r"\b[A-Za-z_0-9.]*(valid|allow|permit|whitelist|allowlist|safe|sanitiz|"
    r"escap|verif|authent|authoriz|legal|accept|approve|trust|clean|normaliz)"
    r"[A-Za-z_0-9]*\s*\(", re.I)
AUTHORIZATION_HINTS = re.compile(
    r"\b(owner|user_?id|userid|account|tenant|org|organisation|organization|"
    r"full_?name|fullname|repo|repository|actor|login|role|scope|permission|admin|"
    r"is_?admin|is_?owner|member|subject|principal|claim|claims)\b", re.I)
EXISTENCE_HINTS = re.compile(
    r"(==|!=)\s*(nil|null|None|undefined)\b|"
    r"^\s*!?\s*(ok|err|error|found|exists)\s*$|"
    r"\blen\s*\([^)]*\)\s*(==|<)\s*(0|1)\b")


def classify_condition(text: str, modelled: bool) -> str:
    """value | validator | authorization | existence | unknown, for one condition."""
    body = (text or "").strip()
    if not body:
        return "unknown"
    if modelled:
        return "value"
    if VALIDATOR_CALLS.search(body):
        return "validator"
    if EXISTENCE_HINTS.search(body):
        return "existence"
    if AUTHORIZATION_HINTS.search(body):
        return "authorization"
    return "unknown"


@dataclass
class Cond:
    """One branch condition on the way to a sink."""
    node: object
    polarity: bool
    line: int
    text: str = ""


class Encoder:
    """Translate condition AST nodes into Z3, over a per-check symbol table."""

    def __init__(self, ad, txt, guards, literals: dict | None = None):
        self.ad = ad
        self.txt = txt                      # callable(node) -> source text
        self.guards = guards                # [(Guard, compiled regex)]
        self.literals = {} if literals is None else literals
        self.vars: dict = {}
        self.nums: dict = {}
        self.atoms: dict = {}
        self.touched: set = set()           # symbols a real constraint was built for
        self.modelled: list = []            # human text of guards we understood
        self.opaque: list = []              # human text of guards we did not
        self.literals_seen: set = set()     # every literal the guards compare against

    # -- symbols ----------------------------------------------------------

    def var(self, name: str):
        if name not in self.vars:
            self.vars[name] = z3.String("v!" + name)
        return self.vars[name]

    def num(self, name: str):
        """The numeric reading of a value, kept as a separate variable.

        Linking it to the string form with str.to_int would be more faithful but drags the
        solver into a theory combination it answers `unknown` for. Instead the two are tied
        by a cheap regex: a value in a numeric comparison must *look* numeric, which is the
        part that actually rules out payloads, while `x > 5 and x < 2` stays pure arithmetic.
        """
        if name not in self.nums:
            self.nums[name] = z3.Int("n!" + name)
        return self.nums[name]

    def _numeric(self, name: str):
        return z3.InRe(self.var(name), _numeric_regex())

    def atom(self, key: str):
        if key not in self.atoms:
            self.atoms[key] = z3.Bool("a!" + key)
        return self.atoms[key]

    def _sym(self, node) -> str | None:
        """The storage key for a node, matching dataflow.Analyzer.symbol()."""
        t = node.type
        if t in self.ad.identifier_nodes:
            return self.txt(node)
        if t in self.ad.member_nodes:
            obj = node.child_by_field_name(self.ad.member_obj_field)
            prop = node.child_by_field_name(self.ad.member_prop_field)
            if obj is not None and prop is not None:
                inner = self._sym(obj)
                if inner is not None:
                    return inner + "." + self.txt(prop)
        if t in self.ad.index_nodes:
            kids = node.named_children
            if kids:
                inner = self._sym(kids[0])
                if inner is not None:
                    return inner + "[]"
        if t in self.ad.call_nodes and self.ad.transparent_calls:
            callee = _callee(self.ad, self.txt, node)
            if callee and callee.split(".")[-1] in self.ad.transparent_calls:
                args = _args(self.ad, node)
                if len(args) == 1:
                    return self._sym(self._unwrap(args[0]))
                if not args:
                    fn = node.child_by_field_name(self.ad.call_fn_field)
                    if fn is not None and fn.type in self.ad.member_nodes:
                        obj = fn.child_by_field_name(self.ad.member_obj_field)
                        if obj is not None:
                            return self._sym(obj)
        return None

    def _op(self, node) -> str:
        child = node.child_by_field_name(self.ad.operator_field)
        if child is not None:
            return self.txt(child).strip()
        for c in node.children:
            if not c.is_named:
                s = self.txt(c).strip()
                if s:
                    return s
        return ""

    def _kids(self, node) -> list:
        return [c for c in node.named_children if c.type != "comment"]

    def _unwrap(self, node):
        seen = 0
        while node is not None and seen < 6:
            if node.type in ("parenthesized_expression", "parenthesized_statement",
                             "expression_statement", "await_expression", "await",
                             "non_null_expression", "as_expression", "argument"):
                kids = self._kids(node)
                if len(kids) == 1:
                    node = kids[0]
                    seen += 1
                    continue
            break
        return node

    # -- terms ------------------------------------------------------------

    def _string_literal(self, node) -> str | None:
        node = self._unwrap(node)
        if node is None:
            return None
        if node.type in self.ad.string_nodes or node.type in self.ad.interp_string_nodes:
            raw = self.txt(node)
            # python r"..." / b"..." / f"...", php b"...", js String.raw is not a literal
            prefix = ""
            while raw and raw[0] in "rRbBuUfF":
                prefix += raw[0].lower()
                raw = raw[1:]
            if len(raw) >= 2 and raw[0] in "\"'`" and raw[-1] == raw[0]:
                body = raw[1:-1]
                if "f" in prefix or "${" in body or (
                        "{" in body and node.type in self.ad.interp_string_nodes):
                    return None
                out = body
                if "r" not in prefix:
                    # a non-raw literal still has its escapes to resolve, and a regex written
                    # as "\\w+" in source means \w+ by the time the engine sees it
                    try:
                        out = body.encode("utf-8", "replace").decode("unicode_escape", "replace")
                    except Exception:
                        out = body
                self.literals_seen.add(out)
                return out
        return None

    def _number_literal(self, node):
        node = self._unwrap(node)
        if node is None:
            return None
        txt = self.txt(node).strip()
        if re.fullmatch(r"-?\d+", txt):
            return int(txt)
        if re.fullmatch(r"-?\d+\.\d+", txt):
            return int(float(txt))
        return None

    def _list_literals(self, node) -> tuple | None:
        """String literals of an array/list expression, or of a known const array."""
        node = self._unwrap(node)
        if node is None:
            return None
        sym = self._sym(node)
        if sym is not None and sym in self.literals:
            return self.literals[sym]
        if node.type in ("array", "array_literal", "list", "array_creation_expression",
                         "tuple", "set", "composite_literal", "array_expression"):
            out = []
            for c in self._kids(node):
                lit = self._string_literal(c)
                if lit is None:
                    # php wraps each element in array_element_initializer, c# in
                    # initializer_expression: look through a single-child wrapper
                    inner = self._kids(c)
                    lit = self._string_literal(inner[-1]) if len(inner) == 1 else None
                if lit is None:
                    return None
                out.append(lit)
            return tuple(out) if out else None
        return None

    def _length_of(self, node):
        """Z3 int term when the node is a length expression, else None."""
        node = self._unwrap(node)
        if node is None:
            return None
        if node.type in self.ad.member_nodes:
            prop = node.child_by_field_name(self.ad.member_prop_field)
            obj = node.child_by_field_name(self.ad.member_obj_field)
            if prop is not None and self.txt(prop) in self.ad.length_props:
                sym = self._sym(obj) if obj is not None else None
                if sym:
                    self.touched.add(sym)
                    return z3.Length(self.var(sym))
        if node.type in self.ad.call_nodes and self.ad.length_fns:
            fn = node.child_by_field_name(self.ad.call_fn_field)
            name = re.sub(r"\s+", "", self.txt(fn)) if fn is not None else ""
            # len(x) in python, but s.length() / s.size() in java and ruby
            if name in self.ad.length_fns or name.split(".")[-1] in self.ad.length_fns:
                args = _args(self.ad, node)
                sym = None
                if len(args) == 1:
                    sym = self._sym(self._unwrap(args[0]))
                elif not args and fn is not None and fn.type in self.ad.member_nodes:
                    obj = fn.child_by_field_name(self.ad.member_obj_field)
                    sym = self._sym(obj) if obj is not None else None
                if sym:
                    self.touched.add(sym)
                    return z3.Length(self.var(sym))
        return None

    def as_int(self, node):
        """(integer term, side constraint) - best-effort numeric reading of an expression.

        The side constraint carries "and the string form has to look like a number", which
        is what lets a numeric guard exclude an injection payload. It is returned rather
        than asserted so that negating the comparison negates it too: `!(x > 5)` is also
        true of a value that is not a number at all.
        """
        lit = self._number_literal(node)
        if lit is not None:
            return z3.IntVal(lit), None
        ln = self._length_of(node)
        if ln is not None:
            return ln, None
        node = self._unwrap(node)
        sym = self._sym(node) if node is not None else None
        if sym:
            self.touched.add(sym)
            return self.num(sym), self._numeric(sym)
        return None, None

    def as_str(self, node):
        lit = self._string_literal(node)
        if lit is not None:
            return z3.StringVal(lit)
        num = self._number_literal(node)
        if num is not None:
            return z3.StringVal(str(num))
        node = self._unwrap(node)
        sym = self._sym(node) if node is not None else None
        if sym:
            self.touched.add(sym)
            return self.var(sym)
        return None

    # -- booleans ---------------------------------------------------------

    def encode(self, node, polarity: bool, depth: int = 0):
        formula = self._bool(node, depth)
        if formula is None:
            formula = self.atom(_key(self.txt(node)))
        return formula if polarity else z3.Not(formula)

    def _operand(self, node, depth: int):
        """One side of a boolean operator, falling back to an opaque atom.

        Written as an explicit None check rather than `self._bool(...) or atom(...)`: `or`
        calls __bool__ on a Z3 expression, which raises, and the exception was swallowed as
        "encode-failed" - so every `&&` and `||` guard lost its path conditions in silence.
        """
        formula = self._bool(node, depth + 1)
        if formula is None:
            return self.atom(_key(self.txt(node)))
        return formula

    def _bool(self, node, depth: int = 0):
        if node is None or depth > MAX_COND_DEPTH:
            return None
        node = self._unwrap(node)
        if node is None:
            return None
        t = node.type
        txt = self.txt(node).strip()

        if txt in self.ad.true_literals:
            return z3.BoolVal(True)
        if txt in self.ad.false_literals:
            return z3.BoolVal(False)

        if t in self.ad.unary_nodes:
            op = self._op(node)
            kids = self._kids(node)
            if op in self.ad.not_operators and kids:
                return z3.Not(self._operand(kids[-1], depth))

        if t in self.ad.binary_nodes or t in self.ad.concat_nodes:
            op = self._op(node)
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is None or right is None:
                kids = self._kids(node)
                if len(kids) == 2:
                    left, right = kids
            if left is None or right is None:
                return None
            if op in self.ad.and_operators:
                return z3.And(self._operand(left, depth), self._operand(right, depth))
            if op in self.ad.or_operators:
                return z3.Or(self._operand(left, depth), self._operand(right, depth))
            if op in self.ad.in_operators:
                items = self._list_literals(right)
                val = self.as_str(left)
                if items is not None and val is not None:
                    self.modelled.append(txt)
                    return z3.Or(*[val == z3.StringVal(s) for s in items])
                container = self._string_literal(right)
                if container is not None and val is not None:
                    subs = _substrings_of(container)
                    if subs is not None:
                        self.modelled.append(txt)
                        return z3.InRe(val, subs)
                return None
            if op in self.ad.regex_operators:
                val = self.as_str(left)
                pattern, flags = self._regex_literal(right)
                if val is not None and pattern:
                    try:
                        self.modelled.append(txt)
                        return regex_constraint(val, pattern, flags)
                    except Exception:
                        return None
                return None
            if op in ("==", "===", "!=", "!==", "<>", "eq", "ne", "is"):
                neg = op in ("!=", "!==", "<>", "ne")
                formula = self._equality(left, right, depth)
                if formula is None:
                    return None
                self.modelled.append(txt)
                return z3.Not(formula) if neg else formula
            if op in ("<", ">", "<=", ">="):
                a, sa = self.as_int(left)
                b, sb = self.as_int(right)
                if a is None or b is None:
                    return None
                self.modelled.append(txt)
                return _conj(sa, sb, {"<": a < b, ">": a > b,
                                      "<=": a <= b, ">=": a >= b}[op])

        if t in self.ad.call_nodes:
            got = self._guard_call(node)
            if got is not None:
                return got
            self.opaque.append(txt)
            return self.atom(_key(txt))

        # a bare value used as a condition: `if (name)`. Truthiness of an arbitrary value is
        # not something to guess at, so it becomes an opaque atom - but the *same* atom, so
        # `if (!ok) return;` followed by `if (ok)` is still provably contradictory.
        sym = self._sym(node)
        if sym is not None:
            return self.atom(_key(sym))
        return None

    def _equality(self, left, right, depth: int):
        # typeof x === "string" / "number"
        type_of = self._typeof(left) or self._typeof(right)
        if type_of is not None:
            sym, _ = type_of
            lit = self._string_literal(right) or self._string_literal(left)
            if sym and lit in ("number", "bigint"):
                self.touched.add(sym)
                return self._numeric(sym)
            if sym and lit in ("string", "object", "boolean", "undefined", "function"):
                return self.atom(_key("typeof:" + sym + ":" + str(lit)))
        ln = self._length_of(left) or self._length_of(right)
        if ln is not None:
            other, side = self.as_int(right if self._length_of(left) is not None else left)
            if other is not None:
                return _conj(side, ln == other)
        if self._number_literal(left) is not None or self._number_literal(right) is not None:
            a, sa = self.as_int(left)
            b, sb = self.as_int(right)
            if a is not None and b is not None:
                return _conj(sa, sb, a == b)
        a, b = self.as_str(left), self.as_str(right)
        if a is None or b is None:
            return None
        return a == b

    def _typeof(self, node):
        node = self._unwrap(node)
        if node is None:
            return None
        if node.type in ("unary_expression", "type_of_expression"):
            if self._op(node) == "typeof":
                kids = self._kids(node)
                if kids:
                    return self._sym(kids[-1]), "typeof"
        txt = self.txt(node).strip()
        m = re.fullmatch(r"typeof\s+([\w.$]+)", txt)
        if m:
            return m.group(1), "typeof"
        return None

    def _guard_call(self, node):
        callee = _callee(self.ad, self.txt, node)
        if not callee:
            return None
        args = _args(self.ad, node)
        recv = None
        fn = node.child_by_field_name(self.ad.call_fn_field)
        if fn is not None and fn.type in self.ad.member_nodes:
            recv = fn.child_by_field_name(self.ad.member_obj_field)
        for guard, rx in self.guards:
            if not rx.search(callee):
                continue
            value_node = recv if guard.value_arg < 0 else (
                args[guard.value_arg] if guard.value_arg < len(args) else None)
            pat_node = recv if guard.pattern_arg < 0 else (
                args[guard.pattern_arg] if guard.pattern_arg < len(args) else None)
            got = self._apply_guard(guard, value_node, pat_node, node)
            if got is not None:
                self.modelled.append(self.txt(node).strip())
                return got
        return None

    def _apply_guard(self, guard, value_node, pat_node, call):
        if value_node is None:
            return None
        if guard.kind == "numeric":
            sym = self._sym(self._unwrap(value_node))
            if not sym:
                return None
            self.touched.add(sym)
            return self._numeric(sym)
        val = self.as_str(value_node)
        if val is None:
            return None
        if guard.kind == "regex":
            if guard.literal:
                pattern, flags = guard.literal, ""
            else:
                pattern, flags = self._regex_literal(pat_node)
            if not pattern:
                return None
            try:
                return regex_constraint(val, pattern, flags)
            except Exception:
                return None
        if guard.kind == "membership":
            items = self._list_literals(pat_node)
            if not items:
                return None
            return z3.Or(*[val == z3.StringVal(s) for s in items])
        lit = self._string_literal(pat_node) if pat_node is not None else None
        if lit is None:
            return None
        # prefix/suffix/contains stay in the regex theory so they combine cheaply with the
        # payload check; the string-predicate forms make Z3 answer `unknown`.
        if guard.kind == "prefix":
            return z3.InRe(val, z3.Concat(z3.Re(lit), _full()))
        if guard.kind == "suffix":
            return z3.InRe(val, z3.Concat(_full(), z3.Re(lit)))
        if guard.kind == "contains":
            return z3.InRe(val, _anywhere(lit))
        if guard.kind == "equals":
            return val == z3.StringVal(lit)
        return None

    def _regex_literal(self, node):
        """(pattern, flags) from /re/i, a quoted pattern, or a const holding one."""
        if node is None:
            return None, ""
        node = self._unwrap(node)
        raw = self.txt(node).strip()
        if node.type in self.ad.regex_nodes or (raw.startswith("/") and len(raw) > 1):
            m = re.fullmatch(r"/(.*)/([gimsuy]*)", raw, re.S)
            if m:
                return m.group(1), m.group(2)
        lit = self._string_literal(node)
        if lit is not None:
            # php delimits with slashes inside the string: '/^[a-z]+$/i'
            m = re.fullmatch(r"([/#~!])(.*)\1([gimsuxyA]*)", lit, re.S)
            if m:
                return m.group(2), m.group(3)
            return lit, ""
        if node.type in self.ad.call_nodes:
            callee = _callee(self.ad, self.txt, node)
            if callee.split(".")[-1] in ("RegExp", "compile", "MustCompile", "Regexp",
                                         "Pattern", "new"):
                args = _args(self.ad, node)
                if args:
                    lit = self._string_literal(args[0])
                    flags = self._string_literal(args[1]) if len(args) > 1 else ""
                    if lit:
                        m = re.fullmatch(r"([/#~])(.*)\1([gimsuxyA]*)", lit, re.S)
                        if m:
                            return m.group(2), m.group(3)
                        return lit, flags or ""
        return None, ""


def _key(text: str) -> str:
    return re.sub(r"\s+", "", text)[:120]


def _callee(ad, txt, call) -> str:
    fn = call.child_by_field_name(ad.call_fn_field)
    if fn is None:
        recv = call.child_by_field_name("receiver")
        meth = call.child_by_field_name("method")
        if meth is not None:
            return ((txt(recv) + ".") if recv is not None else "") + txt(meth)
        return ""
    return re.sub(r"\s+", "", txt(fn))


def _args(ad, call) -> list:
    args = call.child_by_field_name(ad.call_args_field)
    if args is None:
        return []
    out = []
    for c in args.named_children:
        if c.type == "comment":
            continue
        if c.type in ad.arg_wrapper_nodes:
            inner = [g for g in c.named_children if g.type != "comment"]
            out.append(inner[-1] if inner else c)
            continue
        out.append(c)
    return out


# ------------------------------------------------------------------- verdicts

@dataclass
class Verdict:
    status: str = "reachable"    # reachable | unreachable | validated | unknown
    proof: str = ""              # witness | unguarded | value-unguarded | no-solver | ...
    guards: tuple = ()
    witness: str = ""
    queries: int = 0
    kinds: tuple = ()            # value | validator | authorization | existence | unknown

    @property
    def drop(self) -> bool:
        return self.status in ("unreachable", "validated")


class PathChecker:
    """One per file. Holds the solver budget and the file's constant tables."""

    def __init__(self, ad, txt, guards, literals: dict | None = None):
        self.ad = ad
        self.txt = txt
        self.guards = guards
        self.literals = {} if literals is None else literals
        self.spent_ms = 0.0
        self.queries = 0
        self.unreachable = 0
        self.validated = 0
        self.witnesses = 0

    @property
    def live(self) -> bool:
        return z3 is not None and self.spent_ms < FILE_BUDGET_MS

    def check(self, paths: list, taint_syms: tuple, cat: str, removed=()) -> Verdict:
        """`paths` is a list of Cond lists; any one of them being exploitable is enough."""
        if z3 is None:
            return Verdict("reachable", "no-solver")
        if not paths or all(not p for p in paths):
            return Verdict("reachable", "unguarded")
        if not self.live:
            return Verdict("reachable", "budget-exhausted",
                           guards=tuple(_texts(paths[0])))
        t0 = time.time()
        feasible = 0
        guard_text: tuple = tuple(_texts(paths[0]))
        guard_kinds: tuple = ()
        value_seen = False
        try:
            for path in paths[:MAX_PATHS]:
                if not path:
                    return Verdict("reachable", "unguarded")
                enc = Encoder(self.ad, self.txt, self.guards, self.literals)
                solver = z3.Solver()
                solver.set("timeout", QUERY_MS)
                try:
                    for cond in path:
                        solver.add(enc.encode(cond.node, cond.polarity))
                except Exception:
                    return Verdict("reachable", "encode-failed", guards=guard_text)
                self.queries += 1
                res = solver.check()
                if res == z3.unsat:
                    continue
                if res == z3.unknown:
                    return Verdict("reachable", "solver-timeout",
                                   guards=tuple(_texts(path)))
                feasible += 1
                guard_text = tuple(_texts(path))
                guard_kinds = _kinds(path, enc.modelled)
                targets = [s for s in taint_syms if s in enc.touched]
                if not targets:
                    # guards exist, but none of them constrains the value that reaches the
                    # sink - an auth check is not a value check
                    return Verdict("reachable", "value-unguarded", guards=guard_text,
                                   kinds=guard_kinds)
                value_seen = True
                lits = tuple(sorted(enc.literals_seen))
                parts = [_danger(cat, enc.var(s), lits, removed)
                         for s in targets] if cat else []
                parts = [p for p in parts if p is not None]
                if not parts:
                    return Verdict("reachable", "class-not-modelled", guards=guard_text)
                danger = parts[0] if len(parts) == 1 else z3.Or(*parts)
                solver.push()
                solver.add(danger)
                self.queries += 1
                res2 = solver.check()
                if res2 == z3.sat:
                    witness = ""
                    # The first model that satisfies the constraints is often full of
                    # control characters, which is true but useless as a starting payload.
                    # Ask once more for a printable one, and for the ORIGIN classes for one
                    # that carries a recognisable marker rather than just a different host.
                    extra = [z3.InRe(enc.var(s), _PRINTABLE) for s in targets]
                    if cat in ORIGIN_CATS and danger_regex(cat, removed) is not None:
                        extra.append(z3.Or(*[z3.InRe(enc.var(s), danger_regex(cat, removed))
                                             for s in targets]))
                    solver.push()
                    solver.add(z3.And(*extra))
                    self.queries += 1
                    if solver.check() != z3.sat:
                        solver.pop()
                    try:
                        model = solver.model()
                        for s in targets:
                            val = model.eval(enc.var(s), model_completion=True)
                            as_str = val.as_string() if hasattr(val, "as_string") else str(val)
                            if as_str:
                                witness = as_str
                                break
                    except Exception:
                        witness = ""
                    if witness:
                        self.witnesses += 1
                    return Verdict("reachable", "witness" if witness else "satisfiable",
                                   guards=guard_text, witness=witness,
                                   kinds=guard_kinds)
                if res2 == z3.unknown:
                    return Verdict("reachable", "solver-timeout", guards=guard_text)
                solver.pop()
        except Exception:                      # pragma: no cover - solver safety net
            return Verdict("reachable", "solver-error", guards=guard_text)
        finally:
            self.spent_ms += (time.time() - t0) * 1000

        if feasible == 0:
            self.unreachable += 1
            return Verdict("unreachable", "contradictory-guards", guards=guard_text)
        if value_seen:
            self.validated += 1
            return Verdict("validated", "guards-exclude-payload", guards=guard_text)
        return Verdict("reachable", "value-unguarded", guards=guard_text,
                       kinds=guard_kinds)

    def stats(self) -> dict:
        return {"queries": self.queries, "unreachable": self.unreachable,
                "validated": self.validated, "witnesses": self.witnesses,
                "solver_ms": int(self.spent_ms)}


def _kinds(path: list, modelled: list) -> tuple:
    """The kind of each condition on a path, deduplicated and ordered by consequence."""
    seen = []
    known = {_key(m) for m in modelled}
    for cond in path:
        kind = classify_condition(cond.text, _key(cond.text or "") in known)
        if kind not in seen:
            seen.append(kind)
    order = {"value": 0, "validator": 1, "authorization": 2, "unknown": 3, "existence": 4}
    return tuple(sorted(seen, key=lambda k: order.get(k, 9)))


def _texts(path: list) -> list:
    out = []
    for cond in path:
        prefix = "requires" if cond.polarity else "requires NOT"
        out.append("L" + str(cond.line) + " " + prefix + ": " + (cond.text or "")[:120])
    return out
