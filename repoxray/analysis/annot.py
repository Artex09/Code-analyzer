"""Reviewer annotations: linter suppressions and the explanations beside them.

`//nolint:gosec // Explicit no-tls-verify override for selected APIs.` is a developer saying
"a scanner complained here, I looked, and this is deliberate". Ignoring that line and
reporting the finding anyway reproduces exactly the alert the team already triaged.

Three rules make this safe rather than a blanket mute:

1. **Codes bind to categories.** `//nolint:gosec` with no code covers anything gosec would
   say. `#nosec G404` covers weak randomness and *nothing else* - it does not excuse a
   hardcoded secret that happens to sit on the same line.
2. **An explanation counts for more than a bare directive.** A directive with a reason is a
   recorded decision. A bare one is "make it stop", which is worth reading, not trusting.
3. **A proven dataflow beats a comment.** This module only describes what the comment says;
   the caller decides, and the caller keeps a traced flow from untrusted input even when a
   directive sits on the line. A comment is evidence about intent, never proof of safety.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# --------------------------------------------------------------- code -> category
#
# Only codes whose meaning is unambiguous are mapped. An unmapped code yields an empty
# category set, which the caller treats as "this directive is about something, but not
# demonstrably about the finding on this line" - so it does not suppress.

GOSEC = {
    "g101": {"secret"}, "g102": {"config"}, "g103": {"memory"}, "g104": set(),
    "g106": {"authn"}, "g107": {"ssrf"}, "g108": {"config"}, "g109": set(),
    "g110": {"dos"}, "g111": {"path"}, "g112": {"dos"}, "g114": {"config"},
    "g201": {"sqli"}, "g202": {"sqli"}, "g203": {"xss"}, "g204": {"cmd", "argv"},
    "g301": {"path"}, "g302": {"path"}, "g303": {"path"}, "g304": {"path"},
    "g305": {"path"}, "g306": {"path"}, "g307": {"path"},
    "g401": {"crypto"}, "g402": {"tls"}, "g403": {"crypto"}, "g404": {"crypto"},
    "g405": {"crypto"}, "g406": {"crypto"}, "g407": {"crypto"},
    "g501": {"crypto"}, "g502": {"crypto"}, "g503": {"crypto"}, "g504": {"crypto"},
    "g505": {"crypto"}, "g506": {"crypto"}, "g507": {"crypto"},
    "g601": {"memory"}, "g602": {"memory"},
}

# bandit / flake8-bandit share numbering: B602 == S602
BANDIT = {
    "105": {"secret"}, "106": {"secret"}, "107": {"secret"}, "108": {"path"},
    "110": set(), "112": set(),
    "201": {"config"}, "202": {"path"},
    "301": {"deser"}, "302": {"deser"}, "303": {"crypto"}, "304": {"crypto"},
    "305": {"crypto"}, "306": {"path"}, "307": {"code"}, "308": {"xss"},
    "310": {"ssrf"}, "311": {"crypto"}, "312": {"authn"}, "313": {"xxe"},
    "314": {"xxe"}, "315": {"xxe"}, "316": {"xxe"}, "317": {"xxe"}, "318": {"xxe"},
    "319": {"xxe"}, "320": {"xxe"}, "321": {"authn"}, "323": {"tls"}, "324": {"crypto"},
    "325": {"path"},
    "501": {"tls"}, "502": {"tls"}, "503": {"tls"}, "504": {"tls"}, "505": {"crypto"},
    "506": {"deser"}, "507": {"authn"}, "508": {"tls"}, "509": {"crypto"},
    "601": {"cmd"}, "602": {"cmd"}, "603": {"cmd"}, "604": {"cmd"}, "605": {"cmd"},
    "606": {"cmd"}, "607": {"cmd"}, "608": {"sqli"}, "609": {"cmd"}, "610": {"sqli"},
    "611": {"sqli"}, "612": {"disclosure"}, "614": {"deser"},
    "701": {"tmpl"}, "702": {"tmpl"}, "703": {"xss"}, "704": {"code"},
}

ESLINT_SECURITY = {
    "detect-child-process": {"cmd", "argv"},
    "detect-non-literal-fs-filename": {"path"},
    "detect-non-literal-require": {"code"},
    "detect-non-literal-regexp": {"dos"},
    "detect-unsafe-regex": {"dos"},
    "detect-object-injection": {"proto"},
    "detect-eval-with-expression": {"code"},
    "detect-no-csrf-before-method-override": {"csrf"},
    "detect-possible-timing-attacks": {"crypto"},
    "detect-pseudo-random-bytes": {"crypto"},
    "detect-pseudorandombytes": {"crypto"},
    "detect-new-buffer": {"memory"},
    "detect-buffer-noassert": {"memory"},
    "detect-disable-mustache-escape": {"xss"},
    "detect-bidi-characters": set(),
    "no-eval": {"code"},
    "no-implied-eval": {"code"},
    "no-script-url": {"code"},
    "no-unsafe-innerhtml/no-unsafe-variable-input": {"xss"},
    "react/no-danger": {"xss"},
    "xss/no-mixed-html": {"xss"},
}

# CodeQL / LGTM query ids are `lang/slug`; the slug carries the meaning.
CODEQL = {
    "command-line-injection": {"cmd", "argv"}, "shell-command-constructed-from-input":
        {"cmd"}, "sql-injection": {"sqli"}, "path-injection": {"path"},
    "request-forgery": {"ssrf"}, "server-side-unvalidated-url-redirection": {"redirect"},
    "reflected-xss": {"xss"}, "stored-xss": {"xss"}, "unsafe-deserialization": {"deser"},
    "code-injection": {"code"}, "hardcoded-credentials": {"secret"},
    "disabled-certificate-check": {"tls"}, "insecure-randomness": {"crypto"},
    "weak-sensitive-data-hashing": {"crypto"}, "clear-text-logging": {"disclosure"},
    "polynomial-redos": {"dos"}, "redos": {"dos"}, "xxe": {"xxe"},
    "missing-token-validation": {"csrf"}, "cors-misconfiguration": {"cors"},
}

# A bare tool name with no code: everything the tool is capable of saying.
TOOL_SCOPE = {
    "gosec": {c for cats in GOSEC.values() for c in cats},
    "bandit": {c for cats in BANDIT.values() for c in cats},
    "security": {c for cats in ESLINT_SECURITY.values() for c in cats},
    "codeql": {c for cats in CODEQL.values() for c in cats},
    "semgrep": set(),       # semgrep rule ids are arbitrary; no reliable mapping
    "sonar": set(),
    "mypy": set(),          # a type-checker directive says nothing about security
    "flake8": set(),
}

# Directives that are not about security at all. Recognised so they are not mistaken for
# a security review, and so `# type: ignore` beside a real finding does not mute it.
NON_SECURITY = {"mypy", "flake8", "typescript", "prettier", "coverage"}


@dataclass(frozen=True)
class Annotation:
    """One suppression directive, and what it is allowed to excuse."""
    tool: str
    codes: tuple = ()
    cats: frozenset = frozenset()
    note: str = ""
    line: int = 0
    scope: tuple = ()
    raw: str = ""

    @property
    def explained(self) -> bool:
        """Did the author write down a reason? Six characters of prose, not `nolint //`."""
        return len(self.note.strip()) >= 6

    @property
    def security(self) -> bool:
        return self.tool not in NON_SECURITY

    def covers(self, cat: str) -> bool:
        """Does this directive plausibly refer to a finding of category `cat`?

        An empty category set means the directive's scope could not be established - a
        semgrep rule id, an unmapped gosec code - and then it covers nothing, because
        "some scanner said something here" is not a reason to drop a different finding.
        """
        return cat in self.cats

    def describe(self) -> str:
        # `//nolint:gosec` carries its linter in the code list, so the code is the tool
        # here and repeating it reads as "gosec gosec"
        shown = [c for c in self.codes if c.lower() != self.tool.lower()]
        code = "/".join(shown)
        head = self.tool + (" " + code if code else "")
        if self.explained:
            return ("a reviewer silenced " + head + " on this line and wrote down why: "
                    + self.note.strip().rstrip(".") + ".")
        return ("a reviewer silenced " + head + " on this line without saying why, so the "
                "decision behind it cannot be read from the code.")


# ------------------------------------------------------------------ directive patterns
#
# Each entry: (regex, tool-group, how far the directive reaches).
# `next` means the directive governs the following source line, `self` the line it is on,
# `both` either (Go and Python conventionally allow a directive above the statement).

_DIRECTIVES = [
    # golangci-lint: //nolint:gosec,govet // reason
    (re.compile(r"//\s*nolint(?::\s*(?P<codes>[\w,\-]+))?\s*(?://\s*(?P<note>.*))?$"),
     "golangci", "both"),
    # gosec's own form: // #nosec G402 -- reason   /  //gosec:disable G402
    (re.compile(r"//\s*#?\s*nosec\s*(?P<codes>(?:[Gg]\d{3}[\s,]*)*)\s*"
                r"(?:--|//)?\s*(?P<note>.*)$"), "gosec", "both"),
    (re.compile(r"//\s*gosec:disable\s*(?P<codes>(?:[Gg]\d{3}[\s,]*)*)\s*"
                r"(?:--|//)?\s*(?P<note>.*)$"), "gosec", "both"),
    # bandit: # nosec B602 - reason
    (re.compile(r"#\s*nosec\s*(?P<codes>(?:[Bb]?\d{3}[\s,]*)*)\s*"
                r"(?:--|#|:)?\s*(?P<note>.*)$"), "bandit", "self"),
    # flake8-bandit through noqa: # noqa: S602  (reason)
    (re.compile(r"#\s*noqa\s*:\s*(?P<codes>[SB]\d{3}(?:\s*,\s*[A-Z]+\d+)*)\s*"
                r"(?:--|#)?\s*(?P<note>.*)$"), "bandit", "self"),
    # eslint
    (re.compile(r"//\s*eslint-disable-next-line\s*(?P<codes>[\w\-/@,\s]*?)\s*"
                r"(?:--\s*(?P<note>.*))?$"), "eslint", "next"),
    (re.compile(r"//\s*eslint-disable-line\s*(?P<codes>[\w\-/@,\s]*?)\s*"
                r"(?:--\s*(?P<note>.*))?$"), "eslint", "self"),
    (re.compile(r"/\*\s*eslint-disable-next-line\s*(?P<codes>[\w\-/@,\s]*?)\s*"
                r"(?:--\s*(?P<note>.*?))?\s*\*/"), "eslint", "next"),
    # semgrep
    (re.compile(r"(?://|#)\s*nosemgrep\s*:?\s*(?P<codes>[\w\-.\s,]*?)\s*"
                r"(?:--\s*(?P<note>.*))?$"), "semgrep", "both"),
    # CodeQL / LGTM
    (re.compile(r"(?://|#)\s*lgtm\s*\[\s*(?P<codes>[\w\-/,\s]+)\s*\]\s*(?P<note>.*)$"),
     "codeql", "self"),
    (re.compile(r"(?://|#)\s*codeql\s*\[\s*(?P<codes>[\w\-/,\s]+)\s*\]\s*(?P<note>.*)$"),
     "codeql", "self"),
    # SonarQube
    (re.compile(r"//\s*NOSONAR\s*(?P<note>.*)$"), "sonar", "self"),
    (re.compile(r"@SuppressWarnings\s*\(\s*(?P<codes>[^)]*)\)"), "sonar", "next"),
    # type-checkers, recognised so they are not read as a security review
    (re.compile(r"#\s*type:\s*ignore(?:\[(?P<codes>[\w,\-]+)\])?\s*(?P<note>.*)$"),
     "mypy", "self"),
    (re.compile(r"//\s*@ts-(?:ignore|expect-error)\s*(?P<note>.*)$"), "typescript", "self"),
]

_CODE_SPLIT = re.compile(r"[,\s]+")


def _norm_codes(raw: str) -> tuple:
    if not raw:
        return ()
    return tuple(c.strip() for c in _CODE_SPLIT.split(raw.strip()) if c.strip())


def _cats_for(tool: str, codes: tuple) -> tuple[str, frozenset]:
    """Map a directive's tool+codes onto the categories it can excuse.

    Returns the *effective* tool name, because `//nolint:gosec` carries its real tool in
    the code list: golangci-lint is a driver, gosec is the linter that complained.
    """
    cats: set = set()
    eff = tool
    if tool == "golangci":
        if not codes:
            # bare //nolint silences every linter golangci runs, security ones included
            return "golangci", frozenset(TOOL_SCOPE["gosec"])
        for code in codes:
            low = code.lower()
            if low == "gosec":
                eff = "gosec"
                cats |= TOOL_SCOPE["gosec"]
            elif low in ("all", "*"):
                eff = "golangci"
                cats |= TOOL_SCOPE["gosec"]
            elif low in GOSEC:
                eff = "gosec"
                cats |= GOSEC[low]
            # govet, staticcheck, errcheck, lll ... are not security linters: no cats
        return eff, frozenset(cats)

    if tool == "gosec":
        if not codes:
            return "gosec", frozenset(TOOL_SCOPE["gosec"])
        for code in codes:
            cats |= GOSEC.get(code.lower(), set())
        return "gosec", frozenset(cats)

    if tool == "bandit":
        if not codes:
            return "bandit", frozenset(TOOL_SCOPE["bandit"])
        for code in codes:
            num = re.sub(r"^[A-Za-z]+", "", code)
            cats |= BANDIT.get(num, set())
        return "bandit", frozenset(cats)

    if tool == "eslint":
        if not codes:
            # a bare eslint-disable covers whatever plugins are configured; the security
            # plugin is the only one that could be meant here
            return "eslint", frozenset(TOOL_SCOPE["security"])
        for code in codes:
            low = code.lower().strip()
            low = low[len("security/"):] if low.startswith("security/") else low
            cats |= ESLINT_SECURITY.get(low, set())
        return "eslint", frozenset(cats)

    if tool == "codeql":
        for code in codes:
            slug = code.strip().lower().rpartition("/")[2]
            cats |= CODEQL.get(slug, set())
        return "codeql", frozenset(cats)

    if tool in ("semgrep", "sonar"):
        # rule ids are project-specific; the directive is recorded, it excuses nothing
        return tool, frozenset()

    return tool, frozenset()


_LINE_COMMENT = re.compile(r"(?://|#)")


def scan(text: str) -> dict:
    """Annotations by the line number they govern: {line: [Annotation, ...]}.

    One directive can govern two lines (the Go/Python "above the statement" convention),
    in which case it appears under both.
    """
    out: dict = {}
    lines = text.splitlines()
    for idx, line in enumerate(lines, start=1):
        if "nolint" not in line and "nosec" not in line and "noqa" not in line \
                and "eslint-disable" not in line and "nosemgrep" not in line \
                and "lgtm[" not in line and "codeql[" not in line \
                and "NOSONAR" not in line and "SuppressWarnings" not in line \
                and "type: ignore" not in line and "@ts-" not in line:
            continue
        for rx, tool, reach in _DIRECTIVES:
            m = rx.search(line)
            if not m:
                continue
            groups = m.groupdict()
            codes = _norm_codes(groups.get("codes") or "")
            eff, cats = _cats_for(tool, codes)
            note = (groups.get("note") or "").strip()
            # `//nolint:gosec // reason` - the reason is the text after the second `//`
            note = re.sub(r"^(?://|#|--|\*/)+\s*", "", note).strip()
            # a directive on a line of its own governs the next statement; one trailing
            # real code governs its own line
            bare = bool(re.match(r"^\s*(?://|#|/\*)", line))
            scope: tuple
            if reach == "next":
                scope = (idx + 1,)
            elif reach == "self":
                scope = (idx,) if not bare else (idx, idx + 1)
            else:                                   # "both"
                scope = (idx, idx + 1) if bare else (idx,)
            ann = Annotation(tool=eff, codes=codes, cats=cats, note=note,
                             line=idx, scope=scope, raw=line.strip()[:200])
            for ln in scope:
                out.setdefault(ln, []).append(ann)
            break
    return out


def covering(annots: dict, line: int, cat: str) -> Annotation | None:
    """The best annotation that excuses `cat` on `line`, or None.

    "Best" means an explained one wins over a bare one, because the caller treats the two
    differently: an explained directive is a recorded decision, a bare one is noise worth
    reading.
    """
    best = None
    for ann in annots.get(line, ()):
        if not ann.security or not ann.covers(cat):
            continue
        if best is None or (ann.explained and not best.explained):
            best = ann
    return best


# ------------------------------------------------------------ explanatory comments
#
# Separate from suppressions: prose that states what a value *is*. `programs.ts` says in a
# comment that its base58 strings are program addresses; that is the difference between a
# leaked credential and a published constant.

PUBLIC_MEANING = re.compile(
    r"\b(?:program\s*(?:address|id|ids)|pubkey|public\s*key|wallet\s*address|"
    r"contract\s*address|mint(?:\s*address)?|token\s*(?:mint|address|id)|"
    r"account\s*address|devnet|testnet|mainnet(?:-beta)?|"
    r"well[\s-]known|publicly\s*(?:known|documented)|not\s+a\s+secret|"
    r"public\s+(?:constant|identifier|value)|anyone\s+can\s+(?:see|read)|"
    r"on[\s-]chain|checksum|fingerprint|git\s*sha|commit\s*hash)\b", re.I)

SECRET_MEANING = re.compile(
    r"\b(?:do\s+not\s+commit|rotate\s+(?:this|before)|real\s+(?:key|token|secret)|"
    r"production\s+(?:key|token|secret|credential)|private\s*key|"
    r"keep\s+(?:this\s+)?secret|sensitive)\b", re.I)

PLACEHOLDER_MEANING = re.compile(
    r"\b(?:example|sample|placeholder|dummy|fake|replace\s+(?:this|with)|"
    r"for\s+(?:testing|demo|illustration)|fixture|stub|synthetic|mock(?:ed)?|canned|"
    r"throwaway|disposable|harness|"
    # "This synthetic value is never a real credential" - the author wrote the answer
    # down and the reader has to be able to hear a negative sentence.
    r"(?:never|not|no)\s+(?:a\s+|an\s+)?real\s+(?:key|token|secret|credential|password)|"
    r"(?:local|offline|test)[\s-]only)\b", re.I)

# A sentence that denies a secret is not a declaration of one. `SECRET_MEANING` reads
# "sensitive" and "real key"; "this is never a real key" contains both and means the
# opposite, so a negation anywhere in the clause before the match disqualifies it.
_NEGATED = re.compile(r"\b(?:never|not|isn't|is\s+not|no|non|nor)\b[^.;]{0,40}$", re.I)


def meaning_near(lines: list, line: int, span: int = 3) -> str:
    """What the comments around `line` claim the value is: public | secret | placeholder | "".

    Looks at the line itself (a trailing comment) and `span` lines either side, which is
    where a developer writes "// program addresses, public" above a block of constants.
    """
    lo = max(1, line - span)
    hi = min(len(lines), line + span)
    window = "\n".join(lines[lo - 1:hi])
    # only prose in comments counts; a string value containing the word "example" is data
    comment_text = []
    for raw in window.splitlines():
        m = _LINE_COMMENT.search(raw)
        if m:
            comment_text.append(raw[m.end():])
        elif "/*" in raw or "*" == raw.strip()[:1]:
            comment_text.append(raw)
    blob = "\n".join(comment_text)
    if not blob.strip():
        return ""
    # Placeholder first, because it is the only one of the three that is ever written as a
    # negative sentence, and a negated claim about a secret is a claim about a stand-in.
    if PLACEHOLDER_MEANING.search(blob):
        return "placeholder"
    hit = SECRET_MEANING.search(blob)
    if hit is not None and not _NEGATED.search(blob[:hit.start()]):
        return "secret"
    if PUBLIC_MEANING.search(blob):
        return "public"
    return ""
