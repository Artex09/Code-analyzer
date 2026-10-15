"""What a literal *is*, not what its variable is called.

A 44-character base58 string assigned to `bordrless_token` is not a credential - it is a
Solana program address, which is public by construction and printed in the project's own
docs. A name-based rule cannot tell those apart; the encoding and length can.

Three questions live here, each one a thing a pattern match got wrong on a real repository:

* `classify_literal`  - is this string a secret, or a public identifier?
* `redos_shape`       - is this regex actually catastrophic, or just built from a variable?
* `unquoted_expansions` - is this shell variable really unquoted?
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass

# ------------------------------------------------------------------ literal classes

BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_SET = frozenset(BASE58)
HEX_SET = frozenset("0123456789abcdefABCDEF")
B64_SET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")

PLACEHOLDER = re.compile(
    r"^(?:x{3,}|\.{3,}|\*{3,}|-{3,}|_{3,}|0{6,}|1{6,}|a{6,}|z{6,})$|"
    r"(?:your[_\-]?|my[_\-]?|some[_\-]?|the[_\-]?)(?:api|key|token|secret|password|"
    r"client|app|access)|"
    r"\b(?:changeme|change[_\-]?me|replace[_\-]?me|placeholder|example|sample|dummy|"
    r"fake|todo|tbd|xxxx|yyyy|zzzz|redacted|removed|hidden|notreal|not[_\-]?real|"
    # A test harness that needs a client to start hands it a value shaped like a
    # credential and named like one. `OPENAI_API_KEY: "local-fixture-key"` was reported
    # as a hardcoded credential in eight files of one repository; the value says what it
    # is in the word "fixture".
    r"fixture|mock(?:ed)?|stub|synthetic|canned|throwaway|disposable|sentinel|"
    r"local[_\-]?only|offline[_\-]?only|test[_\-]?only|no[_\-]?(?:key|token|secret|auth)|"
    r"unused|ignored|harness|"
    r"insert[_\-]?(?:your|here)|put[_\-]?your|enter[_\-]?your|lorem|foobar|"
    r"deadbeef|cafebabe|abcdef0123|test[_\-]?(?:key|token|secret|password)|"
    # no trailing \b: `changeme123456` is still a placeholder, and the leading \b is
    # what stops these matching inside a longer real value
    r"password123|hunter2|s3cr3t|secret123|letmein)|"
    r"^\s*(?:<[^>]*>|\$\{[^}]*\}|\{\{[^}]*\}\}|%[sdv]|\{\d*\}|#\{[^}]*\})\s*$",
    re.I)

# Credentials whose format pins them down. These are real whatever they are called.
VENDOR = [
    (re.compile(r"^(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}$"), "an AWS access key id"),
    (re.compile(r"^gh[pousr]_[0-9A-Za-z]{20,}$"), "a GitHub token"),
    (re.compile(r"^github_pat_[0-9A-Za-z_]{40,}$"), "a GitHub fine-grained token"),
    (re.compile(r"^xox[baprs]-[0-9A-Za-z-]{10,}$"), "a Slack token"),
    (re.compile(r"^glpat-[0-9A-Za-z_-]{16,}$"), "a GitLab token"),
    (re.compile(r"^(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}$"), "a Stripe key"),
    (re.compile(r"^AIza[0-9A-Za-z_-]{30,}$"), "a Google API key"),
    (re.compile(r"^SG\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{16,}$"), "a SendGrid key"),
    (re.compile(r"^sk-(?:proj-|ant-)?[0-9A-Za-z_-]{20,}$"), "an LLM provider key"),
    (re.compile(r"^(?:npm_|pypi-|dop_v1_|shpat_|shpss_)[0-9A-Za-z_-]{16,}$"),
     "a package-registry or vendor token"),
    (re.compile(r"^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}$"),
     "a signed JWT"),
    (re.compile(r"^-----BEGIN"), "a private key block"),
]

# Shapes that are public by construction. Each one is a thing a scanner has called a secret.
PUBLIC_SHAPES = [
    # Solana / Bitcoin style: 32 raw bytes in base58 is 43-44 chars
    ("base58-pubkey", 43, 44, "a 32-byte base58 public key - a Solana account, program or "
     "mint address, which is public by design"),
    # 20-byte base58 (Bitcoin P2PKH/P2SH addresses, 25-34 chars with version+checksum)
    ("base58-address", 26, 35, "a base58check address - public by design"),
]


@dataclass(frozen=True)
class Literal:
    """A classified string literal."""
    kind: str          # secret | public | placeholder | identifier | unknown
    shape: str         # the recognised encoding, for the explanation
    why: str           # plain English, shown to the user
    entropy: float = 0.0

    @property
    def is_secret(self) -> bool:
        return self.kind == "secret"


def shannon(value: str) -> float:
    """Bits per character. A real random token sits near log2(alphabet); English near 4."""
    if not value:
        return 0.0
    counts: dict = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _charset(value: str) -> str:
    chars = set(value)
    if chars <= HEX_SET:
        return "hex"
    if chars <= BASE58_SET:
        return "base58"
    if chars <= B64_SET:
        return "base64"
    return "mixed"


_SEGMENT = re.compile(r"[-_./ :]+")


def _word_segments(raw: str) -> list:
    """The word-shaped segments of a value, or [] if it is not word-shaped.

    Word-shaped means: at least two segments, every one of them nothing but letters, none
    of them longer than a long English word. `local-fixture-key` qualifies;
    `billing-key-4eC39HqLyjWDarjt` does not, because its last segment carries digits
    and mixed case, which is what a generator produces and a typist does not.
    (The example deliberately avoids a real provider prefix: a live-looking key in a
    docstring is enough to make a push-protection scanner reject the commit.)
    """
    parts = [p for p in _SEGMENT.split(raw) if p]
    if len(parts) < 2 or len(parts) > 8:
        return []
    for part in parts:
        if not part.isalpha() or len(part) > 14:
            return []
    return parts


def classify_literal(value: str, name: str = "", declared: str = "") -> Literal:
    """Decide what a string literal is.

    `name` is the identifier it was assigned to, used only to break ties - never to
    override a shape. `declared` is what a nearby comment says it is ("public", "secret",
    "placeholder"), which beats every heuristic because a human wrote it down.
    """
    raw = value.strip()
    if not raw:
        return Literal("placeholder", "empty", "the value is an empty string")

    # 1. A format that pins the credential down. Even a comment cannot talk this away.
    for rx, label in VENDOR:
        if rx.match(raw):
            return Literal("secret", "vendor", "the value has the exact shape of " + label,
                           shannon(raw))

    # 2. Base58 private keys are a real secret and sit right next to public addresses in
    #    the same alphabet, so the length and version byte have to be checked first.
    cs = _charset(raw)
    if cs == "base58" and len(raw) in (51, 52) and raw[0] in "5KL":
        return Literal("secret", "base58-wif",
                       "the value is a 51-52 character base58 string beginning with "
                       + raw[0] + ", which is the WIF encoding of a private key",
                       shannon(raw))

    # 3. Shapes that have to be read before the placeholder check, because they can
    #    legitimately contain a word the placeholder list looks for:
    #    `postgres://user:hunter2@db/x` is a real leaked password, and
    #    `https://api.example.com/v1` is an ordinary URL.
    if re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I):
        if re.search(r"://[^/\s:@]+:[^/\s@]+@", raw):
            return Literal("secret", "url-userinfo",
                           "the value is a URL with a password in its userinfo",
                           shannon(raw))
        return Literal("identifier", "url",
                       "the value is a URL, not a credential", shannon(raw))
    if re.match(r"^0x[0-9a-fA-F]{40}$", raw):
        return Literal("public", "eth-address",
                       "the value is a 0x-prefixed 40-hex-digit Ethereum address, which "
                       "is public by design", shannon(raw))

    # 4. What the author said it is.
    if declared == "placeholder":
        return Literal("placeholder", cs, "a comment beside it calls it an example or "
                                          "placeholder value")
    if declared == "secret":
        return Literal("secret", cs, "a comment beside it says it is sensitive",
                       shannon(raw))

    # 5. Obvious non-values.
    if PLACEHOLDER.search(raw):
        return Literal("placeholder", cs,
                       "the value reads as a placeholder rather than a live credential")
    if len(set(raw)) <= 2:
        return Literal("placeholder", cs, "the value is a repeated character")

    # 6. Public shapes.
    if cs == "base58":
        for shape, lo, hi, why in PUBLIC_SHAPES:
            if lo <= len(raw) <= hi:
                if declared == "public":
                    why += ", and a comment beside it says so"
                return Literal("public", shape, "the value is " + why, shannon(raw))

    if cs == "hex":
        low = raw.lower()
        if len(raw) == 40:
            return Literal("public", "hex40",
                           "the value is 40 hex characters, the shape of a git commit sha "
                           "or a SHA-1 digest, not of a credential", shannon(raw))
        if len(raw) == 64:
            return Literal("public", "hex64",
                           "the value is 64 hex characters, the shape of a SHA-256 digest; "
                           "it may also be a raw 32-byte key, so check what reads it",
                           shannon(raw))
        if len(raw) in (32, 8, 16):
            return Literal("identifier", "hex" + str(len(raw)),
                           "the value is a short hex string, the shape of a digest or id "
                           "rather than a credential", shannon(raw))

    if re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", raw):
        return Literal("identifier", "uuid",
                       "the value is a UUID, which identifies rather than authenticates",
                       shannon(raw))

    if re.match(r"^v?\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.\-]+)?$", raw):
        return Literal("identifier", "version", "the value is a version string")

    if declared == "public":
        return Literal("public", cs,
                       "a comment beside it says the value is public", shannon(raw))

    # 7. Nothing recognised it. Fall back to entropy plus how specific the name is.
    #
    # Shannon entropy over seventeen characters is not a randomness test. It called
    # `local-fixture-key` "high-entropy" at 3.68 bits per character, which is roughly
    # what any English word scores. Before trusting that number, check whether the value
    # spells words: a generated credential does not, because the generator has no
    # vocabulary. A value that does spell words was typed by a person, and what they
    # meant by it is not something entropy can answer - so it is left open rather than
    # called a secret.
    words = _word_segments(raw)
    if words:
        return Literal("unknown", cs,
                       "the value spells words (" + ", ".join(words[:4])
                       + "), so it was typed rather than generated - a credential "
                         "generator has no vocabulary. Read it and decide; entropy "
                         "cannot tell a passphrase from a stand-in", shannon(raw))

    ent = shannon(raw)
    low_name = name.lower()
    strong_name = bool(re.search(
        r"password|passwd|pwd|secret|private[_\-]?key|client[_\-]?secret|"
        r"api[_\-]?key|apikey|access[_\-]?key|auth[_\-]?key|credential|"
        r"session[_\-]?key|signing[_\-]?key|encryption[_\-]?key", low_name))
    # `token`, `key`, `id` on their own are ambiguous: a program token id reads the same
    weak_name = bool(re.search(r"\btoken\b|\bkey\b|\bid\b|\baddress\b|\bmint\b", low_name))

    if ent >= 3.2 and len(raw) >= 16 and strong_name:
        return Literal("secret", cs,
                       "a high-entropy string assigned to a name that means a credential",
                       ent)
    if ent >= 4.0 and len(raw) >= 24 and not weak_name:
        return Literal("secret", cs,
                       "a high-entropy string with no recognised public format", ent)
    if ent < 2.6:
        return Literal("identifier", cs,
                       "the value has too little entropy to be a generated credential",
                       ent)
    return Literal("unknown", cs,
                   "the value could not be placed: " + str(len(raw)) + " "
                   + cs + " characters at " + format(ent, ".1f")
                   + " bits per character", ent)


# --------------------------------------------------------------------- regex shape
#
# `new RegExp(var)` is reported as ReDoS. Two things have to hold for that to be true: the
# pattern must be able to backtrack catastrophically, and attacker input must reach the
# *subject*. A fixed skeleton with a name spliced into it - `^${name}:\s*(\S+)` - is
# neither, and was reported four times in one CLI.

# nested quantifier: a group that is itself quantified and contains a quantifier
_NESTED_QUANT = re.compile(r"\((?:[^()\\]|\\.)*[+*}](?:[^()\\]|\\.)*\)\s*[+*]|"
                           r"\((?:[^()\\]|\\.)*\)\s*[+*]\s*[+*]")
# overlapping alternation under a quantifier: (a|a)* , (\w|\d)+
_ALT_QUANT = re.compile(r"\((?:[^()\\]|\\.)*\|(?:[^()\\]|\\.)*\)\s*[+*]")
# a hole with nothing around it: the caller writes the whole pattern, quantifiers included
_WHOLE_HOLE = re.compile(r"^[\^]?\x01[$]?$")
# two unbounded quantifiers in a row over classes that can overlap, which is the quadratic
# shape rather than the exponential one
_ADJACENT = re.compile(r"(\\[wWsSdD]|\[[^\]]+\]|\.)[+*]\s*(\\[wWsSdD]|\[[^\]]+\]|\.)[+*]")

# Whether two adjacent quantifiers can backtrack against each other is decided by whether
# their character classes overlap, so the classes are expanded rather than compared by
# name. `\s*[A-Za-z0-9_]+` looks like two quantifiers in a row and is perfectly safe,
# because no character is both whitespace and a word character.
_PRINTABLE = frozenset(chr(c) for c in range(32, 127))
_CLASS = {
    r"\w": frozenset("abcdefghijklmnopqrstuvwxyz"
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"),
    r"\d": frozenset("0123456789"),
    r"\s": frozenset(" \t\n\r\f\v"),
}
_CLASS[r"\W"] = _PRINTABLE - _CLASS[r"\w"]
_CLASS[r"\D"] = _PRINTABLE - _CLASS[r"\d"]
_CLASS[r"\S"] = _PRINTABLE - _CLASS[r"\s"]
_RANGE = re.compile(r"(.)-(.)")


def _class_chars(token: str):
    """The characters a single-class token can match, or None for "any character"."""
    if token in _CLASS:
        return _CLASS[token]
    if token == ".":
        return None
    if token.startswith("[") and token.endswith("]"):
        body = token[1:-1]
        negate = body.startswith("^")
        if negate:
            body = body[1:]
        chars: set = set()
        for esc, expanded in _CLASS.items():
            if esc in body:
                chars |= expanded
                body = body.replace(esc, "")
        for m in _RANGE.finditer(body):
            lo, hi = ord(m.group(1)), ord(m.group(2))
            if lo <= hi and hi - lo < 256:
                chars |= {chr(c) for c in range(lo, hi + 1)}
        body = _RANGE.sub("", body)
        chars |= set(body.replace("\\", ""))
        return (_PRINTABLE - chars) if negate else frozenset(chars)
    return None


@dataclass(frozen=True)
class RegexShape:
    """What the *skeleton* of a runtime-built regex guarantees.

    catastrophic - the literal parts already nest quantifiers: exponential backtracking,
                   whatever is spliced in
    polynomial   - two adjacent unbounded quantifiers over overlapping classes: quadratic
    injectable   - the caller supplies the whole pattern, so they choose the shape
    dynamic      - a fixed skeleton with a value spliced in; the skeleton is safe, and the
                   value can still change what the regex accepts
    benign       - a constant pattern with a safe shape
    """
    risk: str
    why: str
    interpolated: bool = False


def redos_shape(template: str, dynamic_parts: tuple = ()) -> RegexShape:
    """Judge a regex built at runtime.

    `template` is the source text of the pattern with its interpolations left in place
    (`^${name}:\\s*(\\S+)`). `dynamic_parts` names the expressions spliced in, if known.
    """
    body = template
    holes = []
    for rx in (re.compile(r"\$\{([^}]*)\}"), re.compile(r"\"\s*\+\s*(\w[\w.]*)\s*\+\s*\""),
               re.compile(r"%s|\{\}|\{\d+\}")):
        for m in rx.finditer(body):
            holes.append(m.group(1) if m.groups() else m.group(0))
    interpolated = bool(holes) or bool(dynamic_parts)
    # treat each hole as one opaque literal character for shape analysis: whatever the
    # value is, it cannot add a quantifier unless it is itself a pattern
    skeleton = re.sub(r"\$\{[^}]*\}", "\x01", body)
    skeleton = re.sub(r"%s|\{\}|\{\d+\}", "\x01", skeleton)

    if _NESTED_QUANT.search(skeleton) or _ALT_QUANT.search(skeleton):
        return RegexShape("catastrophic",
                          "the pattern nests a quantifier inside a quantified group, which "
                          "is the shape that backtracks exponentially", interpolated)
    if interpolated and _WHOLE_HOLE.match(skeleton.strip()):
        return RegexShape("injectable",
                          "the whole pattern is supplied by the caller, so whoever "
                          "provides it chooses the shape - including a catastrophic one",
                          True)
    adjacent = _adjacent_overlap(skeleton)
    if adjacent:
        return RegexShape("polynomial",
                          "the pattern puts two unbounded quantifiers in a row over "
                          "classes that overlap (" + adjacent + "), which backtracks "
                          "quadratically on a long subject", interpolated)
    if not interpolated:
        return RegexShape("benign",
                          "the pattern is a constant with no ambiguous quantifier, so "
                          "neither the pattern nor its matching time can be influenced",
                          False)
    # A fixed skeleton with a value spliced in. The value cannot introduce a quantifier
    # unless it is itself a pattern, so this is not ReDoS; what it can do is change what
    # the regex accepts, which matters only if the value is untrusted.
    return RegexShape("dynamic",
                      "the pattern is a fixed skeleton with "
                      + (", ".join(sorted(set(h for h in holes if h))[:3])
                         or "a value")
                      + " spliced into it, and the skeleton has no quantifier that can "
                        "backtrack badly", True)


def _adjacent_overlap(skeleton: str) -> str:
    """The first pair of adjacent unbounded quantifiers whose classes can overlap.

    Overlap is what matters: `\\s*[A-Za-z]+` is two quantifiers in a row and cannot
    backtrack, because nothing is both whitespace and a letter. `\\w+\\w+` can.
    """
    for m in _ADJACENT.finditer(skeleton):
        left = _class_chars(m.group(1))
        right = _class_chars(m.group(2))
        if left is None or right is None:          # `.` overlaps with everything
            return m.group(0)
        if left & right:
            return m.group(0)
    return ""


# ------------------------------------------------------------------- shell quoting
#
# `sh.var_cmd` is titled "unquoted variable in command" and its explanation is about word
# splitting, but the pattern matched `rm -f "$file"` - which is quoted, and splits nothing.

# `[[ ... ]]` is a bash keyword, not a command: the shell does no word splitting or glob
# expansion inside it, so `[[ -n $x ]]` is safe however exotic $x is. `[ ... ]` is the
# `test` *builtin* and does split, so only the double-bracket form is removed.
_DBRACKET = re.compile(r"\[\[.*?\]\]", re.S)
# `${x:+"$x"}` and `${x:-"$default"}` quote their alternate word, which is the standard
# idiom for "pass this argument only if it is set"
_GUARDED_WORD = re.compile(r"^[A-Za-z_]\w*(?:\[[^\]]*\])?:[-+=?]\s*\"")


def unquoted_expansions(line: str) -> list:
    """Variable expansions in `line` that the shell will word-split, in order.

    Walks the text tracking quote state, which a regex cannot do, and models the three
    things that decide the answer and are invisible to a pattern:

    * `'$a'` is not an expansion at all, `"$a"` is one word, `$a` is split
    * `$( ... )` starts a fresh quoting context, so the inner `"` in
      `"$(dirname "$snapshot")"` does not unquote `$snapshot`
    * `"${arr[@]}"` is the correct way to pass a list and must not be reported; the bug is
      the unquoted `${arr[@]}`, which splits each element again
    """
    out: list = []
    _walk(_DBRACKET.sub(" ", line), False, out)
    return out


def _walk(text: str, in_double: bool, out: list, depth: int = 0) -> None:
    if depth > 6:
        return
    i = 0
    n = len(text)
    in_single = False
    while i < n:
        ch = text[i]
        if ch == "\\" and not in_single:
            i += 2
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            i += 1
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            i += 1
            continue
        if ch == "#" and not in_single and not in_double and (i == 0 or
                                                              text[i - 1].isspace()):
            break                                   # a comment: nothing after it runs
        if ch == "$" and not in_single:
            # command substitution: a nested context with its own quoting
            if text.startswith("$(", i):
                end = _match_paren(text, i + 1)
                if end > 0:
                    _walk(text[i + 2:end], False, out, depth + 1)
                    i = end + 1
                    continue
            m = re.match(r"\$(?:\{([^}]*)\}|([A-Za-z_]\w*)|([@*#?!$0-9]))", text[i:])
            if m:
                body = m.group(1) or m.group(2) or m.group(3) or ""
                if not in_double and not _GUARDED_WORD.match(body):
                    out.append(body)
                i += m.end()
                continue
        i += 1


def _match_paren(text: str, start: int) -> int:
    """Index of the `)` closing the `(` at `start`, or -1."""
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def shell_word_split_risk(line: str) -> tuple:
    """(risky_names, why) for a command line. Empty list means the quoting is correct."""
    names = unquoted_expansions(line)
    if not names:
        return [], ("every expansion on this line is either inside double quotes or "
                    "inside `[[ ]]`, where the shell does no word splitting or globbing")
    return names, ("$" + ", $".join(sorted(set(names))[:4])
                   + " expands outside double quotes, so its value is split on whitespace "
                     "and globbed before the command sees it")
