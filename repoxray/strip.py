"""Blank out comments before pattern matching, keeping every byte offset intact.

Prose is not code. `// cannot use execvp()` and `the numbering system (0..n)` are English, and
matching them as sinks was the single largest source of false positives - a doc-comment-heavy
C/C++ tree produced thousands of them.

Comments are replaced with spaces rather than removed, so line numbers and offsets computed on
the stripped text still address the original file. String literals are deliberately LEFT ALONE:
plenty of real findings live inside strings (SQL fragments, hardcoded secrets, shell commands),
and they are tracked only so that a `//` inside "https://..." is not mistaken for a comment.
"""
from __future__ import annotations

# line: comment starters; block: (open, close); quotes: string delimiters
# boundary: the line marker only counts at the start of a line or after whitespace,
#           which keeps shell's $# and ${#x} out of it
C_LIKE = {"line": ("//",), "block": ("/*", "*/"), "quotes": "\"'`", "boundary": False}
HASH = {"line": ("#",), "block": None, "quotes": "\"'", "boundary": True}
SQL = {"line": ("--",), "block": ("/*", "*/"), "quotes": "\"'", "boundary": True}
LUA = {"line": ("--",), "block": ("--[[", "]]"), "quotes": "\"'", "boundary": True}
HTML = {"line": (), "block": ("<!--", "-->"), "quotes": "", "boundary": False}
BATCH = {"line": ("::", "rem ", "REM "), "block": None, "quotes": "\"", "boundary": True}

SPECS = {
    # c-family and everything that borrowed its syntax
    "c": C_LIKE, "cpp": C_LIKE, "objc": C_LIKE, "java": C_LIKE, "kotlin": C_LIKE,
    "scala": C_LIKE, "groovy": C_LIKE, "gradle": C_LIKE, "javascript": C_LIKE,
    "typescript": C_LIKE, "vue": C_LIKE, "svelte": C_LIKE, "astro": C_LIKE,
    "csharp": C_LIKE, "go": C_LIKE, "rust": C_LIKE, "swift": C_LIKE, "dart": C_LIKE,
    "php": C_LIKE, "solidity": C_LIKE, "css": {"line": ("//",), "block": ("/*", "*/"),
                                               "quotes": "\"'", "boundary": False},
    "json": {"line": ("//",), "block": ("/*", "*/"), "quotes": "\"", "boundary": False},
    "terraform": {"line": ("#", "//"), "block": ("/*", "*/"), "quotes": "\"", "boundary": True},
    "hcl": {"line": ("#", "//"), "block": ("/*", "*/"), "quotes": "\"", "boundary": True},
    "proto": C_LIKE, "protobuf": C_LIKE, "graphql": HASH, "zig": C_LIKE, "nim": HASH,

    # hash-comment family
    "python": HASH, "ruby": HASH, "shell": HASH, "perl": HASH, "r": HASH, "julia": HASH,
    "yaml": HASH, "toml": HASH, "ini": HASH, "make": HASH, "cmake": HASH,
    "dockerfile": HASH, "powershell": HASH, "properties": HASH, "requirements": HASH,
    "nginx": HASH, "apache": HASH, "config": HASH, "elixir": HASH, "dotenv": HASH,

    "sql": SQL, "lua": LUA, "batch": BATCH,
    "html": HTML, "xml": HTML, "markdown": HTML, "jinja": HTML, "twig": HTML,
    "handlebars": HTML, "ejs": HTML, "blade": HTML,
}


def _blank(buf: list, start: int, end: int) -> None:
    """Overwrite a span with spaces, leaving newlines so line numbers survive."""
    for i in range(start, end):
        if buf[i] != "\n":
            buf[i] = " "


def strip_comments(text: str, lang: str) -> str:
    """Return text with comment bodies blanked. Unknown languages come back untouched."""
    spec = SPECS.get(lang)
    if not spec or not text:
        return text

    line_markers = spec["line"]
    block = spec["block"]
    quotes = spec["quotes"]
    boundary = spec["boundary"]

    buf = list(text)
    n = len(text)
    i = 0
    in_str = ""
    escaped = False

    while i < n:
        ch = text[i]

        if in_str:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == in_str:
                in_str = ""
            elif ch == "\n" and in_str in "\"'":
                in_str = ""          # unterminated literal: do not swallow the whole file
            i += 1
            continue

        if ch in quotes:
            in_str = ch
            i += 1
            continue

        if block and text.startswith(block[0], i):
            end = text.find(block[1], i + len(block[0]))
            end = n if end == -1 else end + len(block[1])
            _blank(buf, i, end)
            i = end
            continue

        hit = None
        for marker in line_markers:
            if text.startswith(marker, i):
                if boundary and i > 0 and text[i - 1] not in " \t\n\r;":
                    continue         # $# in shell, a--b in sql, not a comment
                hit = marker
                break
        if hit:
            end = text.find("\n", i)
            end = n if end == -1 else end
            _blank(buf, i, end)
            i = end
            continue

        i += 1

    return "".join(buf)


def string_spans(text: str, lang: str) -> list:
    """[(start, end)] over the *interiors* of string literals.

    For the handful of rules whose whole claim is "this file executes code", a match
    inside a string literal is text being assembled, not code being run:

        command: `node -e "eval(Buffer.from('${encoded}','base64').toString('utf8'))"`

    was reported as an eval in the file that builds that command line. The eval is in the
    child process, and the only thing this file does is quote it.

    Template-literal interpolation is excluded from the spans, because `${...}` is real
    code in this file and a rule matching inside a hole is matching code.
    """
    spec = SPECS.get(lang)
    if not spec or not text:
        return []
    quotes = spec["quotes"]
    block = spec["block"]
    line_markers = spec["line"]
    boundary = spec["boundary"]
    spans: list = []
    n = len(text)
    i = 0
    while i < n:
        ch = text[i]
        if block and text.startswith(block[0], i):
            end = text.find(block[1], i + len(block[0]))
            i = n if end == -1 else end + len(block[1])
            continue
        marker = next((mk for mk in line_markers if text.startswith(mk, i)), None)
        if marker and not (boundary and i > 0 and text[i - 1] not in " \t\n\r;"):
            end = text.find("\n", i)
            i = n if end == -1 else end
            continue
        if ch in quotes:
            start = i + 1
            j = start
            escaped = False
            while j < n:
                cj = text[j]
                if escaped:
                    escaped = False
                elif cj == "\\":
                    escaped = True
                elif cj == ch:
                    break
                elif cj == "\n" and ch in "\"'":
                    break            # unterminated literal
                elif ch == "`" and cj == "$" and text.startswith("${", j):
                    # close the span before the hole, reopen after its matching brace
                    depth = 0
                    k = j + 1
                    while k < n:
                        if text[k] == "{":
                            depth += 1
                        elif text[k] == "}":
                            depth -= 1
                            if depth == 0:
                                break
                        k += 1
                    if j > start:
                        spans.append((start, j))
                    j = k + 1
                    start = j
                    continue
                j += 1
            if j > start:
                spans.append((start, j))
            i = j + 1
            continue
        i += 1
    return spans


def inside(spans: list, pos: int) -> bool:
    """Is this offset inside one of the spans? Linear; the lists here are short."""
    for start, end in spans:
        if start <= pos < end:
            return True
        if start > pos:
            return False
    return False


def comment_ratio(text: str, stripped: str) -> float:
    """Share of non-whitespace characters that lived in comments. Diagnostics only."""
    if not text:
        return 0.0
    before = sum(1 for c in text if not c.isspace())
    after = sum(1 for c in stripped if not c.isspace())
    return round((before - after) / before, 3) if before else 0.0
