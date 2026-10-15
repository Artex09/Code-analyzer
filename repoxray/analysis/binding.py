"""What does this name actually refer to?

`await exec(command, ["--version"], { env: environment })` was reported as command
injection in eight files of one repository. The name is right and the conclusion is
wrong: in that repository `exec` is

    import { execFile } from "node:child_process";
    export const exec = promisify(execFile);

and execFile hands an argument vector to execvp or CreateProcess with no shell anywhere
in the path. A value containing `;` or `$(...)` arrives at the program as one literal
argument. The same repository has `const execute = promisify(execFile)` on line 18 of a
file where `execute(compiler, ["version"])` was reported as *SQL injection*, because
`execute` is also the name of a database method, and `/^(-?)([0-9]+)$/u.exec(literal)`
was reported as command injection because `exec` is also RegExp.prototype.exec.

A rule that fires on a name is making a claim about identity. Identity is a question with
an answer: read the local definition, and when the name was imported, read the module it
came from. This module answers it.

What it deliberately does not do: resolve through a package in node_modules, or through
more than two files. An unresolved name returns family "" and every caller treats that as
"no opinion" - the rule keeps whatever verdict it had. Being quiet is the only honest
failure mode for a resolver.
"""
from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass

MAX_HOPS = 2
MAX_MODULE_BYTES = 400_000

# Families. A sink's claim about a name is a claim that the name belongs to one of these.
SHELL = "shell"      # the whole string reaches a command interpreter
ARGV = "argv"        # program plus argument vector, no shell
DB = "db"            # a database query method
CODE = "code"        # evaluates source text
REGEX = "regex"      # RegExp.prototype.exec / .test
HTTP = "http"        # an outbound request


@dataclass(frozen=True)
class Bound:
    """A name, and what it was found to be."""
    name: str
    family: str = ""
    detail: str = ""          # the expression it resolves to, e.g. "promisify(execFile)"
    where: str = ""           # "line 18" or "scripts/lib/core.mjs:19"
    hops: int = 0

    def describe(self) -> str:
        if not self.family:
            return ""
        return "`" + self.name + "` is " + self.detail + (
            " (" + self.where + ")" if self.where else "")


# ------------------------------------------------------------------ what an expression is
#
# The base names whose semantics are fixed by the platform. These are the leaves: every
# other answer is reached by rewriting an expression until it lands on one of them.
LEAVES = {
    "exec": SHELL, "execSync": SHELL,
    "execFile": ARGV, "execFileSync": ARGV,
    "spawn": ARGV, "spawnSync": ARGV, "fork": ARGV,
    "eval": CODE, "Function": CODE,
    "query": DB, "execute": DB,
    "fetch": HTTP, "axios": HTTP, "request": HTTP,
}


# The only names worth following into another module: the ones a dangerous-function rule
# can fire on. Following every relative import in a repository meant a disk read per
# candidate extension per import per file - hundreds of thousands of stat calls on a
# 3400-file tree - to answer a question nothing would ever ask.
WATCHED = frozenset(LEAVES) | {
    "execSync", "execFileSync", "spawnSync", "queryRaw", "executeRaw",
    "queryRawUnsafe", "executeRawUnsafe", "raw", "require",
}

_IDENT = r"[A-Za-z_$][\w$]*"
# `promisify(execFile)`, `util.promisify(execFile)`, `pify(execFile)`
_WRAP = re.compile(r"^(?:[\w.$]*\.)?(?:promisify|promisifyAll|pify|denodeify|callbackify)"
                   r"\s*\(\s*(?P<inner>[\w.$]+)\s*\)")
# `execFile.bind(null, …)`, `execFile` on its own, `child_process.execFile`
_PLAIN = re.compile(r"^(?:(?P<ns>[\w$]+)\s*\.\s*)?(?P<base>" + _IDENT + r")\s*"
                    r"(?:\.\s*(?:bind|call|apply)\s*\()?\s*$")
_MEMBER = re.compile(r"^(?:(?P<ns>[\w$]+)\s*\.\s*)?(?P<base>" + _IDENT + r")\b")
# an arrow or function wrapper: `(a, o) => execFile(cmd, a, o)` - the body decides
_BODY_CALL = re.compile(r"\b(?P<base>" + _IDENT + r")\s*\(")

CHILD_PROCESS = re.compile(r"^(?:node:)?child_process$")


def _leaf_of(expr: str, locals_: dict, depth: int) -> tuple:
    """(family, detail) for a right-hand side, resolved through the file's own names."""
    expr = expr.strip().rstrip(";,")
    if not expr or depth > MAX_HOPS:
        return "", ""
    # `const re = /^[0-9]+$/; re.exec(input)` is the same mistake as calling `.exec` on the
    # literal, one assignment removed.
    if _looks_like_regex(expr):
        return REGEX, "a regular expression"
    wrap = _WRAP.match(expr)
    if wrap is not None:
        fam, detail = _leaf_of(wrap.group("inner"), locals_, depth + 1)
        if fam:
            return fam, "a promisified " + detail
        return "", ""
    plain = _PLAIN.match(expr)
    if plain is not None:
        base = plain.group("base")
        ns = plain.group("ns") or ""
        known = locals_.get(base)
        if known is not None and known.family:
            return known.family, known.detail
        if base in LEAVES:
            return LEAVES[base], (ns + "." if ns else "") + base
        return "", ""
    # a wrapper function: whatever its body calls first that we recognise
    if "=>" in expr or expr.startswith("function") or expr.startswith("async"):
        for m in _BODY_CALL.finditer(expr):
            base = m.group("base")
            if base in ("if", "for", "while", "return", "await", "function", "catch"):
                continue
            if base in locals_ and locals_[base].family:
                return locals_[base].family, "a wrapper around " + locals_[base].detail
            if base in LEAVES:
                return LEAVES[base], "a wrapper around " + base
        return "", ""
    return "", ""


# ----------------------------------------------------------------------- finding definitions

_LOCAL_DEF = re.compile(
    r"^[ \t]*(?:export\s+)?(?:const|let|var)\s+(?P<name>" + _IDENT + r")\s*(?::[^=\n]{0,80})?"
    r"=\s*(?P<expr>[^;\n]+)", re.M)
_LOCAL_FN = re.compile(
    r"^[ \t]*(?:export\s+)?(?:async\s+)?function\s*\*?\s*(?P<name>" + _IDENT + r")\s*\(",
    re.M)
MAX_FN_BODY = 600      # a wrapper that long is not a wrapper


def _fn_body(code: str, at: int) -> str:
    """The braces-balanced body of the function declared at `at`, capped."""
    open_at = code.find("{", at)
    if open_at < 0:
        return ""
    depth = 0
    for i in range(open_at, min(len(code), open_at + MAX_FN_BODY)):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return code[open_at + 1:i]
    return ""
# `import { execFile, exec as run } from "node:child_process"`
_IMPORT_NAMED = re.compile(
    r"import\s*(?:type\s+)?\{(?P<names>[^}]*)\}\s*from\s*['\"](?P<spec>[^'\"]+)['\"]")
_REQUIRE_NAMED = re.compile(
    r"(?:const|let|var)\s*\{(?P<names>[^}]*)\}\s*=\s*require\(\s*['\"](?P<spec>[^'\"]+)['\"]")
_IMPORT_STAR = re.compile(
    r"import\s*\*\s*as\s+(?P<alias>" + _IDENT + r")\s*from\s*['\"](?P<spec>[^'\"]+)['\"]")
_EXPORT_LIST = re.compile(r"export\s*\{(?P<names>[^}]*)\}")

_EXTENSIONS = (".mjs", ".js", ".cjs", ".ts", ".mts", ".cts", ".tsx", ".jsx")


def _split_names(blob: str) -> list:
    """[(imported, local)] for a `{ a, b as c }` clause."""
    out = []
    for part in blob.split(","):
        part = part.strip()
        if not part:
            continue
        bits = re.split(r"\s+as\s+", part)
        imported = bits[0].strip()
        local = bits[-1].strip()
        if re.fullmatch(_IDENT, imported) and re.fullmatch(_IDENT, local):
            out.append((imported, local))
    return out


def _candidates(spec: str, path: str) -> list:
    """Repo-relative paths a relative import specifier could mean.

    TypeScript and ESM both write `./lib/core.js` for a file that may be `core.ts` on
    disk, so the extension is replaced as well as appended.
    """
    base = posixpath.normpath(posixpath.join(posixpath.dirname(path), spec))
    if base.startswith(".."):
        return []
    out = [base]
    stem, dot, ext = base.rpartition(".")
    if dot and ("." + ext) in _EXTENSIONS:
        out += [stem + e for e in _EXTENSIONS]
    else:
        out += [base + e for e in _EXTENSIONS]
        out += [base + "/index" + e for e in _EXTENSIONS]
    seen, uniq = set(), []
    for cand in out:
        if cand not in seen:
            seen.add(cand)
            uniq.append(cand)
    return uniq


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _file_locals(code: str) -> dict:
    """{name: Bound} for every local definition in one file, resolved among themselves."""
    locals_: dict = {}
    raw: list = []
    for m in _LOCAL_DEF.finditer(code):
        raw.append((m.group("name"), m.group("expr"), _line_of(code, m.start())))
    # platform names pulled straight in from child_process are leaves for this file
    for rx in (_IMPORT_NAMED, _REQUIRE_NAMED):
        for m in rx.finditer(code):
            spec = m.group("spec")
            if not CHILD_PROCESS.match(spec):
                continue
            for imported, local in _split_names(m.group("names")):
                if imported in LEAVES:
                    locals_[local] = Bound(local, LEAVES[imported],
                                           "child_process." + imported,
                                           "imported from " + spec)
    # A declared function that only forwards: `function exec(cmd, args) { return
    # execFileSync(cmd, args) }` shadows the dangerous name with a safe one.
    for m in _LOCAL_FN.finditer(code):
        name = m.group("name")
        if name not in WATCHED:
            continue
        body = _fn_body(code, m.end())
        if body:
            raw.append((name, "() => {" + body + "}", _line_of(code, m.start())))
    # two passes, so `const exec = promisify(execFile)` resolves whichever order they sit in
    for _ in range(2):
        for name, expr, line in raw:
            if name in locals_ and locals_[name].family:
                continue
            fam, detail = _leaf_of(expr, locals_, 0)
            if fam:
                locals_[name] = Bound(name, fam, detail, "line " + str(line))
    return locals_


def _exported_expr(code: str, want: str) -> tuple:
    """(expr, line) for `export const want = ...` / `export { local as want }`."""
    for m in _LOCAL_DEF.finditer(code):
        if m.group("name") == want and code[max(0, m.start()):m.start() + 40].lstrip() \
                .startswith("export"):
            return m.group("expr"), _line_of(code, m.start())
    for m in _EXPORT_LIST.finditer(code):
        for imported, local in _split_names(m.group("names")):
            # in `export { a as b }` the *local* name is the first one
            if local == want:
                for d in _LOCAL_DEF.finditer(code):
                    if d.group("name") == imported:
                        return d.group("expr"), _line_of(code, d.start())
    return "", 0


def resolve(code: str, lang: str, path: str = "", read=None) -> dict:
    """{name: Bound} for the names in this file whose identity a rule might depend on.

    `read(repo_relative_path)` returns that file's text or "" - it is the only way this
    module touches anything outside the file it was given, and the only thing it reads
    from another file is a single exported definition.
    """
    if lang not in ("javascript", "typescript"):
        return {}
    out = dict(_file_locals(code))

    for rx in (_IMPORT_NAMED, _REQUIRE_NAMED):
        for m in rx.finditer(code):
            spec = m.group("spec")
            if CHILD_PROCESS.match(spec):
                continue              # already handled as a leaf
            pairs = [(imp, loc) for imp, loc in _split_names(m.group("names"))
                     if loc in WATCHED and not (loc in out and out[loc].family)]
            if not pairs:
                continue
            if not spec.startswith("."):
                continue              # a package: not resolved, and not guessed at either
            if read is None or not path:
                continue
            body = ""
            found = ""
            for cand in _candidates(spec, path):
                try:
                    body = read(cand) or ""
                except Exception:                                   # noqa: BLE001
                    body = ""
                if body:
                    found = cand
                    break
            if not body or len(body) > MAX_MODULE_BYTES:
                continue
            their_locals = _file_locals(body)
            for imported, local in pairs:
                if local in out and out[local].family:
                    continue
                expr, line = _exported_expr(body, imported)
                if not expr:
                    continue
                fam, detail = _leaf_of(expr, their_locals, 0)
                if fam:
                    out[local] = Bound(local, fam, detail,
                                       found + ":" + str(line), hops=1)

    for m in _IMPORT_STAR.finditer(code):
        if CHILD_PROCESS.match(m.group("spec")):
            alias = m.group("alias")
            out[alias + ".*"] = Bound(alias, "", "the child_process namespace",
                                      "imported from " + m.group("spec"))
    return out


# ------------------------------------------------------------------- reading a call site

_RECEIVER = re.compile(r"(?P<recv>.*?)\s*\.\s*(?P<base>" + _IDENT + r")\s*$", re.S)


def callee_family(callee: str, bindings: dict) -> Bound | None:
    """What the text of a callee resolves to, or None when nothing is known.

    `callee` is the source text of the called expression: `exec`, `cp.execFile`,
    `/^[0-9]+$/u.exec`, `db.query`. A receiver that is visibly a regular expression
    answers the question on its own - no binding needed, and none would help.
    """
    callee = callee.strip()
    if not callee:
        return None
    member = _RECEIVER.match(callee)
    if member is not None:
        recv = member.group("recv").strip()
        base = member.group("base")
        if base in ("exec", "test") and (recv.startswith("/") or recv.endswith("/")
                                         or _looks_like_regex(recv)):
            return Bound(base, REGEX, "RegExp.prototype." + base
                         + " called on a regular expression literal", "")
        got = bindings.get(recv + ".*")
        if got is not None and base in LEAVES:
            return Bound(base, LEAVES[base], "child_process." + base, got.where)
        held = bindings.get(recv)
        if held is not None and held.family == REGEX and base in ("exec", "test"):
            return Bound(base, REGEX, "RegExp.prototype." + base + " called on "
                         + held.detail, held.where)
        return None
    return bindings.get(callee)


_REGEX_LITERAL = re.compile(r"^/(?:[^/\\\n]|\\.)+/[a-z]*$")


def _looks_like_regex(text: str) -> bool:
    text = text.strip()
    if _REGEX_LITERAL.match(text):
        return True
    return bool(re.match(r"^new\s+RegExp\s*\(", text))
