"""Turn an import statement into a path in this repository.

Cross-file taint tracking is only as good as the link between "the name in this file" and
"the function in that file", so the strength of each link is recorded and travels with the
finding:

  import        - the specifier resolved to an actual file on disk (./util -> lib/util.js)
  same-package  - the two files share a namespace by language rule (Go directory, PHP include)
  name          - nothing resolved, but exactly one file in the repo defines that name

Only the first two are treated as evidence. A `name` link is a guess, and a finding that
depends on one is reported at reduced confidence and says so.

Imports are read with regexes over comment-stripped source rather than from the parse tree.
That is deliberate: import syntax is simple and regular in every language here, the patterns
survive a file with a syntax error elsewhere, and it avoids seven more grammar-specific
traversals for no extra precision.
"""
from __future__ import annotations

import posixpath
import re

JS_EXT = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte")
PY_EXT = (".py", ".pyi")
MAX_TARGETS = 4


class RepoIndex:
    """Path lookups over the scanned file list."""

    def __init__(self, paths) -> None:
        self.paths = set()
        self.by_dir: dict = {}
        self.by_stem: dict = {}      # "utils" -> ["lib/utils.js", "web/utils.py"]
        for raw in paths:
            path = raw.replace("\\", "/")
            self.paths.add(path)
            self.by_dir.setdefault(posixpath.dirname(path), []).append(path)
            stem = posixpath.splitext(posixpath.basename(path))[0]
            self.by_stem.setdefault(stem, []).append(path)

    # ----------------------------------------------------------- per language

    def resolve(self, lang: str, from_path: str, spec: str, kind: str) -> list:
        from_path = from_path.replace("\\", "/")
        spec = spec.strip()
        if not spec:
            return []
        if lang in ("javascript", "typescript", "vue", "svelte", "astro"):
            return self._js(from_path, spec)
        if lang == "python":
            return self._py(from_path, spec)
        if lang == "php":
            return self._php(from_path, spec, kind)
        if lang == "ruby":
            return self._ruby(from_path, spec, kind)
        if lang == "go":
            return self._go(from_path, spec)
        if lang in ("java", "kotlin", "csharp"):
            return self._class(spec, lang)
        return []

    def _exists(self, path: str) -> bool:
        return path in self.paths

    def _js(self, from_path: str, spec: str) -> list:
        bases = []
        if spec.startswith("."):
            base = posixpath.normpath(posixpath.join(posixpath.dirname(from_path), spec))
            if base.startswith(".."):
                return []
            bases.append(base)
        elif "/" in spec.strip("/"):
            # A bare specifier with a slash can still be our own code: node's own
            # `internal/fs/utils`, a tsconfig path alias, a monorepo workspace. Required to
            # contain a slash so that `fs` never resolves to a repo file called fs.js.
            spec = spec.lstrip("/")
            bases += [spec] + [root + "/" + spec
                               for root in ("lib", "src", "app", "packages")]
        else:
            return []
        out = []
        for base in bases:
            for cand in [base] + [base + e for e in JS_EXT] \
                    + [base + "/index" + e for e in JS_EXT]:
                if self._exists(cand):
                    out.append((cand, "import"))
            if out:
                break
        return out[:MAX_TARGETS]

    def _py(self, from_path: str, spec: str) -> list:
        dots = len(spec) - len(spec.lstrip("."))
        rest = spec.lstrip(".").replace(".", "/")
        roots = []
        if dots:
            node = posixpath.dirname(from_path)
            for _ in range(dots - 1):
                node = posixpath.dirname(node)
            roots = [node]
        else:
            # an absolute import can be rooted at the repo, at a src/ layout, or anywhere
            # above the importing file - try each, nearest first
            node = posixpath.dirname(from_path)
            while node:
                roots.append(node)
                node = posixpath.dirname(node)
            roots.append("")
        out = []
        for root in roots:
            base = posixpath.normpath(posixpath.join(root, rest)) if root else rest
            for ext in PY_EXT:
                if self._exists(base + ext):
                    out.append((base + ext, "import"))
            if self._exists(base + "/__init__.py"):
                out.append((base + "/__init__.py", "import"))
            if out:
                break
        return out[:MAX_TARGETS]

    def _php(self, from_path: str, spec: str, kind: str) -> list:
        if kind == "class":
            return self._class(spec, "php")
        spec = spec.replace("__DIR__", ".").lstrip("/")
        base = posixpath.normpath(posixpath.join(posixpath.dirname(from_path), spec))
        out = []
        for cand in (base, spec, base + ".php", spec + ".php"):
            if self._exists(cand):
                out.append((cand, "import"))
        return out[:MAX_TARGETS]

    def _ruby(self, from_path: str, spec: str, kind: str) -> list:
        base = posixpath.normpath(posixpath.join(posixpath.dirname(from_path), spec))
        out = []
        for cand in (base + ".rb", base, spec + ".rb", "lib/" + spec + ".rb"):
            if self._exists(cand):
                out.append((cand, "import" if kind == "relative" else "name"))
        return out[:MAX_TARGETS]

    def _go(self, from_path: str, spec: str) -> list:
        """Match the tail of an import path against a directory, then take its .go files."""
        tail = spec.rstrip("/").split("/")[-1]
        if not tail:
            return []
        out = []
        for directory, files in self.by_dir.items():
            if directory.split("/")[-1] != tail:
                continue
            for path in files:
                if path.endswith(".go"):
                    out.append((path, "import"))
        return out[:MAX_TARGETS]

    def _class(self, spec: str, lang: str) -> list:
        """`import com.acme.Widget` / `use App\\Service\\Widget` -> a file named Widget."""
        name = re.split(r"[.\\]", spec.strip().rstrip(";"))[-1]
        if not name or name in ("*", "_"):
            return []
        ext = {"java": ".java", "kotlin": ".kt", "csharp": ".cs", "php": ".php"}.get(lang, "")
        out = []
        for path in self.by_stem.get(name, []):
            if not ext or path.endswith(ext):
                out.append((path, "import"))
        return out[:MAX_TARGETS]

    def same_package(self, lang: str, from_path: str) -> list:
        """Files that share a namespace with this one without any import statement."""
        if lang != "go":
            return []
        here = posixpath.dirname(from_path.replace("\\", "/"))
        return [(p, "same-package") for p in self.by_dir.get(here, [])
                if p != from_path and p.endswith(".go")]


# ------------------------------------------------------------ import reading

def extract_imports(code: str, spec) -> list:
    """[(kind, specifier, {local alias: name in the other file})] for one file."""
    out = []
    seen = set()
    for rule in spec.imports:
        try:
            rx = re.compile(rule.pattern, re.M)
        except re.error:                                     # pragma: no cover
            continue
        for m in rx.finditer(code):
            groups = m.groupdict()
            target = (groups.get("spec") or "").strip()
            if not target:
                continue
            aliases: dict = {}
            alias = (groups.get("alias") or "").strip()
            if alias:
                aliases[alias] = alias
            for piece in (groups.get("names") or "").split(","):
                piece = piece.strip().strip("{}").strip()
                if not piece or piece == "*":
                    continue
                parts = re.split(r"\s+as\s+", piece)
                remote = parts[0].strip()
                local = parts[-1].strip()
                if re.fullmatch(r"[\w$]+", remote) and re.fullmatch(r"[\w$]+", local):
                    aliases[local] = remote
            if not aliases:
                # a bare `require('./x')` or `use A\B\C` still names the module itself
                stem = posixpath.splitext(posixpath.basename(target.rstrip("/")))[0]
                stem = re.split(r"[\\.]", stem)[-1]
                if re.fullmatch(r"[\w$]+", stem or ""):
                    aliases[stem] = stem
            key = (rule.kind, target, tuple(sorted(aliases.items())))
            if key in seen:
                continue
            seen.add(key)
            out.append((rule.kind, target, aliases))
            if len(out) > 400:
                return out
    return out


def extract_bindings(code: str, spec) -> list:
    """[(field name, class name)] for fields that hold an instance of an imported class."""
    out = []
    seen = set()
    for pattern in spec.bindings:
        try:
            rx = re.compile(pattern, re.M)
        except re.error:                                     # pragma: no cover
            continue
        for m in rx.finditer(code):
            name = (m.groupdict().get("name") or "").strip()
            type_name = (m.groupdict().get("type") or "").strip()
            if not name or not type_name or name == type_name:
                continue
            if (name, type_name) in seen:
                continue
            seen.add((name, type_name))
            out.append((name, type_name))
            if len(out) > 200:
                return out
    return out


def extract_exports(code: str, spec) -> tuple:
    """Names this file hands out, for the name-based fallback link."""
    names: set = set()
    for pattern in spec.exports:
        try:
            rx = re.compile(pattern, re.M)
        except re.error:                                     # pragma: no cover
            continue
        for m in rx.finditer(code):
            raw = m.group(1) if m.groups() else ""
            for piece in raw.split(","):
                piece = re.split(r"\s+as\s+", piece.strip())[-1].strip()
                if re.fullmatch(r"[\w$]+", piece or ""):
                    names.add(piece)
            if len(names) > 300:
                return tuple(sorted(names))
    return tuple(sorted(names))
