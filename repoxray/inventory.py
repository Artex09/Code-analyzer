"""Walk a source tree and classify every file before any scoring happens."""
from __future__ import annotations

import re
from pathlib import Path

MAX_READ_BYTES = 1_500_000      # bigger files get truncated for pattern matching
MAX_FILES = 20_000              # hard stop so a monorepo cannot hang the UI

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", "vendor", "third_party",
    "__pycache__", ".venv", "venv", "env", ".env.d", "site-packages", ".tox", ".nox",
    "dist", "build", "out", "target", ".next", ".nuxt", ".svelte-kit", ".parcel-cache",
    ".idea", ".vscode", ".gradle", ".mvn", ".terraform", ".serverless", "coverage",
    "htmlcov", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".cache", ".yarn",
    "Pods", "DerivedData", ".dart_tool", "cmake-build-debug", "bin", "obj",
}

BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg", ".tiff", ".psd",
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".webm", ".flac", ".ogg",
    ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war", ".ear",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".exe", ".dll", ".so", ".dylib", ".o", ".a", ".lib", ".obj", ".pyc", ".pyo",
    ".class", ".wasm", ".bin", ".dat", ".db", ".sqlite", ".sqlite3", ".mo", ".pack",
}

LANG_BY_EXT = {
    ".py": "python", ".pyw": "python", ".pyi": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".vue": "vue", ".svelte": "svelte", ".astro": "astro",
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".scala": "scala", ".groovy": "groovy",
    ".go": "go", ".rs": "rust", ".rb": "ruby", ".erb": "ruby", ".rake": "ruby",
    ".php": "php", ".phtml": "php", ".php5": "php", ".inc": "php",
    ".cs": "csharp", ".vb": "vbnet", ".fs": "fsharp",
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp",
    ".m": "objc", ".mm": "objc", ".swift": "swift", ".dart": "dart",
    ".pl": "perl", ".pm": "perl", ".lua": "lua", ".r": "r", ".jl": "julia",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".ksh": "shell",
    ".ps1": "powershell", ".psm1": "powershell", ".bat": "batch", ".cmd": "batch",
    ".sql": "sql", ".graphql": "graphql", ".gql": "graphql", ".proto": "protobuf",
    ".html": "html", ".htm": "html", ".hbs": "handlebars", ".ejs": "ejs", ".pug": "pug",
    ".jinja": "jinja", ".jinja2": "jinja", ".j2": "jinja", ".twig": "twig", ".blade": "blade",
    ".css": "css", ".scss": "css", ".sass": "css", ".less": "css",
    ".json": "json", ".yaml": "yaml", ".yml": "yaml", ".toml": "toml", ".ini": "ini",
    ".xml": "xml", ".xsl": "xml", ".plist": "xml", ".properties": "properties",
    ".env": "dotenv", ".tf": "terraform", ".tfvars": "terraform", ".hcl": "hcl",
    ".md": "markdown", ".rst": "rst", ".txt": "text", ".csv": "csv",
    ".dockerfile": "dockerfile", ".gradle": "gradle", ".cmake": "cmake", ".mk": "make",
    ".sol": "solidity", ".ex": "elixir", ".exs": "elixir", ".erl": "erlang", ".clj": "clojure",
    ".nim": "nim", ".zig": "zig", ".hs": "haskell", ".ml": "ocaml", ".cbl": "cobol",
}

FILENAME_LANG = {
    "dockerfile": "dockerfile", "makefile": "make", "rakefile": "ruby", "gemfile": "ruby",
    "procfile": "config", "jenkinsfile": "groovy", "vagrantfile": "ruby", "brewfile": "ruby",
    "cmakelists.txt": "cmake", "gradlew": "shell", ".htaccess": "apache",
    "nginx.conf": "nginx", "requirements.txt": "requirements", "pipfile": "toml",
}

MANIFESTS = {
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt",
    "pipfile", "pipfile.lock", "poetry.lock", "pyproject.toml", "setup.py", "setup.cfg",
    "go.mod", "go.sum", "cargo.toml", "cargo.lock", "gemfile", "gemfile.lock", "composer.json",
    "composer.lock", "pom.xml", "build.gradle", "build.gradle.kts", "build.sbt",
    "mix.exs", "pubspec.yaml", "gradle.properties",
}

CONFIG_LANGS = {"json", "yaml", "toml", "ini", "xml", "properties", "dotenv", "terraform",
                "hcl", "dockerfile", "nginx", "apache", "config", "requirements", "gradle",
                "cmake", "make"}
DOC_LANGS = {"markdown", "rst", "text", "csv"}

TEST_RE = re.compile(
    r"(^|/)(tests?|spec|specs|__tests__|e2e|integration[_-]?tests?|testdata|fixtures?|mocks?|"
    r"benchmarks?|examples?|samples?|demo|docs?|doc|documentation)(/|$)|"
    r"(^|/)(test_[^/]+|[^/]+_test|[^/]+\.test|[^/]+\.spec|conftest)\.[a-z0-9]+$",
    re.I,
)
VENDOR_RE = re.compile(
    r"(^|/)(vendor|vendored|third[_-]?party|3rdparty|external|deps|dependencies|"
    r"node_modules|bundled|lib/external|assets/(js|vendor)|static/(js/)?(vendor|lib))(/|$)",
    re.I,
)
GENERATED_RE = re.compile(
    r"(\.min\.(js|css)$)|(\.bundle\.js$)|([_.]pb2?\.(py|go|js|ts)$)|(\.generated\.)|"
    r"(_generated\.)|(\.g\.dart$)|(\.pb\.go$)|(swagger|openapi)[_-]?(gen|generated)",
    re.I,
)
GENERATED_HEADER_RE = re.compile(
    r"(@generated|do not edit|auto-?generated|automatically generated|code generated by)", re.I
)


def _language(path: Path) -> str:
    name = path.name.lower()
    if name in FILENAME_LANG:
        return FILENAME_LANG[name]
    if name.startswith("dockerfile"):
        return "dockerfile"
    if name.startswith(".env"):
        return "dotenv"
    suffix = path.suffix.lower()
    if suffix in LANG_BY_EXT:
        return LANG_BY_EXT[suffix]
    if suffix in BINARY_EXT:
        return "binary"
    return "other"


def _kind(rel: str, name: str, lang: str) -> str:
    if lang == "binary":
        return "artifact"
    if name in MANIFESTS:
        return "manifest"
    if lang in CONFIG_LANGS:
        return "config"
    if lang in DOC_LANGS:
        return "doc"
    if lang in {"css"}:
        return "style"
    if lang == "other":
        return "other"
    return "code"


def read_text(path: Path) -> tuple[str, bool]:
    """Return (text, truncated). Binary-ish content comes back empty."""
    try:
        raw = path.open("rb").read(MAX_READ_BYTES + 1)
    except OSError:
        return "", False
    truncated = len(raw) > MAX_READ_BYTES
    raw = raw[:MAX_READ_BYTES]
    if b"\x00" in raw[:4096]:
        return "", truncated
    for enc in ("utf-8", "utf-16", "latin-1"):
        try:
            return raw.decode(enc), truncated
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace"), truncated


def build_inventory(root: Path, log=lambda m: None, progress=None) -> dict:
    """Classify every file under root. Returns {files, dirs, skipped, totals}."""
    files: list[dict] = []
    dir_counts: dict[str, int] = {}
    skipped = {"dirs": 0, "binary": 0, "too_many": 0}
    seen = 0

    for path in sorted(root.rglob("*")):
        try:
            rel_path = path.relative_to(root)
        except ValueError:
            continue
        rel = rel_path.as_posix()
        parts = rel_path.parts

        if any(p in SKIP_DIRS for p in parts[:-1]) or (path.is_dir() and path.name in SKIP_DIRS):
            if path.is_dir():
                skipped["dirs"] += 1
            continue
        if path.is_dir():
            continue
        if len(files) >= MAX_FILES:
            skipped["too_many"] += 1
            continue

        seen += 1
        if progress and seen % 400 == 0:
            progress(seen)

        lang = _language(path)
        name = path.name.lower()
        try:
            size = path.stat().st_size
        except OSError:
            size = 0

        if lang == "binary":
            skipped["binary"] += 1
            files.append({
                "path": rel, "dir": rel_path.parent.as_posix() if rel_path.parent.as_posix() != "." else "",
                "name": path.name, "ext": path.suffix.lower(), "lang": "binary", "kind": "artifact",
                "size": size, "lines": 0, "scanned": False, "is_test": False,
                "is_vendored": bool(VENDOR_RE.search(rel)), "is_generated": False, "truncated": False,
            })
            continue

        text, truncated = read_text(path)
        lines = text.count("\n") + 1 if text else 0
        avg_line = (len(text) / lines) if lines else 0
        is_generated = bool(GENERATED_RE.search(rel)) or avg_line > 400 or \
            bool(GENERATED_HEADER_RE.search(text[:600]))

        rec = {
            "path": rel,
            "dir": rel_path.parent.as_posix() if rel_path.parent.as_posix() != "." else "",
            "name": path.name,
            "ext": path.suffix.lower(),
            "lang": lang,
            "kind": _kind(rel, name, lang),
            "size": size,
            "lines": lines,
            "scanned": bool(text),
            "is_test": bool(TEST_RE.search(rel)),
            "is_vendored": bool(VENDOR_RE.search(rel)),
            "is_generated": is_generated,
            "truncated": truncated,
        }
        files.append(rec)
        d = rec["dir"]
        dir_counts[d] = dir_counts.get(d, 0) + 1

    by_lang: dict[str, dict] = {}
    for f in files:
        slot = by_lang.setdefault(f["lang"], {"files": 0, "lines": 0})
        slot["files"] += 1
        slot["lines"] += f["lines"]

    totals = {
        "files": len(files),
        "lines": sum(f["lines"] for f in files),
        "bytes": sum(f["size"] for f in files),
        "code_files": sum(1 for f in files if f["kind"] == "code"),
        "test_files": sum(1 for f in files if f["is_test"]),
        "vendored_files": sum(1 for f in files if f["is_vendored"]),
        "by_lang": dict(sorted(by_lang.items(), key=lambda kv: -kv[1]["lines"])),
    }
    log("inventory: " + str(totals["files"]) + " files, " + str(totals["lines"]) + " lines")
    return {"files": files, "dirs": dir_counts, "skipped": skipped, "totals": totals}
