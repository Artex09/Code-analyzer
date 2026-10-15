"""tree-sitter parser registry.

Grammars are optional: if a package is missing the analyser simply reports that language as
unsupported and the regex pass still runs. Parsers are cached per language because building a
Language object is the expensive part, not parsing.
"""
from __future__ import annotations

import threading

_LOADERS = {
    "python": ("tree_sitter_python", "language"),
    "javascript": ("tree_sitter_javascript", "language"),
    "typescript": ("tree_sitter_typescript", "language_typescript"),
    "tsx": ("tree_sitter_typescript", "language_tsx"),
    "php": ("tree_sitter_php", "language_php"),
    "java": ("tree_sitter_java", "language"),
    "go": ("tree_sitter_go", "language"),
    "ruby": ("tree_sitter_ruby", "language"),
    "csharp": ("tree_sitter_c_sharp", "language"),
}

# languages that share another language's grammar
ALIASES = {"vue": "javascript", "svelte": "javascript", "astro": "javascript",
           "mjs": "javascript", "cjs": "javascript"}

_cache: dict = {}
_lock = threading.Lock()
_available_checked = False
_available: dict = {}


def resolve(lang: str) -> str:
    return ALIASES.get(lang, lang)


def get_parser(lang: str):
    """Return a tree-sitter Parser for lang, or None when the grammar is unavailable."""
    lang = resolve(lang)
    if lang in _cache:
        return _cache[lang]
    with _lock:
        if lang in _cache:
            return _cache[lang]
        parser = None
        entry = _LOADERS.get(lang)
        if entry:
            module_name, fn_name = entry
            try:
                import importlib
                from tree_sitter import Language, Parser
                module = importlib.import_module(module_name)
                parser = Parser(Language(getattr(module, fn_name)()))
            except Exception:
                parser = None
        _cache[lang] = parser
        return parser


def parse(text: str, lang: str):
    """Return (root_node, source_bytes) or (None, b'') if the language has no grammar."""
    parser = get_parser(lang)
    if parser is None:
        return None, b""
    data = text.encode("utf-8", "replace")
    try:
        tree = parser.parse(data)
    except Exception:
        return None, b""
    return tree.root_node, data


def available() -> dict:
    """{language: bool} for every grammar we know how to load. Computed once."""
    global _available_checked
    if not _available_checked:
        for lang in _LOADERS:
            _available[lang] = get_parser(lang) is not None
        _available_checked = True
    return dict(_available)


def supported_languages() -> list:
    return sorted([k for k, v in available().items() if v])
