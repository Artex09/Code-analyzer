"""Per-language analysis: node shapes, sources, sinks, sanitizers.

Adding a language is one module and one row here. `depth` is honest signalling for the UI:
full = modelled framework surface, basic = common sinks only.
"""
from __future__ import annotations

from . import javascript, php, python
from .others import CSHARP_SPEC, GO_SPEC, JAVA_SPEC, RUBY_SPEC

SPECS = {
    "python": python.SPEC,
    "javascript": javascript.SPEC,
    "typescript": javascript.SPEC,
    "vue": javascript.SPEC,
    "svelte": javascript.SPEC,
    "astro": javascript.SPEC,
    "php": php.SPEC,
    "java": JAVA_SPEC,
    "kotlin": JAVA_SPEC,
    "go": GO_SPEC,
    "ruby": RUBY_SPEC,
    "csharp": CSHARP_SPEC,
}

DEPTH = {
    "python": "full", "javascript": "full", "typescript": "full", "php": "full",
    "vue": "full", "svelte": "full", "astro": "full",
    "java": "basic", "kotlin": "basic", "go": "basic", "ruby": "basic", "csharp": "basic",
}


def spec_for(lang: str):
    return SPECS.get(lang)


def depth_for(lang: str) -> str:
    return DEPTH.get(lang, "none")


def summary() -> dict:
    """What the UI advertises: which languages get dataflow, and how deeply modelled."""
    from ..parse import available
    have = available()
    out = {}
    for lang, spec in SPECS.items():
        grammar = lang if lang in have else {"typescript": "typescript", "vue": "javascript",
                                             "svelte": "javascript", "astro": "javascript",
                                             "kotlin": "java"}.get(lang, lang)
        out[lang] = {
            "depth": DEPTH.get(lang, "none"),
            "parser": bool(have.get(grammar)),
            "sources": len(spec.sources),
            "sinks": len(spec.sinks),
            "sanitizers": len(spec.sanitizers),
        }
    return out

_MODELLED: dict = {}


def modelled_cats(lang: str) -> set:
    """Categories the dataflow engine has sinks for in this language.

    Used to decide where the pattern pass should step back: if the engine models command
    injection for Go, a Go file it successfully analysed does not also need a regex opinion
    about command injection competing for the same ranking slot.
    """
    if lang not in _MODELLED:
        spec = SPECS.get(lang)
        _MODELLED[lang] = {sink.cat for sink in spec.sinks} if spec is not None else set()
    return _MODELLED[lang]
