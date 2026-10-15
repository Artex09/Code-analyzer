"""Entry point: analyse one file with AST + dataflow + path conditions, with guard rails.

Never raises. A grammar that chokes, a pathological file, a slow fixpoint or a missing solver
degrades to a weaker result and the regex pass still stands on its own.
"""
from __future__ import annotations

import time

from . import binding, langs, pathcond, reach
from .dataflow import analyse as _analyse
from .parse import parse, resolve
from .resolve import extract_bindings, extract_exports, extract_imports

MAX_BYTES = 900_000      # beyond this, parsing cost stops paying for itself
MAX_SECONDS = 8.0        # per file


def analyse_file(text: str, lang: str, path: str = "", code: str | None = None,
                 tainted_returns=(), guard_lines=(), read=None,
                 dep_kind: str = "") -> dict:
    """Analyse one file. Returns a dict that is always complete, even on failure.

    `code` is the comment-stripped source, if the caller already has it - imports are read
    from that rather than from the raw text so a commented-out require is not a link.
    `tainted_returns` names imported functions a previous round proved return untrusted
    data, which is how flow *back* from another module is picked up.
    `guard_lines` are lines the caller wants the enclosing branch conditions for - the
    pattern hits on settings, where "is this always on?" is the whole question. They reuse
    the tree parsed here, so asking costs one extra walk and no extra parse.
    `read(repo_relative_path)` lets the binding resolver follow a relative import to the
    definition of an imported name, which is what tells `exec` the shell apart from
    `exec = promisify(execFile)` in a sibling module. `dep_kind` is the repository's
    deployment type, which decides whether a value from argv or the environment has
    anyone but the operator behind it.
    """
    out = {"ok": False, "findings": [], "const_sinks": [], "suppressed": [],
           "depth": langs.depth_for(lang), "ms": 0, "reason": "",
           "summaries": {}, "callsites": [], "imports": [], "exports": (),
           "bindings": [], "guards": {}, "callees": {}, "misidentified": [],
           "path": {}, "solver": pathcond.available()}

    spec = langs.spec_for(lang)
    if spec is None:
        out["reason"] = "no language model"
        return out
    if not text.strip():
        out["reason"] = "empty"
        return out
    if len(text) > MAX_BYTES:
        out["reason"] = "file too large for AST analysis"
        return out

    # Resolved before parsing and outside the main try, because the context pass wants it
    # whether or not the tree came out: what `exec` refers to is a textual question.
    callees: dict = {}
    try:
        callees = binding.resolve(code if code is not None else text, lang, path, read)
    except Exception:                                             # noqa: BLE001
        callees = {}
    out["callees"] = callees
    out["callees_described"] = {k: v.describe() for k, v in callees.items() if v.family}

    t0 = time.time()
    try:
        root, data = parse(text, resolve(lang) if lang not in ("typescript",) else "typescript")
        if root is None:
            out["reason"] = "no parser for " + lang
            return out
        if root.has_error:
            # a partial tree is still worth analysing; note it for the UI
            out["reason"] = "parse errors (partial tree)"
        result = _analyse(spec, root, data, text, path=path,
                          tainted_returns=set(tainted_returns or ()),
                          bindings=callees, dep_kind=dep_kind)
        out["findings"] = result["findings"]
        out["const_sinks"] = result["const_sinks"]
        out["suppressed"] = result["suppressed"]
        out["misidentified"] = result["misidentified"]
        out["summaries"] = result["summaries"]
        out["callsites"] = result["callsites"]
        out["path"] = result["path"]
        out["imports"] = extract_imports(code if code is not None else text, spec)
        out["exports"] = extract_exports(code if code is not None else text, spec)
        out["bindings"] = extract_bindings(code if code is not None else text, spec)
        if guard_lines:
            out["guards"] = reach.analyse(root, data, set(guard_lines))
        out["ok"] = True
    except RecursionError:
        out["reason"] = "expression too deeply nested"
    except Exception as exc:                                  # noqa: BLE001
        out["reason"] = type(exc).__name__ + ": " + str(exc)[:120]
    finally:
        out["ms"] = int((time.time() - t0) * 1000)

    if out["ms"] > MAX_SECONDS * 1000:
        out["reason"] = (out["reason"] + "; " if out["reason"] else "") + "slow file"
    return out


def capabilities() -> dict:
    out = langs.summary()
    out["_solver"] = {
        "available": pathcond.available(),
        "version": pathcond.version(),
        "classes": pathcond.modelled_categories(),
        "note": ("Z3 decides whether the branch conditions leading to a sink can hold at "
                 "all, and whether they still admit a payload."
                 if pathcond.available() else
                 "install z3-solver to enable path-condition checking"),
    }
    out["_cross_file"] = {"available": True, "languages": sorted(
        k for k, v in langs.SPECS.items() if v.imports)}
    return out
