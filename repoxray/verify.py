"""Build a self-contained verification prompt to paste into any chat model.

The scanner's job ends at "this is worth reading". Deciding whether a flagged line is actually
exploitable needs reasoning over the code, so this packages everything a model needs - the
evidence, the inferred context, the source with real line numbers - and asks for a verdict in a
shape you can act on: true positive, false positive, or "I need these specific files".
"""
from __future__ import annotations

from .ai import build_excerpt

QUESTIONS = """## Answer in this order, and cite a line number for every claim

1. **Taint.** Is the value that reaches the flagged line controlled by anyone outside the
   application? Name the variable and trace it backwards line by line. If it is a constant, a
   literal, or internal-only data, say so and jump straight to the verdict. Where a DATAFLOW
   trace is given above, check it rather than redoing it: say whether each hop is right, and
   name the first hop that is wrong if one is.
2. **Sink.** Does the call actually interpret that value (execute it, interpolate it into a
   query, write it to a path, render it as markup), or is it parameterised, escaped, allow-listed
   or otherwise neutralised in the code shown?
3. **Reachability.** Can a request from outside reach this code path? Note any auth check,
   feature flag, or guard between the entrypoint and the sink that is visible here. Where
   PATH CONDITIONS are listed, the solver has already checked that they can hold at once and
   that a payload survives them - verify that each condition is really on the path, and say
   so if one of them actually blocks the value. Where a SOLVER WITNESS is given, say whether
   that value would in fact reach the sink, and correct it if not. Where the flow CROSSES
   FILES, confirm that the call really resolves to the function shown - a wrong resolution
   makes the whole finding void.
4. **Verdict.** Your verdict must follow from steps 1-3 and may not contradict them. If step 1
   found the value is attacker-controlled and step 2 found the sink interprets it without
   neutralisation, the answer is TRUE POSITIVE - do not then assert it is parameterised. If you
   want to change the verdict, go back and fix the step you got wrong first.
   Say what you do not know rather than rounding it off: "I cannot tell where `url` comes
   from without seeing the caller" is a better answer than a guess in either direction, and
   NEED MORE CONTEXT is the right verdict for it. Anything marked LEAD above arrived with a
   gap already named - check that specific gap first.
   One line, starting with exactly one of:
   `TRUE POSITIVE` / `FALSE POSITIVE` / `NEED MORE CONTEXT`
   followed by your confidence (low / medium / high) and a one-sentence reason.
5. **If TRUE POSITIVE:** give a concrete proof of concept - the exact HTTP request, payload or
   input - and state the impact in one sentence.
6. **If NEED MORE CONTEXT:** list the exact file paths, functions or config you need to see and
   what each one would settle. Be specific enough that I can fetch them.

Rules: judge only what is in the excerpt. Do not invent helper functions, middleware or
sanitisers that are not shown. If the scanner's reasoning is wrong, say plainly that it is wrong
and why - a confident false positive is more useful to me than a hedge."""


def _finding_lines(rec: dict, focus_line: int | None) -> tuple:
    """Return (sink findings, context findings) as formatted bullet lists."""
    sinks, context = [], []
    for h in rec.get("hits", []):
        if focus_line and h["line"] != focus_line:
            continue
        if h.get("tier") == "signal":
            continue        # an observation, not a claim; listed separately below
        engine = h.get("engine") or "regex"
        taint = engine in ("taint", "xtaint", "xentry")
        head = {"taint": "DATAFLOW", "xtaint": "DATAFLOW ACROSS FILES",
                "xentry": "DATAFLOW LEAVING THIS FILE",
                "workflow": "WORKFLOW MODEL"}.get(engine, "pattern")
        if h.get("verdict") == "lead":
            head = "LEAD / " + head
        bullet = (
            "- **L" + str(h["line"]) + "** [" + head + " / " + (h.get("cwe") or h["cat"])
            + ", weight " + str(h["weight"]) + "/10] " + h["title"] + "\n"
            + "  - code: `" + h["snippet"].strip()[:200] + "`\n"
            + "  - why: " + h["why"]
        )
        ev = h.get("evidence") or {}
        if ev:
            bullet += ("\n  - what is actually established: source=" + str(ev.get("source"))
                       + ", value type=" + str(ev.get("value"))
                       + ", sink=" + str(ev.get("sink"))
                       + ", tainted argument=" + str(ev.get("role") or "n/a")
                       + ", flow=" + str(ev.get("flow"))
                       + ", guards=" + str(ev.get("guard")))
            bd = ev.get("breakdown") or {}
            if bd:
                bullet += ("\n  - confidence by axis: "
                           + ", ".join(k + "=" + str(v) for k, v in bd.items()))
            if ev.get("verdict") == "lead":
                bullet += ("\n  - this is a LEAD, not a claim. The analyser could not "
                           "establish every part. Do not treat it as reported-true.")
            unknowns = ev.get("unknowns") or []
            if unknowns:
                bullet += "\n  - the analyser could NOT determine:"
                for item in unknowns:
                    bullet += "\n      ? " + str(item)
                bullet += ("\n    Settle these first. If you cannot settle them from the "
                           "code shown, say so and ask for exactly what you need - that is "
                           "the correct answer, not a guess in either direction.")
            for note in ev.get("notes") or []:
                bullet += "\n      * " + str(note)
        if taint:
            bullet += ("\n  - the analyser followed untrusted data from `"
                       + str(h.get("source", "?")) + "` to this line; confidence "
                       + str(h.get("confidence", "?")))
            if h.get("sanitizers"):
                bullet += ("\n  - it passed through " + ", ".join(h["sanitizers"])
                           + ", which does not neutralise this category")
            cross = h.get("cross") or {}
            if cross:
                bullet += ("\n  - this flow CROSSES FILES: it enters at `"
                           + str(cross.get("entry_path")) + ":" + str(cross.get("entry_line"))
                           + "` and reaches `" + str(cross.get("sink_path")) + ":"
                           + str(cross.get("sink_line")) + "` as argument "
                           + str(cross.get("arg")) + " of `" + str(cross.get("function"))
                           + "()`, over " + str(cross.get("hops")) + " call hop(s)")
                bullet += ("\n  - the import was resolved by " + str(cross.get("link"))
                           + (" (a NAME GUESS, not a resolved import - check that this is "
                              "really the function being called)" if cross.get("weak")
                              else " (an actual path on disk)"))
                if cross.get("entry_count", 0) > 1:
                    bullet += ("\n  - the same sink is reached from "
                               + str(cross["entry_count"]) + " call sites: "
                               + ", ".join(e["path"] + ":" + str(e["line"])
                                           for e in cross.get("entries", [])[:6]))
            if h.get("guards"):
                bullet += ("\n  - the solver collected these conditions on the path to the "
                           "sink, and says they can all hold at once:")
                for g in h["guards"]:
                    bullet += "\n      " + str(g)
            if h.get("witness"):
                bullet += ("\n  - a value that satisfies every condition above and still "
                           "carries a payload: `" + str(h["witness"]) + "`  (machine-"
                           "generated from the constraints, so treat it as a starting point "
                           "for a proof of concept, not as a tested exploit)")
            steps = h.get("trace") or []
            if steps:
                bullet += "\n  - trace:"
                for s in steps:
                    where = s.get("path") or ""
                    prefix = (where + " ") if where and where != rec.get("path") else ""
                    bullet += ("\n      " + prefix + "L" + str(s["line"]).ljust(5) + s["note"]
                               + ("  ->  `" + s["code"].strip()[:120] + "`"
                                  if s.get("code") else ""))
        if h.get("soft"):
            bullet += "\n  - note: looks like a placeholder, not a live secret"
        (context if h.get("tier") == "context" else sinks).append(bullet)
    return sinks, context


def _companion_files(scan: dict, rec: dict, focus_line: int | None) -> list:
    """Excerpts of the other files a cross-file flow passes through.

    A verdict on "this helper is called with attacker data" cannot be reached from the
    helper alone, so the prompt has to carry the calling code too. Without it the only
    honest answer a model can give is NEED MORE CONTEXT.
    """
    from pathlib import Path

    from .ai import build_excerpt
    from .inventory import read_text

    root = Path(scan.get("source_root") or "")
    here = rec.get("path")
    wanted: dict = {}
    for hit in rec.get("hits") or []:
        if focus_line and hit["line"] != focus_line:
            continue
        cross = hit.get("cross") or {}
        if not cross:
            continue
        for entry in [{"path": cross.get("entry_path"), "line": cross.get("entry_line")}] \
                + list(cross.get("entries") or []):
            path = entry.get("path")
            if not path or path == here:
                continue
            wanted.setdefault(path, set()).add(int(entry.get("line") or 0))
        sink_path = cross.get("sink_path")
        if sink_path and sink_path != here:
            wanted.setdefault(sink_path, set()).add(int(cross.get("sink_line") or 0))
    out = []
    for path, lines in list(wanted.items())[:3]:
        try:
            body, _ = read_text(root / path)
        except Exception:                                    # pragma: no cover
            body = ""
        if not body:
            continue
        excerpt, _trimmed = build_excerpt(body, sorted(lines), max_lines=120, window=18)
        out.append((path, sorted(lines), excerpt))
    return out


def build_prompt(scan: dict, rec: dict, text: str, github_url: str,
                 focus_line: int | None = None, max_lines: int = 500) -> str:
    repo = scan.get("repo", {})
    fetch = scan.get("fetch", {})
    sinks, context = _finding_lines(rec, focus_line)
    companions = _companion_files(scan, rec, focus_line)

    signals = []
    if rec.get("entrypoints"):
        kinds = sorted({e["kind"] for e in rec["entrypoints"]})
        signals.append("- declares an entrypoint: " + ", ".join(kinds))
    if rec.get("sources"):
        ids = ", ".join(s["id"].replace("src.", "") for s in rec["sources"][:6])
        signals.append("- reads untrusted input in this file: " + ids)
    if rec.get("path_signals"):
        signals.append("- the path contains words suggesting "
                       + ", ".join(s["label"] for s in rec["path_signals"])
                       + " (a hint about where to look, not evidence: it is the file's "
                         "name, not its code, and it is not scored)")
    dep = (scan.get("summary") or {}).get("deployment") or rec.get("deployment") or {}
    if dep.get("describe"):
        signals.append("- deployment: " + dep["describe"]
                       + " Who the attacker is follows from that: a service faces the "
                         "network, a CLI is run by the person it belongs to, and a "
                         "library gets its configuration from the application that "
                         "embeds it.")
    if rec.get("is_test"):
        signals.append("- NOTE: this path looks like tests or examples, so weigh reachability")
    if rec.get("is_vendored"):
        signals.append("- NOTE: this is vendored third-party code, not written by the project")

    ai = rec.get("ai")
    ai_block = ""
    if ai and not ai.get("error"):
        ai_block = (
            "\n## A local model already looked at this\n\n"
            + "It said " + str(ai.get("probability")) + "% likely, confidence "
            + str(ai.get("confidence")) + " (" + str(ai.get("model")) + "): "
            + (ai.get("summary") or "").strip() + "\n\n"
            + "Treat that as a hint from a small model, not as evidence. Check it.\n"
        )

    focus = rec.get("match_lines") or []
    if focus_line:
        focus = [focus_line]
    excerpt, trimmed = build_excerpt(text, focus, max_lines=max_lines, window=28)

    lang = rec.get("lang") or ""
    fence = {"typescript": "ts", "javascript": "js", "python": "python", "ruby": "ruby",
             "php": "php", "go": "go", "java": "java", "csharp": "csharp", "cpp": "cpp",
             "c": "c", "shell": "bash", "yaml": "yaml"}.get(lang, "")

    parts = [
        "# Is this a real vulnerability?",
        "",
        "You are a senior application security engineer. Below is one file from a public "
        "repository, flagged by a pattern-matching scanner. Pattern matches are leads, not "
        "findings - your job is to decide which this is.",
        "",
        "## Target",
        "",
        "- repository: " + repo.get("slug", "?") + "  (" + repo.get("html_url", "") + ")",
        "- commit: " + (str(fetch.get("commit", ""))[:12] or "unknown")
        + "   branch/ref: " + str(repo.get("ref") or fetch.get("branch") or "default"),
        "- file: `" + rec["path"] + "`  (" + lang + ", " + str(rec.get("lines")) + " lines)",
        "- permalink: " + github_url,
        "- scanner's heuristic score: " + str(rec.get("score")) + "/100 ("
        + str(rec.get("band")) + ")",
        "",
        "## What the scanner flagged",
        "",
    ]
    parts.append("\n".join(sinks) if sinks else "- (nothing high-confidence; see context below)")
    if context:
        parts += ["", "### Properties of this file (ambient, not claims about a bug)", "",
                  "\n".join(context)]
    annotations = [
        "- **L" + str(h["line"]) + "** " + h["title"] + ": `"
        + h["snippet"].strip()[:120] + "`"
        for h in (rec.get("hits") or []) if h.get("tier") == "signal"
        and (not focus_line or h["line"] == focus_line)
    ]
    if annotations:
        parts += ["", "### Annotations (a developer's note, not a weakness)", "",
                  "A `#nosec`, a `nolint` or a security TODO means someone looked at this "
                  "line and decided to move on. Worth knowing next to a finding. Not itself "
                  "a vulnerability - do not report one as one.", "",
                  "\n".join(annotations)]
    if signals:
        parts += ["", "## Context the scanner inferred", "", "\n".join(signals)]

    # What the scanner decided NOT to report, and why. Shown so the reviewer can overturn
    # it: a dismissal is a claim about the code and can be wrong like any other.
    ruled_out = [d for d in (rec.get("dismissed") or [])
                 if not focus_line or d["line"] == focus_line]
    if ruled_out:
        parts += ["", "## What the scanner ruled out here, and why", "",
                  "These lines matched a pattern and were then dismissed for the reason "
                  "given. They are listed so you can disagree. If one of these reasons is "
                  "wrong, say so plainly and explain what the pattern got right - a "
                  "dismissal is a claim about the code, not a decision you have to "
                  "accept.", ""]
        for item in ruled_out[:10]:
            parts.append("- **L" + str(item["line"]) + "** `"
                         + item["snippet"].strip()[:110] + "`\n  - ruled out because "
                         + item["why"])
    for note in rec.get("context_notes") or []:
        parts += ["", "- " + note]
    if ai_block:
        parts.append(ai_block)

    parts += [
        "",
        "## Source" + (" (trimmed to the relevant windows; line numbers are the real ones)"
                       if trimmed else ""),
        "",
        "```" + fence,
        excerpt,
        "```",
    ]

    if companions:
        parts += ["", "## The other end of the flow", "",
                  "The flagged flow crosses a file boundary, so here is the code on the "
                  "other side. Judge the whole path, not one half of it."]
        for path, lines, body in companions:
            parts += ["", "### `" + path + "`  (around line"
                      + ("s " if len(lines) > 1 else " ")
                      + ", ".join(str(n) for n in lines[:8]) + ")", "",
                      "```" + fence, body, "```"]

    parts += ["", QUESTIONS]
    return "\n".join(parts)
