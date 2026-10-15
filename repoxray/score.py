"""Turn pattern matches and dataflow findings into a per-file risk score plus the evidence.

Scoring runs in two phases, because cross-file flow cannot be known one file at a time:

  phase 1  every file is parsed, analysed and scored on its own; the function summaries and
           tainted call sites it produces are collected
  phase 2  call sites are joined to summaries across the repository, the resulting findings
           are attached to the file that holds the sink (and a pointer to the file that holds
           the entry), and both files are scored again

`finalise` is therefore written to be re-runnable: it derives the score from the collected
parts rather than accumulating into them.
"""
from __future__ import annotations

import bisect
import math
from pathlib import Path

from . import rules
from .analysis import actions as gha
from .analysis import context as ctx_pass
from .analysis import deployment, langs
from .analysis import run as ast_run
from .analysis.cross import CrossIndex
from .analysis.model import Evidence, Finding, TraceStep
from .analysis.resolve import RepoIndex
from .inventory import read_text
from . import strip
from .strip import strip_comments

# Pattern rules that the structural workflow model replaces. They fired on a trigger name,
# on a concurrency group and on an integer PR number, all at weight 8.
WORKFLOW_RULES = ("cfg.ci_injection", "cfg.ci_secret_echo", "cfg.ci_pull_request_target")

MAX_HITS_PER_RULE = 8       # evidence lines kept per rule, per file
MAX_HITS_PER_FILE = 60
MAX_REVERSE_FILES = 400     # files re-analysed for taint flowing back out of a module

BANDS = (
    (75, "critical"),
    (55, "high"),
    (35, "medium"),
    (15, "low"),
    (0, "minimal"),
)

PLACEHOLDER_TOKENS = (
    "example", "changeme", "change_me", "your_", "yourkey", "placeholder", "dummy", "xxxx",
    "todo", "insert", "sample", "test", "fake", "redacted", "<", "{{", "${", "abc123",
    "password123", "secret123", "notasecret", "null", "none", "n/a",
)

# engines whose findings are traced evidence rather than a pattern guess
FLOW_ENGINES = ("taint", "xtaint", "xentry")
CROSS_ENGINES = ("xtaint", "xentry")


def band(score: float) -> str:
    for threshold, name in BANDS:
        if score >= threshold:
            return name
    return "minimal"


def _line_index(text: str) -> list[int]:
    offsets = [0]
    start = 0
    while True:
        nl = text.find("\n", start)
        if nl == -1:
            break
        offsets.append(nl + 1)
        start = nl + 1
    return offsets


def _line_of(offsets: list[int], pos: int) -> int:
    return bisect.bisect_right(offsets, pos)


def _snippet(text: str, offsets: list[int], line_no: int, limit: int = 220) -> str:
    start = offsets[line_no - 1] if 0 < line_no <= len(offsets) else 0
    end = text.find("\n", start)
    if end == -1:
        end = len(text)
    return text[start:end].strip()[:limit]


def _lang_applies(rule_langs: set, lang: str) -> bool:
    return (not rule_langs) or (lang in rule_langs)


def _looks_like_placeholder(snippet: str) -> bool:
    low = snippet.lower()
    return any(tok in low for tok in PLACEHOLDER_TOKENS)


# A dataflow finding is evidence, not a guess, so it outweighs a pattern match. The spread
# is deliberately gentle: severity still leads. A weight-9 eval the analyser is unsure about
# (0.5 x 9 = 4.5) should outrank a weight-4 redirect it is certain of (1.0 x 4), because
# that is the order a reviewer wants to read them in.
CONF_FACTOR = {"high": 1.0, "medium": 0.75, "low": 0.5}
TAINT_BOOST = 1.6
WITNESS_BOOST = 1.15        # the solver produced a value that passes every guard



def _workflow_findings(rec: dict, text: str, hits: list, per_rule: dict,
                       analysis: dict) -> list:
    """Replace the generic YAML patterns on a workflow with the structural model.

    A workflow is not "code with braces in it". The structural pass knows that a trigger is
    not data, that `concurrency.group` is not a sink, that an integer PR number cannot carry
    a payload, and that `env:` plus a quoted `"$VAR"` is the documented mitigation rather
    than a bug.
    """
    result = gha.analyse_workflow(text, rec["path"])
    analysis["workflow"] = {"ok": result["ok"], "reason": result["reason"],
                            "triggers": result["triggers"],
                            "guards": [g["guard"] for g in result["guards"]],
                            "signals": len(result["signals"])}
    if not result["ok"]:
        return []
    # the generic rules no longer apply: this file has a real model
    kept = []
    for hit in hits:
        if hit["rule"] in WORKFLOW_RULES:
            per_rule.pop(hit["rule"], None)
            analysis["regex_superseded"] = analysis.get("regex_superseded", 0) + 1
            continue
        kept.append(hit)
    hits[:] = kept

    out: list = []
    for item in result["findings"] + result["notes"]:
        verdict = item.get("verdict", "lead")
        ev = Evidence(
            # Preserve the workflow model's uncertainty. Reconstructing every result as
            # `known` made an explicitly labelled lead (for example an unclassified event
            # field or an unquoted env expansion) look like a confirmed finding because
            # Evidence.verdict() quite reasonably trusts a known, direct text flow.
            source="inferred" if verdict == "lead" else "known",
            value=item.get("value", "text"),
            sink="direct" if item["cat"] in ("cmd", "code") else "indirect",
            role=item.get("position", ""),
            flow="direct",
            guard="present" if item.get("guards") else "none",
            notes=tuple(
                [n for n in [
                    item.get("fix") and "fix: " + item["fix"],
                    item.get("actor") == "writer"
                    and "requires push access to this repository",
                    item.get("step") and "in: " + str(item["step"]),
                ] if n]
                + ["gated by: " + g for g in (item.get("guards") or [])][:4]),
        )
        tier = "context" if verdict == "context" else "sink"
        out.append(Finding(
            rule=item["rule"], cat=item["cat"],
            title=("LEAD: " + item["title"]) if verdict == "lead" else item["title"],
            why=item["why"], line=item["line"],
            snippet=_nth_line(text, item["line"]),
            weight=item["weight"], cwe=rules.CATEGORIES.get(item["cat"], {}).get("cwe", ""),
            confidence=item.get("confidence", "medium"),
            engine="workflow", source_label=item.get("ref", ""),
            trace=[TraceStep(line=item["line"], code=_nth_line(text, item["line"]),
                             note=item.get("position", "") + ": " + item.get("ref", ""))],
            evidence=ev, tier=tier,
        ))
    for item in result["signals"]:
        out.append(Finding(
            rule=item["rule"], cat="suppress", title=item["title"],
            why=item.get("detail", ""), line=item["line"],
            snippet=_nth_line(text, item["line"]), weight=0, cwe="",
            confidence="high", engine="workflow", tier="signal",
            evidence=Evidence(source="known", value="trigger", sink="indirect"),
        ))
    return out


def _nth_line(text: str, line: int) -> str:
    lines = text.split("\n")
    return lines[line - 1].strip()[:200] if 0 < line <= len(lines) else ""

def _posix(path: str) -> str:
    """Repo-relative path with forward slashes, which is how a module specifier joins."""
    return path.replace("\\", "/")


def collect(rec: dict, text: str, deep: bool = True, tainted_returns=(),
            dep_ctx=None, read=None) -> dict:
    """Run both engines over one file and return the parts `finalise` scores."""
    lang = rec["lang"]
    # match against code with comments blanked; the suppress rules below deliberately
    # read the raw text, because what they look for IS a comment
    code = strip_comments(text, lang)
    offsets = _line_index(text)
    str_spans = strip.string_spans(code, lang)
    analysis_text_only = 0
    hits: list[dict] = []
    per_rule_contrib: dict[str, float] = {}
    cat_weight: dict[str, float] = {}

    for rule in rules.COMPILED_RULES:
        if not _lang_applies(rule["langs"], lang):
            continue
        target = text if rule["cat"] == "suppress" else code
        matches = list(rule["rx"].finditer(target))
        if not matches:
            continue
        lines_seen: list[int] = []
        kept = 0
        in_code_text = rule["id"] in rules.CODE_TEXT_RULES
        for m in matches:
            # A rule whose claim is "this file runs code" is answering about code. The
            # same characters inside a string literal are a command line being quoted,
            # which is a different statement about a different process.
            if in_code_text and strip.inside(str_spans, m.start()):
                analysis_text_only += 1
                continue
            ln = _line_of(offsets, m.start())
            if ln in lines_seen:
                continue
            lines_seen.append(ln)
            if kept < MAX_HITS_PER_RULE and len(hits) < MAX_HITS_PER_FILE:
                snip = _snippet(text, offsets, ln)
                weight = rule["weight"]
                soft = False
                if rule["cat"] == "secret" and _looks_like_placeholder(snip):
                    weight = max(1, weight - 5)
                    soft = True
                hits.append({
                    "rule": rule["id"], "cat": rule["cat"], "title": rule["title"],
                    "cwe": rule["cwe"], "weight": weight, "line": ln, "tier": rule["tier"],
                    "snippet": snip, "why": rule["why"], "soft": soft,
                })
                kept += 1
        n = len(lines_seen)
        if rule["tier"] == "signal":
            # A `#nosec` comment is worth reading and is not a vulnerability. Scoring it as
            # one put clean files into the "low" band for carrying a linter annotation.
            continue
        eff_weight = rule["weight"]
        if rule["cat"] == "secret" and hits and all(
                h.get("soft") for h in hits if h["rule"] == rule["id"]):
            eff_weight = max(1, eff_weight - 5)
        contrib = eff_weight * min(1 + 0.30 * math.log2(n) if n > 1 else 1.0, 2.2)
        per_rule_contrib[rule["id"]] = round(contrib, 2)
        cat_weight[rule["cat"]] = round(cat_weight.get(rule["cat"], 0) + contrib, 2)

    sources = []
    for src in rules.COMPILED_SOURCES:
        if not _lang_applies(src["langs"], lang):
            continue
        m = src["rx"].search(code)
        if not m:
            continue
        # A framework source only counts where the framework is present. Without this,
        # `Resolver(` made a Go gRPC connection parser "read untrusted input: graphql" in
        # a repository that has no GraphQL in it - and that phantom source then multiplied
        # the whole file's score by 1.4.
        if src["requires"] is not None and not src["requires"].search(code):
            continue
        sources.append({"id": src["id"], "line": _line_of(offsets, m.start())})

    entrypoints = []
    for ep in rules.COMPILED_ENTRYPOINTS:
        if not _lang_applies(ep["langs"], lang):
            continue
        found = list(ep["rx"].finditer(code))
        if found:
            entrypoints.append({
                "id": ep["id"], "kind": ep["kind"], "count": len(found),
                "line": _line_of(offsets, found[0].start()),
            })

    path_signals = []
    path_bonus = 0.0
    lowered = "/" + rec["path"].lower()
    for rx, weight, label in rules.COMPILED_PATH_SIGNALS:
        if rx.search(lowered):
            path_signals.append({"label": label, "weight": weight})
    if path_signals:
        path_signals.sort(key=lambda s: -s["weight"])
        path_bonus = path_signals[0]["weight"] + 0.4 * sum(s["weight"] for s in path_signals[1:3])

    neg_factor = 1.0
    neg_labels = []
    for rx, factor, label in rules.COMPILED_NEG_SIGNALS:
        if rx.search(lowered):
            neg_factor = min(neg_factor, factor)
            neg_labels.append(label)

    # ---- AST + dataflow + path conditions -----------------------------------
    # Parses the file, follows untrusted values through assignments and calls, asks the
    # solver whether the branch conditions on the way to each sink can hold at all and can
    # still carry a payload, and only then reports. Two effects: findings regex cannot see,
    # and silence where regex guessed wrong.
    analysis = {"engine": "regex", "depth": "none", "ms": 0, "reason": "", "findings": 0}
    if analysis_text_only:
        analysis["text_not_code"] = analysis_text_only
    taint_findings: list = []
    facts: dict = {}
    guards: dict = {}
    callees: dict = {}
    misidentified: list = []
    if deep and gha.available() and gha.is_workflow(rec["path"]):
        analysis["engine"] = "workflow"
        analysis["depth"] = "full"
        taint_findings = _workflow_findings(rec, text, hits, per_rule_contrib, analysis)
        analysis["findings"] = sum(1 for f in taint_findings if f.tier != "signal")
    elif deep:
        # Lines where the surrounding code decides the verdict, so the AST pass can answer
        # from the tree it is parsing anyway: what guards a setting, and what function a
        # capability sits in - `random()` inside `generateResetToken` is not the same
        # finding as the identical call inside `pickBackgroundColour`.
        guard_lines = {h["line"] for h in hits
                       if h["rule"] in rules.SETTING_RULES
                       or h["rule"] in rules.CAPABILITY_RULES}
        res = ast_run.analyse_file(text, lang, path=_posix(rec["path"]),
                                   code=code, tainted_returns=tainted_returns,
                                   guard_lines=guard_lines, read=read,
                                   dep_kind=dep_ctx.kind if dep_ctx is not None else "")
        analysis.update({"depth": res["depth"], "ms": res["ms"], "reason": res["reason"]})
        callees = res.get("callees") or {}
        misidentified = list(res.get("misidentified") or ())
        if res["ok"]:
            analysis["engine"] = "ast+taint"
            guards = res.get("guards") or {}
            analysis["findings"] = len(res["findings"])
            analysis["suppressed"] = len(res["suppressed"])
            analysis["suppressed_why"] = sorted({r for _ln, _sid, r in res["suppressed"]})[:4]
            solver = res.get("path") or {}
            if solver.get("queries"):
                analysis["solver"] = solver
            taint_findings = list(res["findings"])
            facts = {"summaries": res["summaries"], "callsites": res["callsites"],
                     "imports": res["imports"], "exports": res["exports"],
                     "bindings": res["bindings"]}
            # a line the engine proved takes only constants is not a finding, whatever
            # the regex thought: drop the pattern hit that fired on it
            const = {(ln, cat) for ln, _sid, cat in res["const_sinks"]}
            if const:
                keep = []
                for h in hits:
                    # A context-tier hit survives a const proof in general, because it is
                    # an observation and not a claim. A *capability* hit does not: its
                    # whole claim is "this line builds something at runtime", and the
                    # engine has just shown that this line builds a constant.
                    refuted = (h.get("tier") != "context"
                               or h["rule"] in rules.CAPABILITY_RULES)
                    if (h["line"], h["cat"]) in const and refuted:
                        per_rule_contrib.pop(h["rule"], None)
                        cat_weight.pop(h["cat"], None)
                        analysis["regex_dropped"] = analysis.get("regex_dropped", 0) + 1
                        continue
                    keep.append(h)
                hits = keep
            # where dataflow has a verdict, the pattern match for the same thing is noise;
            # and a sink the solver ruled out does not deserve a pattern hit either
            covered = {(f.line, f.cat) for f in taint_findings}
            ruled_out = {ln for ln, _sid, _r in res["suppressed"]}
            if covered or ruled_out:
                survivors = []
                for h in hits:
                    if (h["line"], h["cat"]) in covered:
                        per_rule_contrib.pop(h["rule"], None)
                        analysis["regex_superseded"] = analysis.get("regex_superseded", 0) + 1
                        continue
                    if h["line"] in ruled_out and h.get("tier") != "context":
                        per_rule_contrib.pop(h["rule"], None)
                        analysis["regex_dropped"] = analysis.get("regex_dropped", 0) + 1
                        continue
                    survivors.append(h)
                hits = survivors
            # Where the dataflow pass ran and models a category, it is authoritative for
            # that category: it either traced the flow or showed there is none. A pattern
            # match on the same class is then a name-based guess competing for the same
            # ranking slot, and at weight 6-9 it outranks real findings. Demote, keep
            # visible, stop scoring.
            modelled = langs.modelled_cats(lang)
            if modelled:
                for hit in hits:
                    if hit.get("tier") != "sink" or hit["cat"] not in modelled:
                        continue
                    if (hit["line"], hit["cat"]) in covered:
                        continue
                    hit["tier"] = "context"
                    hit["weight"] = min(hit["weight"], 4)
                    hit["why"] = (hit["why"] + " The dataflow pass read this file and did "
                                  "not connect untrusted input to this line, so this is "
                                  "ambient context rather than a finding.")
                    per_rule_contrib[hit["rule"]] = round(
                        per_rule_contrib.get(hit["rule"], 0) * 0.25, 2)
                    analysis["regex_demoted"] = analysis.get("regex_demoted", 0) + 1

    # The context pass: a correct pattern match is not yet a finding. Reviewer directives,
    # literal shape, capability corroboration, what guards a setting, what a decoder can
    # actually do, and whether this deployment has a victim at all.
    ctx_state = ctx_pass.apply(
        rec, text, code, lang, hits, per_rule_contrib, cat_weight, sources,
        guards, dep_ctx, analysis, rules, callees=callees,
        misidentified=misidentified)

    return {
        "hits_pattern": hits,
        "dismissed": ctx_state["dismissed"],
        "context_notes": ctx_state["notes"],
        "per_rule_contrib": per_rule_contrib,
        "cat_pattern": cat_weight,
        "taint_findings": taint_findings,
        "cross_findings": [],
        "sources": sources,
        "entrypoints": entrypoints,
        "path_signals": path_signals,
        "path_bonus": path_bonus,
        "neg_factor": neg_factor,
        "neg_labels": neg_labels,
        "analysis": analysis,
        "facts": facts,
        "deployment": ({"kind": dep_ctx.kind, "confidence": dep_ctx.confidence,
                        "describe": dep_ctx.describe()} if dep_ctx is not None else {}),
    }


def finalise(rec: dict, ctx: dict) -> dict:
    """Score one file from its collected parts. Safe to call again after phase 2."""
    hits = list(ctx["hits_pattern"])
    per_rule_contrib = dict(ctx["per_rule_contrib"])
    cat_weight = dict(ctx["cat_pattern"])
    analysis = ctx["analysis"]
    # A sink can be reported twice: once by this file's own dataflow and once by the
    # cross-file pass. The cross-file finding carries strictly more - every entry point and
    # the trace through the calling file - so it wins and the local duplicate goes.
    covered = {(f.line, f.rule.partition(".")[2]) for f in ctx["cross_findings"]
               if f.engine == "xtaint"}
    flow = [f for f in ctx["taint_findings"]
            if (f.line, f.rule.partition(".")[2]) not in covered] + list(ctx["cross_findings"])

    # Diminishing returns per rule, as for patterns: seven low-confidence findings of the
    # same shape (a build script passing $CFLAGS around) must not outweigh one confirmed
    # remote injection.
    taint_contrib = 0.0
    groups: dict = {}
    for f in flow:
        hits.append(f.to_hit())
        groups.setdefault(f.rule, []).append(f)
    for _rule_id, found in groups.items():
        best = max(f.weight * CONF_FACTOR.get(f.confidence, 0.7)
                   * (WITNESS_BOOST if f.witness else 1.0) for f in found)
        n = len(found)
        spread = min(1 + 0.3 * math.log2(n), 2.0) if n > 1 else 1.0
        taint_contrib += best * spread * TAINT_BOOST
        cat = found[0].cat
        cat_weight[cat] = round(cat_weight.get(cat, 0) + best * spread, 2)
    if len(hits) > MAX_HITS_PER_FILE:
        del hits[MAX_HITS_PER_FILE:]

    # "this C file calls memcpy" is true of every C file. Context rules only earn their
    # full weight when something untrusted can actually reach the file.
    sources = ctx["sources"]
    entrypoints = ctx["entrypoints"]
    has_source = bool(sources)
    if not has_source and not entrypoints:
        for rule_id in list(per_rule_contrib):
            rule = rules.COMPILED_BY_ID.get(rule_id)
            if rule and rule["tier"] == "context":
                per_rule_contrib[rule_id] = round(per_rule_contrib[rule_id] * 0.35, 2)

    raw = sum(per_rule_contrib.values()) + taint_contrib
    reasons: list[str] = []
    if any(f.engine in CROSS_ENGINES for f in flow):
        reasons.append("dataflow crosses a file boundary into a sink")
    elif taint_contrib:
        reasons.append("dataflow reaches a sink from untrusted input")
    if any(f.witness for f in flow):
        reasons.append("solver produced a payload that survives the checks on the path")

    has_sink = raw > 0
    taint_factor = 1.0
    if has_source and has_sink:
        taint_factor *= 1.40
        reasons.append("untrusted input and a dangerous sink in the same file")
    if entrypoints and has_sink:
        taint_factor *= 1.15
        reasons.append("reachable from a declared entrypoint")

    # A path signal is navigation, not evidence. `auth/file_cache.go` scored 37.5 with no
    # findings at all: 11.4 of that came from the words "auth" and "file" in its path,
    # against 1.75 from the one thing the scanner actually found in the code. The directory
    # a file sits in tells a reviewer where to look first; it says nothing about whether
    # there is a bug there. So the path now orders files that already carry evidence, by a
    # capped multiplier, and can never produce a score on its own.
    path_bonus = ctx["path_bonus"]
    path_factor = (1.0 + min(0.18, path_bonus / 90.0)) if has_sink else 1.0
    score_raw = raw * taint_factor * path_factor

    damp = 1.0
    if rec["is_vendored"]:
        damp *= 0.30
        reasons.append("vendored third-party code")
    if rec["is_test"]:
        damp *= 0.40
        reasons.append("test/example/doc path")
    if rec["is_generated"]:
        damp *= 0.35
        reasons.append("generated or minified")
    if rec["kind"] == "doc":
        damp *= 0.45
    if rec["lines"] < 12:
        damp *= 0.75
    neg_factor = ctx["neg_factor"]
    score_raw *= damp * neg_factor
    if ctx["neg_labels"]:
        reasons.append(ctx["neg_labels"][0])

    score = 100.0 * (1.0 - math.exp(-score_raw / 28.0))
    score = round(min(99.0, score), 1)

    top_cats = sorted(cat_weight.items(), key=lambda kv: -kv[1])
    for cat, _w in top_cats[:3]:
        reasons.insert(0, rules.CATEGORIES.get(cat, {}).get("name", cat))
    path_signals = ctx["path_signals"]
    if path_signals and not has_sink:
        reasons.append(path_signals[0]["label"]
                       + " - from the path only, nothing found in the code")
    dismissed = ctx.get("dismissed") or []
    if dismissed:
        reasons.append(str(len(dismissed)) + " pattern "
                       + ("match" if len(dismissed) == 1 else "matches")
                       + " dismissed with a reason")

    rec.update({
        "score": score,
        "band": band(score),
        "hits": hits,
        "analysis": analysis,
        "taint_count": sum(1 for h in hits if h.get("engine") in FLOW_ENGINES),
        "cross_count": sum(1 for h in hits if h.get("engine") in CROSS_ENGINES),
        "witness_count": sum(1 for h in hits if h.get("witness")),
        "hit_count": sum(1 for h in hits if h.get("tier") == "sink"),
        "context_count": sum(1 for h in hits if h.get("tier") == "context"),
        "signal_count": sum(1 for h in hits if h.get("tier") == "signal"),
        "lead_count": sum(1 for h in hits if h.get("verdict") == "lead"),
        "finding_count": sum(1 for h in hits if h.get("verdict") == "finding"),
        "match_lines": sorted({h["line"] for h in hits}),
        "categories": dict(top_cats),
        "sources": sources,
        "entrypoints": entrypoints,
        "path_signals": path_signals[:4],
        "reasons": reasons[:6],
        "dismissed": dismissed,
        "context_notes": ctx.get("context_notes") or [],
        "deployment": ctx.get("deployment") or {},
        "score_parts": {
            "sinks": round(raw, 2),
            "taint_factor": round(taint_factor, 2),
            "path_factor": round(path_factor, 2),
            "dampener": round(damp * neg_factor, 2),
        },
    })
    return rec


def analyse_file(rec: dict, text: str, deep: bool = True) -> dict:
    """Single-file convenience wrapper: collect and score, with no cross-file phase."""
    return finalise(rec, collect(rec, text, deep=deep))


def _blank(rec: dict, reason: str) -> None:
    rec.update({"score": 0.0, "band": "minimal", "hits": [], "hit_count": 0,
                "match_lines": [], "categories": {}, "sources": [], "entrypoints": [],
                "path_signals": [], "reasons": [reason], "score_parts": {},
                "dismissed": [], "context_notes": [], "deployment": {}})


DISMISS_LABEL = {
    "reviewed": "a reviewer silenced it and wrote down why",
    "not-a-secret": "the literal is a public identifier, not a credential",
    "placeholder": "the literal is a placeholder",
    "capability": "the capability is there but nothing corroborates a flaw",
    "opt-in": "the setting is reachable only when the operator turns it on",
    "no-victim": "this deployment has no attacker for that class",
    "wrong-function": "the name belongs to a different function than the rule means",
}


def _dismiss_tally(files: list) -> dict:
    """Exact per-kind totals, read from the analysis block rather than the stored list.

    A file holding a thousand identical dismissals keeps twelve of them in the record,
    so counting the list would report twelve. The count is the claim; the list is the
    sample.
    """
    out: dict = {}
    for rec in files:
        exact = ((rec.get("analysis") or {}).get("dismissed_by")) or {}
        if exact:
            for kind, n in exact.items():
                out[kind] = out.get(kind, 0) + n
            continue
        for item in rec.get("dismissed") or []:
            out[item["kind"]] = out.get(item["kind"], 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def score_repo(root: Path, inventory: dict, log=lambda m: None, progress=None,
               deep: bool = True, cross: bool = True) -> dict:
    """Score every readable file, then resolve flow between them. Mutates the records."""
    files = inventory["files"]
    total = len(files)
    contexts: dict = {}
    by_path = {rec["path"].replace("\\", "/"): rec for rec in files}
    index = RepoIndex(list(by_path))
    cross_index = CrossIndex(index)

    # Who the attacker is, decided once for the whole repository. SSRF in a service is a
    # pivot into the internal network; the same line in a command-line tool is the user
    # talking to their own endpoint. Nothing in the line says which, so the deployment has
    # to be established before any of the findings can be judged.
    # Memoised, because the binding resolver asks for the same handful of shared modules
    # from every file that imports them, and asks for a path that does not exist on the
    # way to one that does. A miss is worth caching too: `./lib/core.mjs` resolving to
    # `.ts` means every caller tries the `.mjs` first.
    _seen: dict = {}
    _seen_bytes = [0]

    def _read(path: str) -> str:
        if path in _seen:
            return _seen[path]
        body, _ = read_text(root / path)
        body = body or ""
        if _seen_bytes[0] + len(body) < 12_000_000:
            _seen[path] = body
            _seen_bytes[0] += len(body)
        return body

    dep_ctx = deployment.classify([rec["path"].replace("\\", "/") for rec in files
                                   if rec.get("scanned")],
                                  _read, inventory.get("totals", {}).get("by_lang"))
    log("deployment: " + dep_ctx.describe())

    for i, rec in enumerate(files):
        if progress and i % 50 == 0:
            progress(i, total)
        if not rec.get("scanned"):
            _blank(rec, "not scanned (binary or unreadable)")
            continue
        text, _ = read_text(root / rec["path"])
        if not text:
            _blank(rec, "empty file")
            continue
        ctx = collect(rec, text, deep=deep, dep_ctx=dep_ctx, read=_read)
        finalise(rec, ctx)
        if ctx["facts"]:
            path = rec["path"].replace("\\", "/")
            contexts[path] = ctx
            if cross:
                facts = ctx["facts"]
                cross_index.add(path, rec["lang"], facts, facts["imports"], facts["exports"])

    cross_stats: dict = {"enabled": False}
    if cross and deep and contexts:
        log("linking " + str(len(contexts)) + " analysed files across module boundaries")
        cross_index.build_links()
        cross_index.close()

        # Flow coming back *out* of a module: a helper that returns untrusted data makes
        # its callers worth a second look, and that can only be known now.
        reverse = cross_index.tainted_returns()
        redone = 0
        for path, names in reverse.items():
            rec = by_path.get(path)
            if rec is None or redone >= MAX_REVERSE_FILES:
                continue
            text, _ = read_text(root / rec["path"])
            if not text:
                continue
            ctx = collect(rec, text, deep=True, dep_ctx=dep_ctx, read=_read,
                          tainted_returns=tuple(sorted(names)))
            finalise(rec, ctx)
            contexts[path] = ctx
            redone += 1
        if redone:
            log("re-analysed " + str(redone)
                + " callers of functions that return untrusted data")

        found = cross_index.findings()
        dropped_test_only = 0
        for path, items in found.items():
            rec = by_path.get(path)
            ctx = contexts.get(path)
            if rec is None or ctx is None:
                continue
            keep = []
            for item in items:
                # A flow that exists only in the test suite is a true dataflow fact and
                # useless: nodejs/node's own tests call execFile, which would put a
                # cross-file finding on lib/child_process.js reached from eight test files.
                entries = (item.cross or {}).get("entries") or []
                if entries and all(_is_harness(by_path.get(e.get("path"))) for e in entries):
                    dropped_test_only += 1
                    continue
                if not item.snippet:
                    item.snippet = _line_text(root / rec["path"], item.line)
                keep.append(item)
            ctx["cross_findings"] = keep
            finalise(rec, ctx)
        cross_stats = dict(cross_index.stats)
        cross_stats["enabled"] = True
        cross_stats["files_linked"] = len(found)
        cross_stats["reverse_reanalysed"] = redone
        cross_stats["test_only_dropped"] = dropped_test_only
        log("cross-file pass: " + str(cross_index.stats["findings"]) + " findings from "
            + str(cross_index.stats["resolved"]) + " resolved call sites")

    cat_totals: dict[str, dict] = {}
    rule_totals: dict[str, dict] = {}
    for rec in files:
        for h in rec.get("hits") or []:
            ct = cat_totals.setdefault(h["cat"], {"hits": 0, "files": set(), "top_weight": 0})
            ct["hits"] += 1
            ct["files"].add(rec["path"])
            ct["top_weight"] = max(ct["top_weight"], h["weight"])
            rt = rule_totals.setdefault(h["rule"], {
                "title": h["title"], "cat": h["cat"], "cwe": h["cwe"], "hits": 0, "files": set(),
            })
            rt["hits"] += 1
            rt["files"].add(rec["path"])

    categories = {}
    for cat, data in cat_totals.items():
        meta = rules.CATEGORIES.get(cat, {})
        categories[cat] = {
            "id": cat,
            "name": meta.get("name", cat),
            "cwe": meta.get("cwe", ""),
            "accent": meta.get("accent", "#888"),
            "hits": data["hits"],
            "file_count": len(data["files"]),
            "top_weight": data["top_weight"],
        }
    categories = dict(sorted(categories.items(),
                             key=lambda kv: (-kv[1]["top_weight"], -kv[1]["hits"])))

    top_rules = sorted(
        ({"id": rid, **{k: v for k, v in d.items() if k != "files"}, "file_count": len(d["files"])}
         for rid, d in rule_totals.items()),
        key=lambda r: -r["hits"],
    )[:25]

    bands = {"critical": 0, "high": 0, "medium": 0, "low": 0, "minimal": 0}
    for rec in files:
        bands[rec.get("band", "minimal")] += 1

    scored = [f for f in files if f.get("score", 0) > 0]
    parsed = [f for f in files if (f.get("analysis") or {}).get("engine") == "ast+taint"]
    summary = {
        "ast_files": len(parsed),
        "ast_ms": sum((f.get("analysis") or {}).get("ms", 0) for f in files),
        "taint_findings": sum(f.get("taint_count", 0) for f in files),
        # three different things, counted separately: a flow where every part is
        # established, a flow with a named gap, and a pattern match with no flow at all
        "confirmed_findings": sum(1 for f in files for h in (f.get("hits") or [])
                                  if h.get("verdict") == "finding"),
        "lead_findings": sum(1 for f in files for h in (f.get("hits") or [])
                             if h.get("verdict") == "lead"),
        "pattern_hits": sum(1 for f in files for h in (f.get("hits") or [])
                            if h.get("tier") == "sink" and not h.get("verdict")),
        "signal_hits": sum(f.get("signal_count", 0) for f in files),
        "regex_demoted": sum((f.get("analysis") or {}).get("regex_demoted", 0)
                             for f in files),
        # matches the context pass took off the board, each with a stated reason
        "dismissed": sum((f.get("analysis") or {}).get("dismissed", 0) or
                         len(f.get("dismissed") or []) for f in files),
        "dismissed_by": _dismiss_tally(files),
        "cross_findings": sum(f.get("cross_count", 0) for f in files),
        "witness_findings": sum(f.get("witness_count", 0) for f in files),
        "regex_dropped": sum((f.get("analysis") or {}).get("regex_dropped", 0) for f in files),
        "regex_superseded": sum((f.get("analysis") or {}).get("regex_superseded", 0)
                                for f in files),
        "sanitizer_suppressed": sum((f.get("analysis") or {}).get("suppressed", 0)
                                    for f in files),
        "text_not_code": sum((f.get("analysis") or {}).get("text_not_code", 0)
                             for f in files),
        "solver_queries": sum(((f.get("analysis") or {}).get("solver") or {}).get("queries", 0)
                              for f in files),
        "solver_ms": sum(((f.get("analysis") or {}).get("solver") or {}).get("solver_ms", 0)
                         for f in files),
        "paths_unreachable": sum(((f.get("analysis") or {}).get("solver") or {})
                                 .get("unreachable", 0) for f in files),
        "paths_validated": sum(((f.get("analysis") or {}).get("solver") or {})
                               .get("validated", 0) for f in files),
        "cross": cross_stats,
        "bands": bands,
        "flagged_files": len(scored),
        "total_hits": sum(f.get("hit_count", 0) for f in files),
        "entrypoint_files": sum(1 for f in files if f.get("entrypoints")),
        "source_files": sum(1 for f in files if f.get("sources")),
        "mean_score": round(sum(f["score"] for f in scored) / len(scored), 1) if scored else 0.0,
        "max_score": max((f.get("score", 0) for f in files), default=0.0),
        "deployment": {"kind": dep_ctx.kind, "confidence": dep_ctx.confidence,
                       "describe": dep_ctx.describe(),
                       "evidence": list(dep_ctx.evidence)},
    }
    log("scored " + str(total) + " files, " + str(summary["total_hits"]) + " hits")
    return {"categories": categories, "top_rules": top_rules, "summary": summary}


def _is_harness(rec) -> bool:
    """True when a file is test, example, vendored or generated code."""
    if not rec:
        return False
    return bool(rec.get("is_test") or rec.get("is_vendored") or rec.get("is_generated"))


def _line_text(path: Path, line: int) -> str:
    """One line of a file, for a finding whose evidence lives in a file we already left."""
    try:
        text, _ = read_text(path)
        if not text:
            return ""
        lines = text.split("\n")
        return lines[line - 1].strip()[:200] if 0 < line <= len(lines) else ""
    except Exception:                                        # pragma: no cover
        return ""
