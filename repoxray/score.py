"""Turn pattern matches into a per-file risk score plus the evidence behind it."""
from __future__ import annotations

import bisect
import math
from pathlib import Path

from . import rules
from .inventory import read_text

MAX_HITS_PER_RULE = 8       # evidence lines kept per rule, per file
MAX_HITS_PER_FILE = 60

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


def analyse_file(rec: dict, text: str) -> dict:
    """Attach hits, sources, entrypoints, path signals and a score to one file record."""
    lang = rec["lang"]
    offsets = _line_index(text)
    hits: list[dict] = []
    per_rule_contrib: dict[str, float] = {}
    cat_weight: dict[str, float] = {}

    for rule in rules.COMPILED_RULES:
        if not _lang_applies(rule["langs"], lang):
            continue
        # generic (language-less) rules only make sense on text we can read
        matches = list(rule["rx"].finditer(text))
        if not matches:
            continue
        lines_seen: list[int] = []
        kept = 0
        for m in matches:
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
                    "cwe": rule["cwe"], "weight": weight, "line": ln,
                    "snippet": snip, "why": rule["why"], "soft": soft,
                })
                kept += 1
        n = len(lines_seen)
        eff_weight = rule["weight"]
        if rule["cat"] == "secret" and hits and all(h.get("soft") for h in hits if h["rule"] == rule["id"]):
            eff_weight = max(1, eff_weight - 5)
        contrib = eff_weight * min(1 + 0.30 * math.log2(n) if n > 1 else 1.0, 2.2)
        per_rule_contrib[rule["id"]] = round(contrib, 2)
        cat_weight[rule["cat"]] = round(cat_weight.get(rule["cat"], 0) + contrib, 2)

    sources = []
    for src in rules.COMPILED_SOURCES:
        if not _lang_applies(src["langs"], lang):
            continue
        m = src["rx"].search(text)
        if m:
            sources.append({"id": src["id"], "line": _line_of(offsets, m.start())})

    entrypoints = []
    for ep in rules.COMPILED_ENTRYPOINTS:
        if not _lang_applies(ep["langs"], lang):
            continue
        found = list(ep["rx"].finditer(text))
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

    raw = sum(per_rule_contrib.values())
    reasons: list[str] = []

    has_source = bool(sources)
    has_sink = raw > 0
    taint_factor = 1.0
    if has_source and has_sink:
        taint_factor *= 1.40
        reasons.append("untrusted input and a dangerous sink in the same file")
    if entrypoints and has_sink:
        taint_factor *= 1.15
        reasons.append("reachable from a declared entrypoint")

    # path signals matter, but should not invent risk in a file with no findings at all
    effective_path = path_bonus if has_sink else path_bonus * 0.25
    score_raw = (raw * taint_factor) + effective_path

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
    score_raw *= damp * neg_factor
    if neg_labels:
        reasons.append(neg_labels[0])

    score = 100.0 * (1.0 - math.exp(-score_raw / 28.0))
    score = round(min(99.0, score), 1)

    top_cats = sorted(cat_weight.items(), key=lambda kv: -kv[1])
    for cat, _w in top_cats[:3]:
        reasons.insert(0, rules.CATEGORIES.get(cat, {}).get("name", cat))
    if path_signals and not has_sink:
        reasons.append(path_signals[0]["label"] + " (name only)")

    rec.update({
        "score": score,
        "band": band(score),
        "hits": hits,
        "hit_count": sum(1 for _ in hits),
        "match_lines": sorted({h["line"] for h in hits}),
        "categories": dict(top_cats),
        "sources": sources,
        "entrypoints": entrypoints,
        "path_signals": path_signals[:4],
        "reasons": reasons[:6],
        "score_parts": {
            "sinks": round(raw, 2),
            "taint_factor": round(taint_factor, 2),
            "path": round(effective_path, 2),
            "dampener": round(damp * neg_factor, 2),
        },
    })
    return rec


def score_repo(root: Path, inventory: dict, log=lambda m: None, progress=None) -> dict:
    """Score every readable file. Mutates and returns the inventory file records."""
    files = inventory["files"]
    total = len(files)
    cat_totals: dict[str, dict] = {}
    rule_totals: dict[str, dict] = {}

    for i, rec in enumerate(files):
        if progress and i % 50 == 0:
            progress(i, total)
        if not rec.get("scanned"):
            rec.update({"score": 0.0, "band": "minimal", "hits": [], "hit_count": 0,
                        "match_lines": [], "categories": {}, "sources": [], "entrypoints": [],
                        "path_signals": [], "reasons": ["not scanned (binary or unreadable)"],
                        "score_parts": {}})
            continue
        text, _ = read_text(root / rec["path"])
        if not text:
            rec.update({"score": 0.0, "band": "minimal", "hits": [], "hit_count": 0,
                        "match_lines": [], "categories": {}, "sources": [], "entrypoints": [],
                        "path_signals": [], "reasons": ["empty file"], "score_parts": {}})
            continue
        analyse_file(rec, text)

        for h in rec["hits"]:
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
    summary = {
        "bands": bands,
        "flagged_files": len(scored),
        "total_hits": sum(f.get("hit_count", 0) for f in files),
        "entrypoint_files": sum(1 for f in files if f.get("entrypoints")),
        "source_files": sum(1 for f in files if f.get("sources")),
        "mean_score": round(sum(f["score"] for f in scored) / len(scored), 1) if scored else 0.0,
        "max_score": max((f.get("score", 0) for f in files), default=0.0),
    }
    log("scored " + str(total) + " files, " + str(summary["total_hits"]) + " pattern hits")
    return {"categories": categories, "top_rules": top_rules, "summary": summary}
