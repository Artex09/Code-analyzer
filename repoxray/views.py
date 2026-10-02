"""Organisational views over one scan.

Adding a view later means writing one builder function and adding one VIEWS entry;
the frontend renders whatever shape the builder declares ("tree", "ranked", "groups").
"""
from __future__ import annotations

from . import rules

SUMMARY_FIELDS = (
    "path", "name", "dir", "lang", "kind", "lines", "size", "score", "band",
    "hit_count", "is_test", "is_vendored", "is_generated", "triage",
)

TRIAGE_STATES = ("confirmed", "looking", "dismissed")


def brief(rec: dict) -> dict:
    out = {k: rec.get(k) for k in SUMMARY_FIELDS}
    out["cats"] = list(rec.get("categories", {}).keys())[:4]
    out["reasons"] = rec.get("reasons", [])[:3]
    out["entry_kinds"] = sorted({e["kind"] for e in rec.get("entrypoints", [])})
    ai = rec.get("ai")
    if ai:
        out["ai"] = {
            "probability": ai.get("probability"),
            "confidence": ai.get("confidence"),
            "finding_count": len(ai.get("findings", [])),
            "headline": (ai.get("findings") or [{}])[0].get("title") if ai.get("findings") else ai.get("summary", "")[:90],
            "error": ai.get("error"),
        }
    return out


# ------------------------------------------------------------------ 1. layout

def view_tree(scan: dict) -> dict:
    """Standard directory layout, with risk rolled up into every folder."""
    root = {"name": scan["repo"]["repo"], "path": "", "type": "dir", "children": {},
            "files": 0, "lines": 0, "max_score": 0.0, "risk_sum": 0.0, "flagged": 0}

    for rec in scan["files"]:
        parts = rec["path"].split("/")
        node = root
        acc = []
        for part in parts[:-1]:
            acc.append(part)
            child = node["children"].get(part)
            if child is None:
                child = {"name": part, "path": "/".join(acc), "type": "dir", "children": {},
                         "files": 0, "lines": 0, "max_score": 0.0, "risk_sum": 0.0, "flagged": 0}
                node["children"][part] = child
            node = child
        node["children"][parts[-1]] = {"type": "file", **brief(rec)}

        node_path_parts = []
        walker = root
        walker["files"] += 1
        walker["lines"] += rec.get("lines", 0)
        walker["max_score"] = max(walker["max_score"], rec.get("score", 0))
        walker["risk_sum"] += rec.get("score", 0)
        walker["flagged"] += 1 if rec.get("score", 0) >= 35 else 0
        for part in parts[:-1]:
            node_path_parts.append(part)
            walker = walker["children"][part]
            walker["files"] += 1
            walker["lines"] += rec.get("lines", 0)
            walker["max_score"] = max(walker["max_score"], rec.get("score", 0))
            walker["risk_sum"] += rec.get("score", 0)
            walker["flagged"] += 1 if rec.get("score", 0) >= 35 else 0

    def finish(node):
        if node["type"] == "file":
            return node
        kids = [finish(c) for c in node["children"].values()]
        dirs = sorted([k for k in kids if k["type"] == "dir"], key=lambda k: -k["max_score"])
        files = sorted([k for k in kids if k["type"] == "file"], key=lambda k: -(k.get("score") or 0))
        node["children"] = dirs + files
        node["max_score"] = round(node["max_score"], 1)
        node["avg_score"] = round(node["risk_sum"] / node["files"], 1) if node["files"] else 0.0
        del node["risk_sum"]
        return node

    return {"shape": "tree", "root": finish(root)}


# ------------------------------------------------------------- 2. risk ranked

def view_risk(scan: dict) -> dict:
    """Every file, highest risk first, bucketed by band."""
    order = ["critical", "high", "medium", "low", "minimal"]
    buckets: dict[str, list] = {k: [] for k in order}
    for rec in sorted(scan["files"], key=lambda r: -(r.get("score") or 0)):
        if rec.get("kind") == "artifact" and not rec.get("score"):
            continue
        buckets[rec.get("band", "minimal")].append(brief(rec))
    groups = []
    for key in order:
        items = buckets[key]
        if not items:
            continue
        groups.append({
            "key": key,
            "label": key.upper(),
            "count": len(items),                 # files in this band, before the display cap
            "items": items if key != "minimal" else items[:250],
            "truncated": key == "minimal" and len(items) > 250,
        })
    return {"shape": "groups", "groups": groups, "group_style": "band"}


# ------------------------------------------------- 3. vulnerability classes

def view_classes(scan: dict) -> dict:
    """Files grouped under the weakness class their matches belong to."""
    per_cat: dict[str, list] = {}
    for rec in scan["files"]:
        for cat in rec.get("categories", {}):
            per_cat.setdefault(cat, []).append(rec)

    groups = []
    for cat, meta in scan["categories"].items():
        recs = sorted(per_cat.get(cat, []), key=lambda r: -(r.get("categories", {}).get(cat, 0)))
        items = []
        for rec in recs:
            evidence = [h for h in rec.get("hits", []) if h["cat"] == cat]
            item = brief(rec)
            item["evidence"] = [
                {"line": h["line"], "title": h["title"], "snippet": h["snippet"],
                 "weight": h["weight"], "why": h["why"], "soft": h.get("soft", False)}
                for h in evidence[:6]
            ]
            item["evidence_count"] = len(evidence)
            item["cat_weight"] = round(rec.get("categories", {}).get(cat, 0), 1)
            items.append(item)
        groups.append({
            "key": cat,
            "label": meta["name"],
            "cwe": meta["cwe"],
            "accent": meta["accent"],
            "count": meta["file_count"],
            "hits": meta["hits"],
            "items": items,
        })
    return {"shape": "groups", "groups": groups, "group_style": "class"}


# ---------------------------------------------------------- 4. attack surface

def view_surface(scan: dict) -> dict:
    """Where the outside world touches this codebase."""
    by_kind: dict[str, list] = {}
    for rec in scan["files"]:
        for ep in rec.get("entrypoints", []):
            by_kind.setdefault(ep["kind"], []).append((rec, ep))

    groups = []
    for kind in sorted(by_kind, key=lambda k: -len(by_kind[k])):
        items = []
        for rec, ep in sorted(by_kind[kind], key=lambda pair: -(pair[0].get("score") or 0)):
            item = brief(rec)
            item["entry_detail"] = {"count": ep["count"], "line": ep["line"], "id": ep["id"]}
            items.append(item)
        groups.append({"key": "ep:" + kind, "label": kind, "count": len(items),
                       "accent": "#5ac8fa", "items": items})

    readers = [brief(r) for r in sorted(
        (r for r in scan["files"] if r.get("sources")),
        key=lambda r: -(r.get("score") or 0))]
    if readers:
        groups.append({"key": "sources", "label": "reads untrusted input",
                       "count": len(readers), "accent": "#ffd60a", "items": readers[:200]})

    manifests = [brief(r) for r in scan["files"] if r.get("kind") in ("manifest", "config")]
    manifests.sort(key=lambda r: -(r.get("score") or 0))
    if manifests:
        groups.append({"key": "config", "label": "manifests and configuration",
                       "count": len(manifests), "accent": "#ced4da", "items": manifests[:200]})
    return {"shape": "groups", "groups": groups, "group_style": "surface"}


# ------------------------------------------------------------- 5. directory heat

def view_hotspots(scan: dict) -> dict:
    """Directories ranked by concentrated risk, so you can pick a region to dig into."""
    agg: dict[str, dict] = {}
    for rec in scan["files"]:
        d = rec.get("dir") or "(root)"
        slot = agg.setdefault(d, {"dir": d, "files": 0, "lines": 0, "risk": 0.0,
                                  "max_score": 0.0, "hits": 0, "cats": {}, "top": []})
        slot["files"] += 1
        slot["lines"] += rec.get("lines", 0)
        slot["risk"] += rec.get("score", 0)
        slot["hits"] += rec.get("hit_count", 0)
        slot["max_score"] = max(slot["max_score"], rec.get("score", 0))
        for cat, w in rec.get("categories", {}).items():
            slot["cats"][cat] = round(slot["cats"].get(cat, 0) + w, 1)
        if rec.get("score", 0) >= 20:
            slot["top"].append(brief(rec))

    rows = []
    for slot in agg.values():
        slot["avg_score"] = round(slot["risk"] / slot["files"], 1) if slot["files"] else 0
        slot["risk"] = round(slot["risk"], 1)
        slot["max_score"] = round(slot["max_score"], 1)
        slot["top"] = sorted(slot["top"], key=lambda r: -(r.get("score") or 0))[:8]
        slot["cats"] = dict(sorted(slot["cats"].items(), key=lambda kv: -kv[1])[:5])
        slot["cat_names"] = [rules.CATEGORIES.get(c, {}).get("name", c) for c in slot["cats"]]
        rows.append(slot)
    rows.sort(key=lambda r: (-r["max_score"], -r["risk"]))
    return {"shape": "hotspots", "rows": rows[:120]}


# ------------------------------------------------------------- 6. AI verdicts

def view_ai(scan: dict) -> dict:
    """Files the model actually read, ordered by its own probability judgement."""
    reviewed = [r for r in scan["files"] if r.get("ai")]
    reviewed.sort(key=lambda r: -((r["ai"].get("probability") or 0)))
    items = []
    for rec in reviewed:
        ai = rec["ai"]
        item = brief(rec)
        item["ai_full"] = {
            "probability": ai.get("probability"),
            "confidence": ai.get("confidence"),
            "summary": ai.get("summary", ""),
            "findings": ai.get("findings", []),
            "safe_notes": ai.get("safe_notes", []),
            "model": ai.get("model"),
            "backend": ai.get("backend"),
            "elapsed": ai.get("elapsed"),
            "error": ai.get("error"),
        }
        items.append(item)
    queue = [brief(r) for r in sorted(scan["files"], key=lambda r: -(r.get("score") or 0))
             if not r.get("ai") and r.get("score", 0) >= 20][:40]
    return {"shape": "ai", "items": items, "queue": queue,
            "state": scan.get("ai_state", {"status": "idle"})}


def view_triage(scan: dict) -> dict:
    """What you marked while reading: confirmed leads, in progress, dismissed."""
    labels = {
        "confirmed": ("confirmed leads", "#ff4d4f"),
        "looking": ("still looking", "#ffb454"),
        "dismissed": ("dismissed", "#5d6672"),
    }
    groups = []
    for state in TRIAGE_STATES:
        items = [brief(r) for r in sorted(
            (r for r in scan["files"] if r.get("triage") == state),
            key=lambda r: -(r.get("score") or 0))]
        label, accent = labels[state]
        groups.append({"key": "tri:" + state, "label": label, "accent": accent,
                       "count": len(items), "items": items})
    unmarked = sum(1 for r in scan["files"]
                   if not r.get("triage") and (r.get("score") or 0) >= 35)
    return {"shape": "groups", "groups": [g for g in groups if g["count"]],
            "group_style": "triage", "unmarked": unmarked}


VIEWS = [
    {"id": "risk", "name": "Risk Ranked", "glyph": "01",
     "tagline": "every file ordered by likelihood of containing a flaw",
     "builder": view_risk},
    {"id": "tree", "name": "Standard Layout", "glyph": "02",
     "tagline": "the repository as it is on disk, with risk rolled up per folder",
     "builder": view_tree},
    {"id": "classes", "name": "Vulnerability Classes", "glyph": "03",
     "tagline": "grouped by weakness type with the matching evidence",
     "builder": view_classes},
    {"id": "surface", "name": "Attack Surface", "glyph": "04",
     "tagline": "entrypoints, untrusted input readers, configuration",
     "builder": view_surface},
    {"id": "hotspots", "name": "Directory Heat", "glyph": "05",
     "tagline": "regions of the tree where risk concentrates",
     "builder": view_hotspots},
    {"id": "ai", "name": "AI Verdicts", "glyph": "06",
     "tagline": "model-read files with per-finding reasoning",
     "builder": view_ai},
    {"id": "triage", "name": "Triage Board", "glyph": "07",
     "tagline": "what you confirmed, are still reading, or ruled out",
     "builder": view_triage},
]

VIEW_INDEX = {v["id"]: v for v in VIEWS}


def view_catalog() -> list:
    return [{k: v for k, v in view.items() if k != "builder"} for view in VIEWS]


def build_view(view_id: str, scan: dict) -> dict:
    view = VIEW_INDEX.get(view_id)
    if not view:
        raise KeyError("unknown view " + view_id)
    payload = view["builder"](scan)
    payload["id"] = view["id"]
    payload["name"] = view["name"]
    payload["tagline"] = view["tagline"]
    return payload
