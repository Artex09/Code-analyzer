"""Flask application: JSON API for the engine plus the single-page console."""
from __future__ import annotations

import os
import webbrowser
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request

from . import ai as ai_mod
from . import engine, rules, store, views
from .inventory import read_text

app = Flask(__name__)
# Flask 3 moved this off app.config; without it jsonify re-sorts every dict
# alphabetically and the carefully ranked category / language orders are lost.
app.json.sort_keys = False


# --------------------------------------------------------------------- helpers

def _scan_or_404(scan_id: str):
    scan = store.load_scan(scan_id)
    if not scan:
        return None, (jsonify({"error": "scan not found", "id": scan_id}), 404)
    return scan, None


def _header(scan: dict) -> dict:
    """Everything the UI chrome needs, without shipping the whole file list."""
    return {
        "id": scan["id"],
        "created_at": scan.get("created_at"),
        "repo": scan["repo"],
        "meta": scan.get("meta", {}),
        "fetch": scan.get("fetch", {}),
        "totals": scan.get("totals", {}),
        "skipped": scan.get("skipped", {}),
        "summary": dict(scan.get("summary", {}), histogram=_histogram(scan)),
        "categories": scan.get("categories", {}),
        "top_rules": scan.get("top_rules", []),
        "rule_counts": scan.get("rule_counts", {}),
        "ai_state": scan.get("ai_state", {}),
        "ai_reviewed": sum(1 for f in scan.get("files", []) if f.get("ai")),
        "triage_counts": _triage_counts(scan),
        "source_root": scan.get("source_root"),
        "options": scan.get("options", {}),
    }


def _histogram(scan: dict, buckets: int = 20) -> list:
    """Score distribution in 5-point buckets, for the rail sparkline."""
    out = [0] * buckets
    for rec in scan.get("files", []):
        if rec.get("kind") == "artifact":
            continue
        idx = min(buckets - 1, int((rec.get("score") or 0) // (100 / buckets)))
        out[idx] += 1
    return out


def _triage_counts(scan: dict) -> dict:
    counts = {state: 0 for state in views.TRIAGE_STATES}
    for rec in scan.get("files", []):
        state = rec.get("triage")
        if state in counts:
            counts[state] += 1
    return counts


def _safe_source_path(scan: dict, rel: str) -> Path | None:
    root = Path(scan["source_root"]).resolve()
    try:
        target = (root / rel).resolve()
        target.relative_to(root)
    except (ValueError, OSError):
        return None
    return target if target.is_file() else None


# ----------------------------------------------------------------------- pages

@app.get("/")
def index():
    return render_template("index.html")


# ------------------------------------------------------------------------- api

@app.get("/api/bootstrap")
def bootstrap():
    ollama_models = ai_mod.list_ollama_models()
    claude_ok, claude_note = ai_mod.AnthropicBackend().available()
    return jsonify({
        "views": views.view_catalog(),
        "rules": rules.rule_count(),
        "categories": {k: {"name": v["name"], "cwe": v["cwe"], "accent": v["accent"]}
                       for k, v in rules.CATEGORIES.items()},
        "history": store.list_scans(),
        "backends": {
            "ollama": {"available": bool(ollama_models), "models": ollama_models,
                       "note": "local, free, slower" if ollama_models
                               else "ollama not reachable on 127.0.0.1:11434"},
            "claude": {"available": claude_ok, "models": ["claude-opus-5", "claude-sonnet-5"],
                       "note": claude_note},
        },
    })


@app.post("/api/scan")
def api_scan():
    body = request.get_json(silent=True) or {}
    url = (body.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url is required"}), 400
    job = engine.start_scan(url, {
        "refresh": bool(body.get("refresh")),
        "metadata": bool(body.get("metadata", True)),
    })
    return jsonify(job.snapshot()), 202


@app.get("/api/job/<job_id>")
def api_job(job_id: str):
    job = engine.get_job(job_id)
    if not job:
        return jsonify({"error": "job not found"}), 404
    return jsonify(job.snapshot())


@app.get("/api/disk")
def api_disk():
    """Walks every cloned file, so it is deliberately not part of bootstrap."""
    return jsonify(store.disk_usage())


@app.get("/api/history")
def api_history():
    return jsonify({"history": store.list_scans()})


@app.get("/api/scan/<scan_id>")
def api_scan_header(scan_id: str):
    scan, err = _scan_or_404(scan_id)
    if err:
        return err
    return jsonify(_header(scan))


@app.delete("/api/scan/<scan_id>")
def api_scan_delete(scan_id: str):
    drop = request.args.get("source") in ("1", "true", "yes")
    existed = store.delete_scan(scan_id, drop_source=drop)
    return jsonify({"deleted": existed, "source_removed": drop})


@app.get("/api/scan/<scan_id>/view/<view_id>")
def api_view(scan_id: str, view_id: str):
    scan, err = _scan_or_404(scan_id)
    if err:
        return err
    try:
        payload = views.build_view(view_id, scan)
    except KeyError:
        return jsonify({"error": "unknown view", "view": view_id}), 404
    return jsonify(payload)


@app.get("/api/scan/<scan_id>/file")
def api_file(scan_id: str):
    scan, err = _scan_or_404(scan_id)
    if err:
        return err
    rel = request.args.get("path", "")
    rec = next((f for f in scan["files"] if f["path"] == rel), None)
    if rec is None:
        return jsonify({"error": "file not in scan", "path": rel}), 404
    target = _safe_source_path(scan, rel)
    if target is None:
        return jsonify({"error": "file missing from local source copy", "path": rel}), 410

    text, truncated = read_text(target)
    html_lines = _highlight(text, rel, rec.get("lang", ""))
    return jsonify({
        "path": rel,
        "record": {k: v for k, v in rec.items() if k != "hits"},
        "hits": rec.get("hits", []),
        "ai": rec.get("ai"),
        "lines": html_lines,
        "truncated": truncated,
        "github_url": _github_file_url(scan, rel),
    })


@app.post("/api/scan/<scan_id>/deepdive")
def api_deepdive(scan_id: str):
    scan, err = _scan_or_404(scan_id)
    if err:
        return err
    body = request.get_json(silent=True) or {}
    job = engine.start_deep_dive(scan_id, {
        "backend": body.get("backend", "ollama"),
        "model": body.get("model", ""),
        "num_ctx": body.get("num_ctx", 8192),
        "top_n": body.get("top_n", 10),
        "min_score": body.get("min_score", 15),
        "skip_reviewed": body.get("skip_reviewed", True),
        "include_tests": body.get("include_tests", False),
        "paths": body.get("paths") or [],
    })
    return jsonify(job.snapshot()), 202


@app.post("/api/scan/<scan_id>/triage")
def api_triage(scan_id: str):
    """Mark a file confirmed / looking / dismissed. Empty state clears the mark."""
    scan, err = _scan_or_404(scan_id)
    if err:
        return err
    body = request.get_json(silent=True) or {}
    rel = body.get("path", "")
    state = (body.get("state") or "").strip().lower()
    if state and state not in views.TRIAGE_STATES:
        return jsonify({"error": "unknown triage state", "state": state,
                        "allowed": list(views.TRIAGE_STATES)}), 400
    rec = next((f for f in scan["files"] if f["path"] == rel), None)
    if rec is None:
        return jsonify({"error": "file not in scan", "path": rel}), 404

    if state:
        rec["triage"] = state
    else:
        rec.pop("triage", None)
    with engine.scan_lock(scan_id):
        store.save_scan(scan)
    return jsonify({"path": rel, "state": state, "counts": _triage_counts(scan)})


@app.get("/api/scan/<scan_id>/index")
def api_index(scan_id: str):
    """Compact list of every file, for client-side fuzzy jumping."""
    scan, err = _scan_or_404(scan_id)
    if err:
        return err
    return jsonify({"files": [
        {"p": f["path"], "s": f.get("score", 0), "b": f.get("band", "minimal"),
         "l": f.get("lang", ""), "h": f.get("hit_count", 0), "t": f.get("triage", "")}
        for f in scan["files"] if f.get("kind") != "artifact"
    ]})


@app.get("/api/scan/<scan_id>/report.md")
def api_report(scan_id: str):
    scan, err = _scan_or_404(scan_id)
    if err:
        return err
    md = _markdown_report(scan)
    return Response(md, mimetype="text/markdown",
                    headers={"Content-Disposition":
                             'attachment; filename="repoxray-' + scan_id + '.md"'})


# ------------------------------------------------------------------ rendering

def _highlight(text: str, rel: str, lang: str) -> list:
    """Return a list of HTML strings, one per source line."""
    if not text:
        return []
    try:
        from pygments import highlight
        from pygments.formatters import HtmlFormatter
        from pygments.lexers import get_lexer_by_name, guess_lexer_for_filename
        from pygments.util import ClassNotFound
        try:
            lexer = guess_lexer_for_filename(rel, text, stripnl=False)
        except ClassNotFound:
            try:
                lexer = get_lexer_by_name(lang or "text", stripnl=False)
            except ClassNotFound:
                from pygments.lexers.special import TextLexer
                lexer = TextLexer(stripnl=False)
        body = highlight(text, lexer, HtmlFormatter(nowrap=True, classprefix="pg-"))
        return body.split("\n")
    except Exception:
        import html as html_mod
        return [html_mod.escape(line) for line in text.split("\n")]


def pygments_css() -> str:
    try:
        from pygments.formatters import HtmlFormatter
        return HtmlFormatter(style="native", classprefix="pg-").get_style_defs(".code-body")
    except Exception:
        return ""


@app.get("/static/pygments.css")
def pygments_style():
    return Response(pygments_css(), mimetype="text/css")


def _github_file_url(scan: dict, rel: str) -> str:
    repo = scan["repo"]
    ref = repo.get("ref") or (scan.get("fetch") or {}).get("branch") or "HEAD"
    sub = repo.get("subpath") or ""
    full = (sub + "/" + rel) if sub else rel
    return "https://github.com/" + repo["slug"] + "/blob/" + ref + "/" + full


def _markdown_report(scan: dict) -> str:
    s = scan.get("summary", {})
    t = scan.get("totals", {})
    lines = [
        "# RepoXray report: " + scan["repo"]["slug"],
        "",
        "- scanned: " + str(scan.get("created_at")),
        "- source: " + scan["repo"].get("html_url", ""),
        "- ref: " + str(scan["repo"].get("ref") or (scan.get("fetch") or {}).get("branch") or ""),
        "- commit: " + str((scan.get("fetch") or {}).get("commit", ""))[:12],
        "- files: " + str(t.get("files")) + " (" + str(t.get("lines")) + " lines)",
        "- flagged: " + str(s.get("flagged_files")) + "  |  critical " +
        str((s.get("bands") or {}).get("critical", 0)) + ", high " +
        str((s.get("bands") or {}).get("high", 0)),
        "",
        "## Weakness classes seen",
        "",
        "| class | CWE | files | hits |",
        "| --- | --- | --- | --- |",
    ]
    for cat in scan.get("categories", {}).values():
        lines.append("| " + cat["name"] + " | " + cat["cwe"] + " | " + str(cat["file_count"])
                     + " | " + str(cat["hits"]) + " |")

    counts = _triage_counts(scan)
    if any(counts.values()):
        lines += ["", "## Triage", "",
                  "- confirmed: " + str(counts["confirmed"])
                  + "  |  still looking: " + str(counts["looking"])
                  + "  |  dismissed: " + str(counts["dismissed"])]

    # confirmed leads first, then anything still open, dismissed last
    rank = {"confirmed": 0, "looking": 1, "": 2, None: 2, "dismissed": 3}
    ranked = sorted(scan["files"],
                    key=lambda r: (rank.get(r.get("triage"), 2), -(r.get("score") or 0)))
    lines += ["", "## Priority files", ""]
    for rec in ranked[:30]:
        if not rec.get("score") and not rec.get("triage"):
            break
        mark = rec.get("triage")
        lines.append("### " + rec["path"] + "  -  " + str(rec["score"]) + "/100 ("
                     + rec["band"] + (", " + mark.upper() if mark else "") + ")")
        if rec.get("reasons"):
            lines.append("")
            lines.append("_" + "; ".join(rec["reasons"]) + "_")
        lines.append("")
        for h in rec.get("hits", [])[:10]:
            lines.append("- `L" + str(h["line"]) + "` **" + h["title"] + "** ("
                         + (h["cwe"] or h["cat"]) + "): `" + h["snippet"][:160] + "`")
        ai = rec.get("ai")
        if ai and not ai.get("error"):
            lines += ["", "**AI verdict** " + str(ai.get("probability")) + "% ("
                      + str(ai.get("confidence")) + " confidence, " + str(ai.get("model")) + ")", ""]
            if ai.get("summary"):
                lines.append("> " + ai["summary"])
                lines.append("")
            for f in ai.get("findings", []):
                lines.append("- **" + f["title"] + "** [" + f["severity"] + "] lines "
                             + ", ".join(str(x) for x in f["lines"]))
                if f.get("explanation"):
                    lines.append("  - " + f["explanation"])
                if f.get("attack_sketch"):
                    lines.append("  - attack: " + f["attack_sketch"])
                if f.get("needs_to_confirm"):
                    lines.append("  - to confirm: " + f["needs_to_confirm"])
            for note in ai.get("safe_notes", [])[:4]:
                lines.append("- (safe) " + note)
        lines.append("")
    lines += ["", "---", "", "Generated by RepoXray. Pattern hits are leads, not proof:",
              "confirm exploitability before reporting anything."]
    return "\n".join(lines)


def create_app() -> Flask:
    store.ensure_dirs()
    return app


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="RepoXray - GitHub source triage console")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7331)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    store.ensure_dirs()
    url = "http://" + ("127.0.0.1" if args.host in ("0.0.0.0", "::") else args.host) \
        + ":" + str(args.port) + "/"

    # Windows lets a second process bind the same port, which silently splits state
    # between two servers. Detect a live instance and hand over to it instead.
    import socket
    probe = socket.socket()
    probe.settimeout(0.6)
    if probe.connect_ex(("127.0.0.1", args.port)) == 0:
        probe.close()
        print("RepoXray is already running on " + url)
        print("Opening that instance. Use --port to run a second one.")
        if not args.no_browser:
            try:
                webbrowser.open(url)
            except Exception:
                pass
        return
    probe.close()

    print("RepoXray listening on " + url)
    print("  rules: " + str(rules.rule_count()))
    print("  data:  " + str(store.DATA_DIR))
    if not args.no_browser and not os.environ.get("WERKZEUG_RUN_MAIN"):
        try:
            webbrowser.open(url)
        except Exception:
            pass
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True,
            use_reloader=args.debug)


if __name__ == "__main__":
    main()
