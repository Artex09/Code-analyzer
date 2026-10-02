"""Job orchestration: fetch + inventory + score, and the AI deep-dive pass."""
from __future__ import annotations

import threading
import time
import traceback
from pathlib import Path

from . import ai as ai_mod
from . import rules, store
from .fetch import FetchError, RepoSpec, fetch_repo, parse_github_url, repo_metadata
from .inventory import build_inventory, read_text
from .score import score_repo

JOBS: dict = {}
_JOBS_LOCK = threading.Lock()
_SCAN_LOCKS: dict = {}


class Job:
    def __init__(self, kind: str, label: str):
        self.id = kind + "-" + store.new_scan_id(label)
        self.kind = kind
        self.label = label
        self.status = "queued"
        self.phase = "queued"
        self.message = "waiting to start"
        self.pct = 0
        self.log: list = []
        self.scan_id: str | None = None
        self.error: str | None = None
        self.started = time.time()
        self.finished: float | None = None
        self.extra: dict = {}
        self._lock = threading.Lock()

    def say(self, message: str, phase: str | None = None, pct: int | None = None) -> None:
        with self._lock:
            if phase:
                self.phase = phase
            if pct is not None:
                self.pct = max(0, min(100, int(pct)))
            self.message = message
            self.log.append({"t": round(time.time() - self.started, 1), "m": message})
            del self.log[:-200]

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "id": self.id, "kind": self.kind, "label": self.label, "status": self.status,
                "phase": self.phase, "message": self.message, "pct": self.pct,
                "log": list(self.log[-60:]), "scan_id": self.scan_id, "error": self.error,
                "elapsed": round((self.finished or time.time()) - self.started, 1),
                "extra": dict(self.extra),
            }


def register(job: Job) -> Job:
    with _JOBS_LOCK:
        JOBS[job.id] = job
        if len(JOBS) > 40:
            for key in sorted(JOBS, key=lambda k: JOBS[k].started)[:10]:
                if JOBS[key].status in ("done", "error"):
                    JOBS.pop(key, None)
    return job


def get_job(job_id: str) -> Job | None:
    return JOBS.get(job_id)


def scan_lock(scan_id: str) -> threading.Lock:
    with _JOBS_LOCK:
        return _SCAN_LOCKS.setdefault(scan_id, threading.Lock())


# ------------------------------------------------------------------ full scan

def start_scan(url: str, options: dict | None = None) -> Job:
    options = options or {}
    job = register(Job("scan", url.strip()[:120]))
    threading.Thread(target=_run_scan, args=(job, url, options), daemon=True).start()
    return job


def _run_scan(job: Job, url: str, options: dict) -> None:
    job.status = "running"
    try:
        spec: RepoSpec = parse_github_url(url)
        job.say("target " + spec.slug + (" @ " + spec.ref if spec.ref else ""), "resolve", 3)

        store.ensure_dirs()
        job.say("fetching source", "fetch", 6)
        root, fetch_info = fetch_repo(
            spec, store.REPOS_DIR,
            log=lambda m: job.say(m, "fetch", 10),
            refresh=bool(options.get("refresh")),
        )
        job.say("source at " + str(root), "fetch", 22)

        meta = repo_metadata(spec) if options.get("metadata", True) else {}

        job.say("walking tree", "inventory", 26)
        inv = build_inventory(
            root,
            log=lambda m: job.say(m, "inventory", 34),
            progress=lambda n: job.say("indexed " + str(n) + " files", "inventory",
                                       min(44, 26 + n // 120)),
        )
        if not inv["files"]:
            raise FetchError("No readable files found in the fetched source.")

        job.say("matching " + str(rules.rule_count()["sinks"]) + " sink rules", "score", 46)

        def score_progress(i, total):
            job.say("scored " + str(i) + "/" + str(total), "score",
                    46 + int(48 * (i / max(1, total))))

        analysis = score_repo(root, inv, log=lambda m: job.say(m, "score", 92),
                              progress=score_progress)

        scan = {
            "id": store.new_scan_id(spec.slug),
            "created_at": store.now_iso(),
            "input_url": url.strip(),
            "repo": {
                "owner": spec.owner, "repo": spec.repo, "ref": spec.ref,
                "slug": spec.slug, "subpath": spec.subpath,
                "html_url": meta.get("html_url") or ("https://github.com/" + spec.slug),
            },
            "meta": meta,
            "fetch": fetch_info,
            "source_root": str(root),
            "totals": inv["totals"],
            "skipped": inv["skipped"],
            "files": inv["files"],
            "categories": analysis["categories"],
            "top_rules": analysis["top_rules"],
            "summary": analysis["summary"],
            "rule_counts": rules.rule_count(),
            "options": options,
            "ai_state": {"status": "idle", "done": 0, "total": 0, "message": "no AI pass yet"},
        }
        job.say("writing scan record", "save", 96)
        store.save_scan(scan)
        job.scan_id = scan["id"]
        job.extra["summary"] = scan["summary"]
        job.say(
            "done: " + str(scan["totals"]["files"]) + " files, "
            + str(scan["summary"]["flagged_files"]) + " flagged, top score "
            + str(scan["summary"]["max_score"]), "done", 100,
        )
        job.status = "done"
    except FetchError as exc:
        job.status = "error"
        job.error = str(exc)
        job.say("failed: " + str(exc), "error", 100)
    except Exception as exc:  # noqa: BLE001 - surface anything to the UI
        job.status = "error"
        job.error = type(exc).__name__ + ": " + str(exc)
        job.say("failed: " + job.error, "error", 100)
        job.extra["traceback"] = traceback.format_exc()[-2000:]
    finally:
        job.finished = time.time()


# --------------------------------------------------------------- AI deep dive

def pick_candidates(scan: dict, top_n: int, min_score: float, skip_reviewed: bool,
                    include_tests: bool) -> list:
    pool = []
    for rec in scan["files"]:
        if rec.get("score", 0) < min_score or not rec.get("scanned"):
            continue
        if skip_reviewed and rec.get("ai"):
            continue
        if not include_tests and (rec.get("is_test") or rec.get("is_vendored")
                                  or rec.get("is_generated")):
            continue
        pool.append(rec)
    pool.sort(key=lambda r: -(r.get("score") or 0))
    return pool[:max(1, top_n)]


def start_deep_dive(scan_id: str, options: dict | None = None) -> Job:
    options = options or {}
    job = register(Job("deepdive", scan_id))
    job.scan_id = scan_id
    threading.Thread(target=_run_deep_dive, args=(job, scan_id, options), daemon=True).start()
    return job


def _run_deep_dive(job: Job, scan_id: str, options: dict) -> None:
    job.status = "running"
    lock = scan_lock(scan_id)
    if not lock.acquire(blocking=False):
        job.status = "error"
        job.error = "another AI pass is already running for this scan"
        job.say(job.error, "error", 100)
        job.finished = time.time()
        return
    try:
        scan = store.load_scan(scan_id)
        if not scan:
            raise ValueError("scan " + scan_id + " not found")

        backend = ai_mod.make_backend(
            options.get("backend", "ollama"),
            options.get("model", ""),
            int(options.get("num_ctx", 8192)),
        )
        ok, note = backend.available()
        job.say(note, "check", 4)
        if not ok:
            raise RuntimeError(note)

        explicit = options.get("paths") or []
        if explicit:
            by_path = {r["path"]: r for r in scan["files"]}
            targets = [by_path[p] for p in explicit if p in by_path]
        else:
            targets = pick_candidates(
                scan,
                top_n=int(options.get("top_n", 10)),
                min_score=float(options.get("min_score", 15)),
                skip_reviewed=bool(options.get("skip_reviewed", True)),
                include_tests=bool(options.get("include_tests", False)),
            )
        if not targets:
            raise RuntimeError("nothing to review with the current filters")

        root = Path(scan["source_root"])
        total = len(targets)
        scan["ai_state"] = {
            "status": "running", "done": 0, "total": total, "backend": backend.name,
            "model": backend.model, "started_at": store.now_iso(),
            "message": "reviewing " + str(total) + " files with " + backend.model,
        }
        store.save_scan(scan)
        job.extra["total"] = total
        job.say("reviewing " + str(total) + " files with " + backend.model, "review", 6)

        findings_total = 0
        spent = 0.0
        for i, rec in enumerate(targets, start=1):
            eta = ""
            if i > 1:
                per = spent / (i - 1)
                left = per * (total - i + 1)
                eta = "  (~" + str(int(per)) + "s/file, ~" + str(int(left / 60)) + "m left)"
            job.say("[" + str(i) + "/" + str(total) + "] " + rec["path"] + eta, "review",
                    6 + int(90 * ((i - 1) / total)))
            t_file = time.time()
            text, _ = read_text(root / rec["path"])
            if not text:
                rec["ai"] = {"error": "file unreadable on disk", "probability": 0,
                             "findings": [], "safe_notes": [], "confidence": "low",
                             "backend": backend.name, "model": backend.model}
            else:
                verdict = backend.review(rec, text)
                verdict["reviewed_at"] = store.now_iso()
                rec["ai"] = verdict
                findings_total += len(verdict.get("findings") or [])
                if verdict.get("error"):
                    job.say("  model error: " + str(verdict["error"])[:120], "review")
                else:
                    job.say("  probability " + str(verdict.get("probability")) + ", "
                            + str(len(verdict.get("findings") or [])) + " findings, "
                            + str(verdict.get("elapsed")) + "s", "review")

            spent += time.time() - t_file
            per_file = spent / i
            remaining = per_file * (total - i)
            scan["ai_state"].update({
                "done": i, "total": total, "current": rec["path"],
                "findings": findings_total,
                "seconds_per_file": round(per_file, 1),
                "eta_seconds": int(remaining),
                "message": "reviewed " + str(i) + "/" + str(total) + ", " + str(findings_total)
                           + " findings, " + str(int(per_file)) + "s/file"
                           + (", ~" + str(max(1, int(remaining / 60))) + "m left" if i < total else ""),
            })
            store.save_scan(scan)       # stream results to the UI as they land

        scan["ai_state"].update({
            "status": "done", "finished_at": store.now_iso(),
            "message": "reviewed " + str(total) + " files, " + str(findings_total) + " findings",
        })
        store.save_scan(scan)
        job.extra["findings"] = findings_total
        job.say("AI pass complete: " + str(findings_total) + " findings across "
                + str(total) + " files", "done", 100)
        job.status = "done"
    except Exception as exc:  # noqa: BLE001
        job.status = "error"
        job.error = type(exc).__name__ + ": " + str(exc)
        job.say("failed: " + job.error, "error", 100)
        scan = store.load_scan(scan_id)
        if scan:
            state = scan.get("ai_state") or {}
            state.update({"status": "error", "message": job.error})
            scan["ai_state"] = state
            store.save_scan(scan)
    finally:
        lock.release()
        job.finished = time.time()
