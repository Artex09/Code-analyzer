"""Scan persistence: one JSON document per scan, plus a lightweight in-memory cache."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("REPOXRAY_DATA", APP_ROOT / "data"))
REPOS_DIR = DATA_DIR / "repos"
SCANS_DIR = DATA_DIR / "scans"

_CACHE: "OrderedDict[str, dict]" = OrderedDict()
_CACHE_MAX = 4


def ensure_dirs() -> None:
    REPOS_DIR.mkdir(parents=True, exist_ok=True)
    SCANS_DIR.mkdir(parents=True, exist_ok=True)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_scan_id(slug: str) -> str:
    digest = hashlib.sha1((slug + str(time.time())).encode()).hexdigest()[:8]
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return stamp + "-" + digest


def scan_path(scan_id: str) -> Path:
    safe = "".join(c for c in scan_id if c.isalnum() or c in "-_")
    return SCANS_DIR / (safe + ".json")


def save_scan(scan: dict) -> Path:
    ensure_dirs()
    path = scan_path(scan["id"])
    tmp = path.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(scan, fh, separators=(",", ":"))
    tmp.replace(path)
    _CACHE[scan["id"]] = scan
    _CACHE.move_to_end(scan["id"])
    while len(_CACHE) > _CACHE_MAX:
        _CACHE.popitem(last=False)
    _write_index_entry(scan)
    return path


def load_scan(scan_id: str) -> dict | None:
    if scan_id in _CACHE:
        _CACHE.move_to_end(scan_id)
        return _CACHE[scan_id]
    path = scan_path(scan_id)
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as fh:
            scan = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None
    _CACHE[scan_id] = scan
    _CACHE.move_to_end(scan_id)
    while len(_CACHE) > _CACHE_MAX:
        _CACHE.popitem(last=False)
    return scan


def drop_from_cache(scan_id: str) -> None:
    _CACHE.pop(scan_id, None)


INDEX_PATH = lambda: SCANS_DIR / "_index.json"  # noqa: E731


def _read_index() -> list:
    p = INDEX_PATH()
    if not p.exists():
        return []
    try:
        with p.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []


def _write_index_entry(scan: dict) -> None:
    entry = {
        "id": scan["id"],
        "created_at": scan.get("created_at"),
        "slug": scan["repo"].get("slug"),
        "ref": scan["repo"].get("ref") or (scan.get("fetch") or {}).get("branch") or "",
        "url": scan["repo"].get("html_url", ""),
        "files": (scan.get("totals") or {}).get("files", 0),
        "lines": (scan.get("totals") or {}).get("lines", 0),
        "flagged": (scan.get("summary") or {}).get("flagged_files", 0),
        "critical": ((scan.get("summary") or {}).get("bands") or {}).get("critical", 0),
        "high": ((scan.get("summary") or {}).get("bands") or {}).get("high", 0),
        "max_score": (scan.get("summary") or {}).get("max_score", 0),
        "ai_reviewed": sum(1 for f in scan.get("files", []) if f.get("ai")),
    }
    index = [e for e in _read_index() if e.get("id") != entry["id"]]
    index.insert(0, entry)
    ensure_dirs()
    tmp = INDEX_PATH().with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(index[:200], fh, indent=1)
    tmp.replace(INDEX_PATH())


def list_scans(limit: int = 40) -> list:
    index = _read_index()
    alive = [e for e in index if scan_path(e["id"]).exists()]
    if len(alive) != len(index):
        ensure_dirs()
        with INDEX_PATH().open("w", encoding="utf-8") as fh:
            json.dump(alive, fh, indent=1)
    return alive[:limit]


def delete_scan(scan_id: str, drop_source: bool = False) -> bool:
    scan = load_scan(scan_id)
    path = scan_path(scan_id)
    existed = path.exists()
    if existed:
        path.unlink()
    drop_from_cache(scan_id)
    index = [e for e in _read_index() if e.get("id") != scan_id]
    ensure_dirs()
    with INDEX_PATH().open("w", encoding="utf-8") as fh:
        json.dump(index, fh, indent=1)
    if drop_source and scan:
        src = scan.get("source_root")
        if src:
            top = Path(src)
            # only ever delete inside our own repos directory
            try:
                top.relative_to(REPOS_DIR)
                shutil.rmtree(top, ignore_errors=True)
            except ValueError:
                pass
    return existed


def disk_usage() -> dict:
    def size_of(p: Path) -> int:
        if not p.exists():
            return 0
        return sum(f.stat().st_size for f in p.rglob("*") if f.is_file())
    return {"repos_bytes": size_of(REPOS_DIR), "scans_bytes": size_of(SCANS_DIR),
            "repos_dir": str(REPOS_DIR), "scans_dir": str(SCANS_DIR)}
