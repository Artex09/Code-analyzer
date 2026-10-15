"""Re-score an already-fetched repository from disk, with no network and no job queue.

Used to compare a scoring change against a repository that produced a bad result before:

    python tools/rescan.py nebius__gosdk__default conn/parse.go auth/file_cache.go
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from repoxray.inventory import build_inventory                        # noqa: E402
from repoxray.score import score_repo                                 # noqa: E402

ROOT = Path(__file__).resolve().parent.parent / "data" / "repos"


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: rescan.py <repo-dir-name> [path ...]")
        print("available:")
        for child in sorted(ROOT.iterdir()):
            if child.is_dir():
                print("  " + child.name)
        return 2
    repo = ROOT / sys.argv[1]
    want = [p.replace("\\", "/") for p in sys.argv[2:]]
    if not repo.is_dir():
        print("no such repo: " + str(repo))
        return 2

    t0 = time.time()
    inv = build_inventory(repo, log=lambda m: None)
    analysis = score_repo(repo, inv, log=lambda m: print("  . " + m))
    files = inv["files"]
    summary = analysis["summary"]

    print("\n" + "=" * 78)
    print("deployment: " + summary.get("deployment", {}).get("describe", "?"))
    print("bands: " + ", ".join(k + "=" + str(v)
                                for k, v in summary["bands"].items() if v))
    print("findings=" + str(summary["confirmed_findings"])
          + "  leads=" + str(summary["lead_findings"])
          + "  pattern=" + str(summary["pattern_hits"])
          + "  signals=" + str(summary["signal_hits"])
          + "  dismissed=" + str(summary.get("dismissed", 0)))
    if summary.get("dismissed_by"):
        for kind, count in summary["dismissed_by"].items():
            print("    - " + str(count) + " x " + kind)
    print("max score: " + str(summary["max_score"])
          + "   mean(scored): " + str(summary["mean_score"])
          + "   in " + str(round(time.time() - t0, 1)) + "s")

    show = [f for f in files if f["path"].replace("\\", "/") in want] if want else \
        sorted((f for f in files if f.get("score", 0) > 0),
               key=lambda f: -f["score"])[:12]
    for rec in show:
        print("\n" + "-" * 78)
        print(rec["path"] + "   score " + str(rec.get("score"))
              + " (" + str(rec.get("band")) + ")")
        parts = rec.get("score_parts") or {}
        if parts:
            print("  parts: " + ", ".join(k + "=" + str(v) for k, v in parts.items()))
        if rec.get("sources"):
            print("  sources: " + ", ".join(s["id"] + "@" + str(s["line"])
                                            for s in rec["sources"]))
        if rec.get("path_signals"):
            print("  path words: " + ", ".join(p["label"] for p in rec["path_signals"]))
        for hit in rec.get("hits") or []:
            print("  [" + hit.get("tier", "?") + "] " + hit["rule"] + " w"
                  + str(hit["weight"]) + " L" + str(hit["line"]) + "  "
                  + (hit.get("title") or ""))
            print("        " + (hit.get("snippet") or "")[:100])
        for item in rec.get("dismissed") or []:
            print("  (dismissed: " + item["kind"] + ") " + item["rule"]
                  + " L" + str(item["line"]))
            print("        " + item["snippet"][:100])
            print("        -> " + item["why"][:260])
        for note in rec.get("context_notes") or []:
            print("  note: " + note)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
