"""Show every hit, lead and dismissal for named files in an already-fetched repository.

    python tools/inspect_file.py juice-shop__juice-shop__default profileImageUrlUpload
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from repoxray.inventory import build_inventory                        # noqa: E402
from repoxray.score import score_repo                                 # noqa: E402

ROOT = Path(__file__).resolve().parent.parent / "data" / "repos"


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: inspect_file.py <repo-dir-name> <path-substring> ...")
        return 2
    repo = ROOT / sys.argv[1]
    needles = [n.lower() for n in sys.argv[2:]]
    inv = build_inventory(repo, log=lambda m: None)
    score_repo(repo, inv, log=lambda m: None)

    for rec in inv["files"]:
        path = rec["path"].replace("\\", "/")
        if not any(n in path.lower() for n in needles):
            continue
        print("\n" + "=" * 78)
        print(path + "   score " + str(rec.get("score")) + " (" + str(rec.get("band")) + ")")
        if rec.get("sources"):
            print("  sources: " + ", ".join(s["id"] + "@" + str(s["line"])
                                            for s in rec["sources"]))
        for hit in rec.get("hits") or []:
            print("  [" + str(hit.get("tier")) + "/" + str(hit.get("verdict") or "-")
                  + "] " + hit["rule"] + " w" + str(hit["weight"])
                  + " L" + str(hit["line"]) + "  " + str(hit.get("cwe") or ""))
            print("      " + (hit.get("snippet") or "")[:120])
        for item in rec.get("dismissed") or []:
            print("  (dismissed " + item["kind"] + ") " + item["rule"]
                  + " L" + str(item["line"]))
            print("      " + item["snippet"][:120])
            print("      -> " + item["why"][:240])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
