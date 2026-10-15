"""Audit what the context pass took off the board, so over-suppression is visible.

A pass that silently drops real findings is worse than the noise it removed, so every
dismissal is inspectable:

    python tools/audit_dismissed.py juice-shop__juice-shop__default
    python tools/audit_dismissed.py juice-shop__juice-shop__default --rule js.regex_dyn
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from repoxray.inventory import build_inventory                        # noqa: E402
from repoxray.score import score_repo                                 # noqa: E402

ROOT = Path(__file__).resolve().parent.parent / "data" / "repos"


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    want_rule = ""
    for arg in sys.argv[1:]:
        if arg.startswith("--rule="):
            want_rule = arg.split("=", 1)[1]
    if "--rule" in sys.argv:
        want_rule = sys.argv[sys.argv.index("--rule") + 1]
    if not args:
        print("usage: audit_dismissed.py <repo-dir-name> [--rule <id>]")
        return 2
    repo = ROOT / args[0]
    inv = build_inventory(repo, log=lambda m: None)
    score_repo(repo, inv, log=lambda m: None)

    by_rule: dict = {}
    for rec in inv["files"]:
        for item in rec.get("dismissed") or []:
            by_rule.setdefault(item["rule"], []).append((rec["path"], item))

    print("dismissed matches by rule")
    for rule, items in sorted(by_rule.items(), key=lambda kv: -len(kv[1])):
        kinds = sorted({i[1]["kind"] for i in items})
        print("  " + str(len(items)).rjust(4) + "  " + rule.ljust(22)
              + " (" + ", ".join(kinds) + ")")

    print("\nkept findings by rule, for comparison")
    kept: dict = {}
    for rec in inv["files"]:
        for hit in rec.get("hits") or []:
            if hit.get("tier") == "sink":
                kept.setdefault(hit["rule"], 0)
                kept[hit["rule"]] += 1
    for rule, count in sorted(kept.items(), key=lambda kv: -kv[1])[:18]:
        print("  " + str(count).rjust(4) + "  " + rule)

    if want_rule:
        print("\n--- every dismissal of " + want_rule + " ---")
        for path, item in by_rule.get(want_rule, []):
            print("\n" + path + ":" + str(item["line"]) + "  [" + item["kind"] + "]")
            print("  " + item["snippet"][:150])
            print("  -> " + item["why"][:300])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
