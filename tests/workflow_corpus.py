"""Regression cases for GitHub Actions semantics and uncertainty reporting.

Run with `python tests/workflow_corpus.py`. These cases exercise the structural workflow
pass directly so a generic YAML regex cannot hide a semantic regression.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from repoxray.analysis import actions  # noqa: E402
from repoxray.score import _workflow_findings  # noqa: E402
from repoxray import rules  # noqa: E402


def run() -> int:
    if not actions.available():
        print("workflow corpus skipped: PyYAML is not installed")
        return 0

    # A trigger is an exposure condition, and an integer PR number is not shell text.
    number = actions.analyse_workflow('''name: review
on: pull_request_target
permissions: write-all
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - run: gh pr review ${{ github.event.pull_request.number }} --approve
''', ".github/workflows/review.yml")
    assert number["ok"]
    assert not number["findings"], number["findings"]
    assert "pull_request_target" in number["triggers"]

    # An unknown event field reaching `run:` stays a lead after score/report conversion.
    unknown = '''name: custom event
on: pull_request
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.custom_payload }}"
'''
    result = actions.analyse_workflow(unknown, ".github/workflows/custom.yml")
    assert result["ok"]
    assert result["findings"]
    assert result["findings"][0]["verdict"] == "lead", result["findings"]
    findings = _workflow_findings(
        {"path": ".github/workflows/custom.yml"}, unknown, [], {}, {})
    hit = next(f.to_hit() for f in findings if f.rule == "gha.run_injection")
    assert hit["verdict"] == "lead", hit

    # Suppression annotations are visible security signals, never scored findings/CWEs.
    assert rules.tier_of("gen.suppressed", 5, "suppress") == "signal"
    assert rules.CATEGORIES["suppress"]["cwe"] == ""

    # nebius/gosdk pr_create.yml: a branch name spliced into a `gh pr create` command.
    # Two things have to be right about the evidence, not just the verdict.
    block = '''name: Create PR from Sync branch
on:
  push:
    branches: ["sync/**"]
jobs:
  create-pr:
    runs-on: ubuntu-latest
    steps:
      - name: Create Pull Request using gh CLI
        run: |
          PR_URL=$(gh pr create --title "Sync: ${{ github.ref_name }}" --body "from ${{ github.ref_name }}" --head "${{ github.ref_name }}")
          echo "done"
'''
    result = actions.analyse_workflow(block, ".github/workflows/pr_create.yml")
    assert result["ok"], result["reason"]
    runs = [f for f in result["findings"] if f["rule"] == "gha.run_injection"]
    # A block scalar's node starts on the `run: |` line; its content starts on the next.
    # Reporting the `run: |` line points at the one line of the script with no expression.
    assert len(runs) == 1, "same rule, line and ref is one problem: " + str(runs)
    # line 10 is `run: |`, line 11 is the PR_URL command that carries the expression
    assert runs[0]["line"] == 11, ("the finding must point at the interpolation, not at "
                                   "`run: |` (got line " + str(runs[0]["line"]) + ")")
    assert "gh pr create" in runs[0].get("ref", "") + block.splitlines()[10]

    print("workflow corpus: 4 cases passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
