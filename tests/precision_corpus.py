"""Precision and recall, measured rather than asserted.

"Found 100 possible vulnerabilities" is not a result. This corpus states, for each case,
what the tool is supposed to conclude - including the category and the verdict, not just
whether something fired - and reports the two numbers that matter:

    precision = of what was reported as a finding, how much was real
    recall    = of what was real, how much was reported

Every case here came from a false positive on a real repository, or from the true positive
that the same rule has to keep catching. The true-negative cases are the point: a rule that
gets broader gets noisier, and a tool with high recall and low precision wastes the only
thing a reviewer cannot buy more of.

`expect` is a list of (rule substring, category, verdict). A case with an empty `expect`
must produce no sink-tier finding at all.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from repoxray.analysis import actions                        # noqa: E402
from repoxray.analysis import run as ar                      # noqa: E402

# --------------------------------------------------------------------- code cases

CASES = [
    # ---- source modelling: a type is a fact, a name is a convention -----------
    {
        "name": "go: context.Context is not a request",
        "lang": "go", "expect": [],
        "code": """
package main

import ("context"; "net/http"; "time")

const endpoint = "http://metadata.internal/v1/token"

func probe(ctx context.Context, logger *slog.Logger) {
    rctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
    defer cancel()
    req, _ := http.NewRequestWithContext(rctx, http.MethodGet, endpoint, nil)
    http.DefaultClient.Do(req)
}
""",
    },
    {
        "name": "go: http.Request by type is a request",
        "lang": "go", "expect": [("go.ssrf_new_ctx", "ssrf", "finding")],
        "code": """
package main

import ("context"; "net/http")

func fetch(ctx context.Context, r *http.Request) {
    target := r.URL.Query().Get("url")
    req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
    http.DefaultClient.Do(req)
}
""",
    },
    {
        "name": "go: a logger parameter is never a source",
        "lang": "go", "expect": [],
        "code": """
package main

import ("log/slog"; "os/exec")

func run(logger *slog.Logger, req string) {
    exec.Command("sh", "-c", "echo hi")
}
""",
    },
    {
        "name": "python: self and cls are not sources",
        "lang": "python", "expect": [],
        "code": """
import subprocess


class Runner:
    def run(self, cls):
        subprocess.run("echo hello", shell=True)
""",
    },
    # ---- argument roles: which argument is the dangerous one ------------------
    {
        "name": "go: taint in the context, not the URL",
        "lang": "go", "expect": [],
        "code": """
package main

import ("net/http")

const endpoint = "https://api.internal/v1"

func fetch(r *http.Request) {
    ctx := r.Context()
    req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
    http.DefaultClient.Do(req)
}
""",
    },
    {
        "name": "python: requests.request method is argument 0, url is argument 1",
        "lang": "python", "expect": [("py.requests_req", "ssrf", "finding")],
        "code": """
import requests
from flask import request


def proxy():
    return requests.request("GET", request.args.get("u"))
""",
    },
    # ---- shell semantics: argv is not a command line -------------------------
    {
        "name": "go: shell -c makes the argument a command line",
        "lang": "go", "expect": [("go.exec", "cmd", "finding")],
        "code": """
package main

import ("net/http"; "os/exec")

func h(w http.ResponseWriter, r *http.Request) {
    exec.Command("sh", "-c", "run "+r.FormValue("name"))
}
""",
    },
    {
        "name": "go: fixed non-shell program is argument injection",
        "lang": "go", "expect": [("go.exec", "argv", "finding")],
        "code": """
package main

import ("net/http"; "os/exec")

func h(w http.ResponseWriter, r *http.Request) {
    exec.Command("open", r.FormValue("url"))
}
""",
    },
    {
        "name": "go: constant argument to a fixed program is nothing",
        "lang": "go", "expect": [],
        "code": """
package main

import ("net/http"; "os/exec")

const target = "https://example.com/"

func h(w http.ResponseWriter, r *http.Request) {
    exec.Command("open", target)
}
""",
    },
    {
        "name": "python: shell=True is a command line",
        "lang": "python", "expect": [("py.subprocess", "cmd", "finding")],
        "code": """
import subprocess
from flask import request


def run():
    subprocess.run("ping " + request.args.get("host"), shell=True)
""",
    },
    {
        "name": "python: a list argv without shell is argument injection",
        "lang": "python", "expect": [("py.subprocess", "argv", "finding")],
        "code": """
import subprocess
from flask import request


def run():
    subprocess.run(["ping", "-c1", request.args.get("host")])
""",
    },
    # ---- constants and assignments -------------------------------------------
    {
        "name": "go: a variable assigned from a constant is constant",
        "lang": "go", "expect": [],
        "code": """
package main

import ("context"; "net/http")

const defaultMetadataTokenEndpoint = "http://metadata.internal/v1/iam/token"

func probe(ctx context.Context) {
    tokenEndpoint := defaultMetadataTokenEndpoint
    req, _ := http.NewRequestWithContext(ctx, "GET", tokenEndpoint, nil)
    http.DefaultClient.Do(req)
}
""",
    },
    # ---- context flow is not data flow ---------------------------------------
    {
        "name": "go: context.WithTimeout does not carry taint",
        "lang": "go", "expect": [],
        "code": """
package main

import ("context"; "net/http"; "time")

const endpoint = "https://api.internal/x"

func fetch(r *http.Request) {
    rctx, cancel := context.WithTimeout(r.Context(), time.Second)
    defer cancel()
    req, _ := http.NewRequestWithContext(rctx, "GET", endpoint, nil)
    http.DefaultClient.Do(req)
}
""",
    },
    # ---- guards --------------------------------------------------------------
    {
        "name": "go: prefix guard leaves the rest of the value free",
        "lang": "go", "expect": [("go.exec", "cmd", "finding")],
        "code": """
package main

import ("net/http"; "os/exec"; "strings")

func h(w http.ResponseWriter, r *http.Request) {
    ref := r.FormValue("ref")
    if !strings.HasPrefix(ref, "sync-terraform-provider/") {
        return
    }
    exec.Command("sh", "-c", "git checkout "+ref)
}
""",
    },
    {
        "name": "go: an allow-list guard closes it",
        "lang": "go", "expect": [],
        "code": """
package main

import ("net/http"; "os/exec")

func h(w http.ResponseWriter, r *http.Request) {
    mode := r.FormValue("mode")
    if mode != "status" && mode != "uptime" {
        return
    }
    exec.Command("sh", "-c", "report "+mode)
}
""",
    },
    # ---- partial sanitizers --------------------------------------------------
    {
        "name": "go: ReplaceAll of one character is not sanitisation",
        "lang": "go", "expect": [("go.exec", "cmd", "finding")],
        "code": """
package main

import ("net/http"; "os/exec"; "strings")

func h(w http.ResponseWriter, r *http.Request) {
    u := strings.ReplaceAll(r.FormValue("u"), "&", "^&")
    exec.Command("cmd.exe", "/c", "curl "+u)
}
""",
    },
    # ---- the edge case from the report, lifted from nebius/gosdk browser.go --
    {
        "name": "go: cmd.exe /c start with a partly escaped url",
        "lang": "go", "expect": [("go.exec", "cmd", "finding")],
        "code": """
package main

import ("net/http"; "os/exec"; "strings")

func h(w http.ResponseWriter, r *http.Request) {
    url := r.FormValue("u")
    exec.Command("cmd.exe", "/c", "start", strings.ReplaceAll(url, "&", "^&"))
}
""",
    },
    {
        "name": "go: program from a literal list, none of them a shell",
        "lang": "go", "expect": [("go.exec_ctx", "argv", "finding")],
        "code": """
package main

import ("context"; "net/http"; "os/exec")

func h(ctx context.Context, r *http.Request) {
    url := r.FormValue("u")
    providers := []string{"xdg-open", "x-www-browser", "www-browser"}
    for _, provider := range providers {
        exec.CommandContext(ctx, provider, url)
    }
}
""",
    },
    # ---- guards are not interchangeable --------------------------------------
    {
        "name": "go: a validator the analyser cannot read makes it a lead",
        "lang": "go", "expect": [("go.exec", "cmd", "lead")],
        "code": """
package main

import ("net/http"; "os/exec")

func isAllowedHost(h string) bool { return h == "a.example.com" }

func h(w http.ResponseWriter, r *http.Request) {
    host := r.FormValue("host")
    if !isAllowedHost(host) {
        return
    }
    exec.Command("sh", "-c", "curl "+host)
}
""",
    },
    {
        "name": "go: an authorization check gates who, not what",
        "lang": "go", "expect": [("go.exec", "cmd", "finding")],
        "code": """
package main

import ("net/http"; "os/exec")

func h(w http.ResponseWriter, r *http.Request) {
    repo := r.FormValue("repo")
    if r.Header.Get("X-Owner") != "me" {
        return
    }
    exec.Command("sh", "-c", "clone "+repo)
}
""",
    },
    # ---- secrets are their own class -----------------------------------------
    {
        "name": "go: a credential written to a log is disclosure",
        "lang": "go", "expect": [("go.log", "disclosure", "finding")],
        "code": """
package main

import ("log"; "os")

func main() {
    token := os.Getenv("GITHUB_TOKEN")
    log.Printf("using token %s", token)
}
""",
    },
    {
        "name": "go: a credential in a shell is not command injection",
        "lang": "go", "expect": [],
        "code": """
package main

import ("os"; "os/exec")

func main() {
    token := os.Getenv("GITHUB_TOKEN")
    exec.Command("sh", "-c", "curl -H "+token)
}
""",
    },
    {
        "name": "go: an ordinary environment variable in a log is nothing",
        "lang": "go", "expect": [],
        "code": """
package main

import ("log"; "os")

func main() {
    log.Printf("region %s", os.Getenv("AWS_REGION"))
}
""",
    },
    {
        # `req.cookies.token` contains the word "token" and is the attacker's input, not a
        # credential the application holds. Classifying it as a secret suppressed the RCE
        # at the end of the flow - the same name-only mistake, introduced by the fix for it.
        "name": "js: a token arriving in a request is input, not a credential",
        "lang": "javascript", "expect": [("js.eval", "code", "finding")],
        "code": """
const express = require("express");
app.get("/p", (req, res) => {
  const token = req.cookies.token;
  eval(token);
});
""",
    },

    # ---- the propagation honesty rule ----------------------------------------
    {
        "name": "js: a flow through an unseen call is a lead, not a finding",
        "lang": "javascript", "expect": [("js.exec", "cmd", "lead")],
        "code": """
const { exec } = require("child_process");
app.post("/run", (req, res) => {
  const name = lookupSomething(req.body.name);
  exec("./run " + name);
});
""",
    },
    {
        "name": "js: a direct flow in a registered handler is a finding",
        "lang": "javascript", "expect": [("js.exec", "cmd", "finding")],
        "code": """
const { exec } = require("child_process");
app.post("/run", (req, res) => {
  exec("./run " + req.body.name);
});
""",
    },
    {
        # `req.body.x` is a framework-shaped accessor, so it stands on its own wherever it
        # appears. A *bare* parameter called `req` is the guess, and the difference between
        # the two is what `trust` records.
        "name": "js: a request accessor is specific enough anywhere",
        "lang": "javascript", "expect": [("js.exec", "cmd", "finding")],
        "code": """
const { exec } = require("child_process");
function buildReport(req) {
  exec("./run " + req.body.name);
}
""",
    },
    {
        # `(req, res)` is an express convention, and a convention means nothing in a file
        # that has never heard of express. In morluto/rea a local variable named `request`
        # - the parsed JSON of a debugger request file - made `exec(compile(...))` read as
        # "flask request reaches eval" in a repository with no web framework in it.
        "name": "js: a parameter named req with no framework in the file is not a source",
        "lang": "javascript", "expect": [],
        "code": """
const { exec } = require("child_process");
function buildReport(req) {
  exec("./run " + req);
}
""",
    },
    {
        # ... and where the framework *is* present the guess is still worth a lead, which
        # is the half of this the gate must not take away.
        "name": "js: a bare parameter named req in an express file is a lead",
        "lang": "javascript", "expect": [("js.exec", "cmd", "lead")],
        "code": """
const { exec } = require("child_process");
const express = require("express");
function buildReport(req) {
  exec("./run " + req);
}
""",
    },
    {
        "name": "js: res and next are not sources",
        "lang": "javascript", "expect": [],
        "code": """
const { exec } = require("child_process");
app.use((err, req2, res, next) => {
  exec("./cleanup");
  next(err);
});
""",
    },
]

# ----------------------------------------------------------------- workflow cases

WORKFLOW_CASES = [
    {
        "name": "actions: a trigger is not data and an id is not a payload",
        "expect": [],
        "yaml": """
name: autoapprove
on:
  pull_request_target:
    types: [opened, synchronize]
concurrency:
  group: autoapprove-${{ github.event.pull_request.number }}
permissions:
  contents: read
  pull-requests: write
jobs:
  approve:
    if: ${{ github.event.pull_request.head.repo.full_name == github.repository }}
    runs-on: ubuntu-latest
    steps:
      - name: Approve
        env:
          PR_NUMBER: ${{ github.event.pull_request.number }}
        run: gh pr review "$PR_NUMBER" --approve
""",
    },
    {
        "name": "actions: issue title straight into a shell is injection",
        "expect": [("gha.run_injection", "cmd", "finding")],
        "yaml": """
on: issues
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Title is ${{ github.event.issue.title }}"
""",
    },
    {
        "name": "actions: the same value through env, quoted, is the documented fix",
        "expect": [],
        "yaml": """
on: issues
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - env:
          TITLE: ${{ github.event.issue.title }}
        run: echo "Title is $TITLE"
""",
    },
    {
        "name": "actions: env value in command position is injection again",
        "expect": [("gha.env_reinterpreted", "cmd", "finding")],
        "yaml": """
on: issue_comment
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - env:
          CMD: ${{ github.event.comment.body }}
        run: eval "$CMD"
""",
    },
    {
        "name": "actions: a matrix value is written by the workflow author",
        "expect": [],
        "yaml": """
on: push
jobs:
  build:
    strategy:
      matrix:
        features: [a, b]
    runs-on: ubuntu-latest
    steps:
      - run: cargo build --features ${{ matrix.features }}
""",
    },
    {
        "name": "actions: github-script with an untrusted body",
        "expect": [("gha.script_injection", "code", "finding")],
        "yaml": """
on: issue_comment
jobs:
  reply:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            console.log("${{ github.event.comment.body }}")
""",
    },
]


def run_code_cases() -> tuple:
    tp = fp = fn = 0
    lines = []
    for case in CASES:
        res = ar.analyse_file(case["code"], case["lang"], path="t." + case["lang"])
        got = [(f.rule, f.cat, f.verdict()) for f in res["findings"] if f.tier == "sink"]
        want = case["expect"]
        matched = []
        missing = []
        for rule, cat, verdict in want:
            hit = next((g for g in got
                        if rule in g[0] and g[1] == cat and g[2] == verdict), None)
            if hit:
                matched.append(hit)
                tp += 1
            else:
                missing.append((rule, cat, verdict))
                fn += 1
        extra = [g for g in got if g not in matched]
        fp += len(extra)
        ok = not missing and not extra
        lines.append(("  pass  " if ok else "  FAIL  ") + case["name"])
        if not ok:
            if missing:
                lines.append("          missing: " + str(missing))
            if extra:
                lines.append("          unwanted: " + str(extra))
            if not res["ok"]:
                lines.append("          analysis failed: " + res["reason"])
    return tp, fp, fn, lines


def run_workflow_cases() -> tuple:
    tp = fp = fn = 0
    lines = []
    if not actions.available():
        lines.append("  skipped: PyYAML is not installed, workflow model unavailable")
        return tp, fp, fn, lines
    for case in WORKFLOW_CASES:
        res = actions.analyse_workflow(case["yaml"], ".github/workflows/t.yml")
        got = [(f["rule"], f["cat"], f["verdict"]) for f in res["findings"]]
        want = case["expect"]
        matched = []
        missing = []
        for rule, cat, verdict in want:
            hit = next((g for g in got
                        if rule in g[0] and g[1] == cat and g[2] == verdict), None)
            if hit:
                matched.append(hit)
                tp += 1
            else:
                missing.append((rule, cat, verdict))
                fn += 1
        extra = [g for g in got if g not in matched]
        fp += len(extra)
        ok = not missing and not extra
        lines.append(("  pass  " if ok else "  FAIL  ") + case["name"])
        if not ok:
            if missing:
                lines.append("          missing: " + str(missing))
            if extra:
                lines.append("          unwanted: " + str(extra))
            if not res["ok"]:
                lines.append("          parse failed: " + res["reason"])
    return tp, fp, fn, lines


def main() -> int:
    ctp, cfp, cfn, clines = run_code_cases()
    wtp, wfp, wfn, wlines = run_workflow_cases()
    print("  code:")
    print("\n".join(clines))
    print("  workflows:")
    print("\n".join(wlines))

    tp, fp, fn = ctp + wtp, cfp + wfp, cfn + wfn
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    failures = sum(1 for line in clines + wlines if line.startswith("  FAIL"))
    print()
    print("  true positives %d | false positives %d | missed %d" % (tp, fp, fn))
    print("  precision %.0f%%  recall %.0f%%" % (precision * 100, recall * 100))
    print()
    print("%d/%d precision cases pass" % (len(CASES) + len(WORKFLOW_CASES) - failures,
                                          len(CASES) + len(WORKFLOW_CASES)))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
