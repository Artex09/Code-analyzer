"""Cross-file taint cases: the flow is only visible when two files are read together.

Each case is a small repository. `expect` names (path, rule) pairs that must appear;
`forbid` names rules that must not. The point of every case is that neither file alone
contains a finding - the pattern pass and the single-file dataflow pass are both silent.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from repoxray.analysis import run as ar                      # noqa: E402
from repoxray.analysis.cross import CrossIndex               # noqa: E402
from repoxray.analysis.resolve import RepoIndex              # noqa: E402

LANG_OF = {".js": "javascript", ".ts": "typescript", ".py": "python", ".php": "php",
           ".go": "go", ".rb": "ruby", ".java": "java", ".cs": "csharp"}

CASES = [
    {
        "name": "js: route hands request data to a helper module",
        "files": {
            "routes/admin.js": """
const { runJob } = require("../lib/jobs");
app.post("/run", (req, res) => {
  runJob(req.body.name);
  res.end("ok");
});
""",
            "lib/jobs.js": """
const { exec } = require("child_process");
exports.runJob = function (name) {
  exec("./scripts/run " + name);
};
""",
        },
        "expect": [("lib/jobs.js", "xtaint.js.exec"), ("routes/admin.js", "xentry.js.exec")],
        "forbid": [],
    },
    {
        "name": "js: two hops through a second module",
        "files": {
            "routes/a.js": """
const svc = require("../svc/one");
app.get("/x", (req, res) => svc.handle(req.query.q));
""",
            "svc/one.js": """
const two = require("./two");
exports.handle = function (value) {
  return two.store(value);
};
""",
            "svc/two.js": """
const fs = require("fs");
exports.store = function (p) {
  return fs.readFileSync(p);
};
""",
        },
        "expect": [("svc/two.js", "xtaint.js.fs")],
        "forbid": [],
    },
    {
        "name": "js: helper validates its argument, so no finding crosses",
        "files": {
            "routes/b.js": """
const { runSafe } = require("../lib/safe");
app.post("/r", (req, res) => runSafe(req.body.name));
""",
            "lib/safe.js": """
const { exec } = require("child_process");
exports.runSafe = function (name) {
  if (!/^[a-z]+$/.test(name)) { return null; }
  return exec("./run " + name);
};
""",
        },
        "expect": [],
        "forbid": ["xtaint.js.exec", "xentry.js.exec"],
    },
    {
        "name": "js: unrelated module with the same function name is not linked",
        "files": {
            "routes/c.js": """
const { render } = require("../lib/template");
app.get("/c", (req, res) => render(req.query.body));
""",
            "lib/template.js": """
exports.render = function (body) {
  return String(body).toUpperCase();
};
""",
            "other/danger.js": """
const { exec } = require("child_process");
exports.shellOut = function (body) { exec(body); };
""",
        },
        "expect": [],
        "forbid": ["xtaint.js.exec"],
    },
    {
        "name": "python: flask view calls a helper in another module",
        "files": {
            "app/views.py": """
from flask import request
from app.helpers import run_report

def report():
    return run_report(request.args.get("name"))
""",
            "app/helpers.py": """
import subprocess

def run_report(name):
    return subprocess.run("report " + name, shell=True)
""",
        },
        "expect": [("app/helpers.py", "xtaint.py.subprocess")],
        "forbid": [],
    },
    {
        "name": "python: relative import resolves",
        "files": {
            "pkg/web.py": """
from flask import request
from .store import save

def upload():
    save(request.args.get("path"))
""",
            "pkg/store.py": """
def save(path):
    with open(path, "wb") as fh:
        fh.write(b"x")
""",
        },
        "expect": [("pkg/store.py", "xtaint.py.open")],
        "forbid": [],
    },
    {
        "name": "php: include brings in the dangerous function",
        "files": {
            "index.php": """
<?php
require_once 'lib/runner.php';
run_task($_GET['task']);
""",
            "lib/runner.php": """
<?php
function run_task($task) {
    system('/usr/local/bin/task ' . $task);
}
""",
        },
        "expect": [("lib/runner.php", "xtaint.php.exec")],
        "forbid": [],
    },
    {
        "name": "go: same directory is one package, no import needed",
        "files": {
            "api/handler.go": """
package api

import "net/http"

func Handle(w http.ResponseWriter, r *http.Request) {
    RunIt(r.URL.Query().Get("n"))
}
""",
            "api/runner.go": """
package api

import "os/exec"

func RunIt(name string) {
    exec.Command("sh", "-c", "run "+name)
}
""",
        },
        "expect": [("api/runner.go", "xtaint.go.exec")],
        "forbid": [],
    },
    {
        "name": "js: sanitizer at the call site stops the cross-file flow",
        "files": {
            "routes/d.js": """
const path = require("path");
const { readIt } = require("../lib/reader");
app.get("/d", (req, res) => readIt(path.basename(req.query.f)));
""",
            "lib/reader.js": """
const fs = require("fs");
exports.readIt = function (p) { return fs.readFileSync("/data/" + p); };
""",
        },
        "expect": [],
        "forbid": ["xtaint.js.fs"],
    },
]


def analyse_case(case: dict) -> dict:
    files = case["files"]
    index = RepoIndex(list(files))
    cross = CrossIndex(index)
    for path, code in files.items():
        lang = LANG_OF.get(Path(path).suffix, "")
        res = ar.analyse_file(code, lang, path=path)
        if not res["ok"]:
            print("      note: %s did not analyse (%s)" % (path, res["reason"]))
        cross.add(path, lang, res, res["imports"], res["exports"])
    cross.build_links()
    cross.close()
    return cross.findings(), cross


def main() -> int:
    passed = failed = 0
    for case in CASES:
        found, cross = analyse_case(case)
        pairs = {(path, f.rule) for path, items in found.items() for f in items}
        rules = {rule for _p, rule in pairs}
        problems = []
        for want in case["expect"]:
            if tuple(want) not in pairs:
                problems.append("missing " + want[1] + " in " + want[0])
        for bad in case["forbid"]:
            if bad in rules:
                problems.append("unwanted " + bad)
        if problems:
            failed += 1
            print("  FAIL  " + case["name"])
            for problem in problems:
                print("          " + problem)
            if pairs:
                print("          got: " + ", ".join(sorted(p[0] + ":" + p[1] for p in pairs)))
            else:
                print("          got nothing; links " + str(cross.stats))
        else:
            passed += 1
            print("  pass  " + case["name"])
    print()
    print("%d/%d cross-file cases pass" % (passed, passed + failed))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
