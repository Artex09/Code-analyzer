"""Path-sensitivity cases: what the solver must suppress, and what it must not.

Each case states the expected verdict for one sink:

  drop     the finding must be gone, because the guards contradict each other or because
           no value that survives them can be a payload
  keep     the finding must survive; `witness` asserts the solver produced a concrete value

The `keep` cases matter more than the `drop` ones. A validation that looks strict but is not
- `^[\\w.-]+$` still allows `..` - is exactly where a human reviewer stops reading, and
silently dropping those would make the tool worse than useless.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from repoxray.analysis import pathcond                       # noqa: E402
from repoxray.analysis import run as ar                      # noqa: E402

CASES = [
    # ---------------------------------------------------------------- drop
    {
        "name": "js: regex allows only lowercase letters",
        "lang": "javascript", "verdict": "drop", "rule": "taint.js.exec",
        "code": """
const { exec } = require("child_process");
app.get("/ping", (req, res) => {
  const host = req.query.host;
  if (!/^[a-z0-9.]+$/.test(host)) { return res.status(400).end(); }
  exec("ping -c1 " + host);
});
""",
    },
    {
        "name": "js: literal allow-list array",
        "lang": "javascript", "verdict": "drop", "rule": "taint.js.exec",
        "code": """
const { exec } = require("child_process");
const ALLOWED = ["status", "uptime"];
app.get("/run", (req, res) => {
  const cmd = req.query.cmd;
  if (!ALLOWED.includes(cmd)) { return res.status(400).end(); }
  exec("/usr/bin/" + cmd);
});
""",
    },
    {
        "name": "js: contradictory numeric guards make the sink unreachable",
        "lang": "javascript", "verdict": "drop", "rule": "taint.js.fs",
        "code": """
const fs = require("fs");
app.get("/f", (req, res) => {
  const n = req.query.n;
  if (n > 5) {
    if (n < 2) {
      fs.readFile(n, (e, d) => res.end(d));
    }
  }
});
""",
    },
    {
        "name": "js: extension allow-list blocks traversal",
        "lang": "javascript", "verdict": "drop", "rule": "taint.js.fs",
        "code": """
const fs = require("fs");
app.get("/img", (req, res) => {
  const name = req.query.name;
  if (!/^[a-z0-9]+\\.(png|jpg)$/.test(name)) { return res.status(400).end(); }
  fs.readFile("/img/" + name, (e, d) => res.end(d));
});
""",
    },
    {
        "name": "python: isalnum() leaves no shell metacharacter",
        "lang": "python", "verdict": "drop", "rule": "taint.py.subprocess",
        "code": """
import subprocess
from flask import request

def ping():
    host = request.args.get("host")
    if not host.isalnum():
        return "bad", 400
    subprocess.run("ping " + host, shell=True)
""",
    },
    {
        "name": "python: numeric comparison excludes injection",
        "lang": "python", "verdict": "drop", "rule": "taint.py.sql",
        "code": """
from flask import request

def rows(cur):
    page = request.args.get("page")
    if int(page) > 1000:
        return []
    if not str(page).isdigit():
        return []
    cur.execute("select * from t limit " + page)
""",
    },
    {
        "name": "php: in_array against a literal list",
        "lang": "php", "verdict": "drop", "rule": "taint.php.exec",
        "code": """
<?php
$cmd = $_GET['cmd'];
if (!in_array($cmd, ['status', 'uptime'])) { die('no'); }
system('/usr/bin/' . $cmd);
""",
    },
    {
        "name": "php: ctype_alnum guard",
        "lang": "php", "verdict": "drop", "rule": "taint.php.file",
        "code": """
<?php
$f = $_GET['f'];
if (!ctype_alnum($f)) { exit; }
echo file_get_contents('/data/' . $f);
""",
    },
    # ---------------------------------------------------------------- keep
    {
        "name": "js: regex that still allows a semicolon",
        "lang": "javascript", "verdict": "keep", "witness": True,
        "rule": "taint.js.exec",
        "code": """
const { exec } = require("child_process");
app.get("/ping", (req, res) => {
  const host = req.query.host;
  if (!/^[\\w.;-]+$/.test(host)) { return res.status(400).end(); }
  exec("ping -c1 " + host);
});
""",
    },
    {
        "name": "js: no guard at all is reported as unguarded",
        "lang": "javascript", "verdict": "keep", "proof": "unguarded",
        "rule": "taint.js.exec",
        "code": """
const { exec } = require("child_process");
app.get("/ping", (req, res) => exec("ping -c1 " + req.query.host));
""",
    },
    {
        "name": "js: an auth check is not a value check",
        "lang": "javascript", "verdict": "keep", "rule": "taint.js.exec",
        "code": """
const { exec } = require("child_process");
app.get("/run", (req, res) => {
  if (!req.user || !req.user.isAdmin) { return res.status(403).end(); }
  exec("/bin/sh -c " + req.query.cmd);
});
""",
    },
    {
        "name": "python: word characters still allow ..",
        "lang": "python", "verdict": "keep", "witness": True,
        "rule": "taint.py.open",
        "code": """
import re
from flask import request

def show():
    name = request.args.get("name")
    if not re.match(r"^[\\w.-]+$", name):
        return "bad", 400
    return open("/data/" + name).read()
""",
    },
    {
        "name": "go: HasPrefix constrains the start, not the rest",
        "lang": "go", "verdict": "keep", "witness": True, "rule": "taint.go.exec",
        "code": """
package main

import ("net/http"; "strings"; "os/exec")

func h(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    if !strings.HasPrefix(name, "job-") {
        return
    }
    exec.Command("sh", "-c", "run "+name)
}
""",
    },
    {
        "name": "js: a validator the encoder cannot read leaves the finding alone",
        "lang": "javascript", "verdict": "keep", "rule": "taint.js.exec",
        "code": """
const { exec } = require("child_process");
const check = require("./check");
app.get("/run", (req, res) => {
  const cmd = req.query.cmd;
  if (!check.looksFine(cmd)) { return res.status(400).end(); }
  exec("/usr/bin/" + cmd);
});
""",
    },
    {
        "name": "js: redirect allow-list by equality is safe, by prefix is not",
        "lang": "javascript", "verdict": "keep", "rule": "taint.js.redirect",
        "code": """
app.get("/go", (req, res) => {
  const url = req.query.url;
  if (!url.startsWith("https://")) { return res.status(400).end(); }
  res.redirect(url);
});
""",
    },
]


def check_degradation() -> list:
    """Without Z3 every finding must survive, guards and all. Nothing may be suppressed.

    The claim "install it or not, nothing true is lost" is worth testing rather than
    asserting, so the solver is removed and the drop cases are re-run.
    """
    problems = []
    saved = pathcond.z3
    pathcond.z3 = None
    try:
        for case in CASES:
            if case["verdict"] != "drop":
                continue
            res = ar.analyse_file(case["code"], case["lang"], path="t." + case["lang"])
            found = next((f for f in res["findings"] if f.rule == case["rule"]), None)
            if found is None:
                problems.append("without z3, " + case["name"] + " lost " + case["rule"])
            elif found.proof != "no-solver":
                problems.append("without z3, " + case["name"] + " claims proof "
                                + found.proof)
    finally:
        pathcond.z3 = saved
    return problems


def main() -> int:
    if not pathcond.available():
        print("  z3 is not installed; path-sensitivity cases cannot run")
        print("  install it with: pip install z3-solver")
        return 1
    print("  solver: z3 " + pathcond.version())
    passed = failed = 0
    for case in CASES:
        res = ar.analyse_file(case["code"], case["lang"], path="t." + case["lang"])
        rules = {f.rule for f in res["findings"]}
        target = case["rule"]
        found = next((f for f in res["findings"] if f.rule == target), None)
        problems = []
        if case["verdict"] == "drop":
            if found is not None:
                problems.append("still reported " + target
                                + " (proof " + str(found.proof) + ", witness "
                                + repr(found.witness) + ")")
            elif not res["suppressed"]:
                problems.append("gone, but nothing was recorded as suppressed")
        else:
            if found is None:
                problems.append("lost " + target + "; suppressed="
                                + str(res["suppressed"]) + " rules=" + str(sorted(rules)))
            else:
                if case.get("witness") and not found.witness:
                    problems.append("no witness value (proof " + found.proof + ")")
                if case.get("proof") and found.proof != case["proof"]:
                    problems.append("proof is " + found.proof + ", expected "
                                    + case["proof"])
        if not res["ok"]:
            problems.append("analysis failed: " + res["reason"])
        if problems:
            failed += 1
            print("  FAIL  [" + case["lang"] + "] " + case["name"])
            for problem in problems:
                print("          " + problem)
        else:
            passed += 1
            extra = ""
            if found is not None and found.witness:
                extra = "  witness " + repr(found.witness)
            print("  pass  [" + case["lang"] + "] " + case["name"] + extra)
    degraded = check_degradation()
    if degraded:
        failed += 1
        print("  FAIL  [no solver] findings must survive when z3 is absent")
        for problem in degraded:
            print("          " + problem)
    else:
        passed += 1
        print("  pass  [no solver] every suppressed finding comes back when z3 is absent")

    print()
    print("%d/%d path-sensitivity cases pass" % (passed, passed + failed))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
