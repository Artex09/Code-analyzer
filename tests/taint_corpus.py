"""Labelled dataflow corpus: does taint reach the sink, and does it stop when it should?

Each case states the sinks that must be reported and the lines that must stay silent. The
negative cases are the point: a constant argument, a sanitised value, or a sink nothing
untrusted reaches must produce nothing at all.

    python tests/taint_corpus.py           # every language
    python tests/taint_corpus.py python    # one
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from repoxray.analysis.run import analyse_file  # noqa: E402

# (lang, name, code, expect_rules[], forbid_rules[], expect_const_safe[])
CASES: list[tuple] = [

    # ------------------------------------------------------------------ python
    ("python", "taint through two assignments", '''
import os
from flask import request
def view():
    name = request.args.get("n")
    cmd = "ls " + name
    os.system(cmd)
''', ["taint.py.os_system"], [], []),

    ("python", "constant command is not a finding", '''
import os
def view():
    os.system("ls /tmp")
''', [], ["taint.py.os_system"], ["py.os_system"]),

    # Constness that survives a call. The gain and the risk are the same edit, so both
    # directions are pinned: a fixed sibling path is proven safe, and a path with one
    # untrusted component through the same builder is still a finding.
    ("python", "a path built only from __file__ is a constant", '''
import os
from flask import request, Flask
app = Flask(__name__)
@app.route("/f")
def f():
    p = os.path.join(os.path.dirname(__file__), "fixed.txt")
    return open(p).read()
''', [], ["taint.py.open"], ["py.open"]),

    ("python", "one untrusted component makes the same join unsafe", '''
import os
from flask import request, Flask
app = Flask(__name__)
@app.route("/f")
def f():
    p = os.path.join(os.path.dirname(__file__), request.args.get("n"))
    return open(p).read()
''', ["taint.py.open"], [], []),

    ("python", "shlex.quote neutralises it", '''
import os, shlex
from flask import request
def view():
    os.system("ls " + shlex.quote(request.args.get("n")))
''', [], ["taint.py.os_system"], []),

    ("python", "sql built with percent formatting", '''
from flask import request
def view(cur):
    q = "SELECT * FROM t WHERE a='%s'" % request.args.get("a")
    cur.execute(q)
''', ["taint.py.sql"], [], []),

    ("python", "parameterised query stays quiet", '''
from flask import request
def view(cur):
    cur.execute("SELECT * FROM t WHERE a=%s", (request.args.get("a"),))
''', [], ["taint.py.sql"], []),

    ("python", "pickle of request body", '''
import pickle
from flask import request
def view():
    return pickle.loads(request.get_json())
''', ["taint.py.pickle"], [], []),

    ("python", "taint across a local function call", '''
import os
from flask import request
def helper(v):
    os.system(v)
def view():
    helper(request.args.get("x"))
''', ["taint.py.os_system"], [], []),

    ("python", "environment variable is a weaker source", '''
import os
def view():
    os.system("backup " + os.environ.get("TARGET"))
''', ["taint.py.os_system"], [], []),

    # -------------------------------------------------------------- javascript
    ("javascript", "template literal into sql", '''
app.get("/u", (req, res) => {
  const id = req.query.id
  const q = `SELECT * FROM users WHERE id = '${id}'`
  db.query(q)
})
''', ["taint.js.sql"], [], []),

    ("javascript", "constant exec is not a finding", '''
app.get("/v", (req, res) => { exec("node --version") })
''', [], ["taint.js.exec"], ["js.exec"]),

    ("javascript", "regex exec is not a command at all", '''
const m = /ab(c)/.exec(someString)
const n = new RegExp(pattern).exec(line)
''', [], ["taint.js.exec"], []),

    # morluto/rea verify-commandcode-client.mjs: `exec` imported from a sibling module
    # where it is `promisify(execFile)`. Reported as CWE-78 in eight files; there is no
    # shell in that path, so the engine reclassifies rather than reports, and the hit says
    # which definition it read.
    ("javascript", "a promisified execFile is not a shell", '''
import { promisify } from "node:util";
import { execFile } from "node:child_process";
const exec = promisify(execFile);
app.get("/v", (req, res) => { exec(req.query.bin, ["--version"]) })
''', ["taint.js.exec"], [], []),

    # morluto/rea verify-go-binary.mjs:18 - `execute` is also a database method name, and
    # `js.sql` fired on it at weight 9.
    ("javascript", "a promisified execFile is not a database call either", '''
import { promisify } from "node:util";
import { execFile } from "node:child_process";
const execute = promisify(execFile);
app.get("/v", (req, res) => { execute(compiler, ["version"], { env: req.query }) })
''', [], ["taint.js.sql"], []),

    ("javascript", "a path from __dirname alone is a constant", '''
const path = require("path");
const fs = require("fs");
app.get("/f", (req, res) => {
  res.send(fs.readFileSync(path.join(__dirname, "assets", "logo.svg")))
})
''', [], ["taint.js.fs"], ["js.fs"]),

    ("javascript", "one untrusted component makes the same join unsafe", '''
const path = require("path");
const fs = require("fs");
app.get("/f", (req, res) => {
  res.send(fs.readFileSync(path.join(__dirname, "uploads", req.query.name)))
})
''', ["taint.js.fs"], [], []),

    ("javascript", "ssrf through a variable", '''
app.post("/fetch", (req, res) => {
  const url = req.body.target
  fetch(url).then(r => r.text())
})
''', ["taint.js.fetch"], [], []),

    ("javascript", "basename kills traversal but not command injection", '''
app.get("/a", (req, res) => {
  const f = path.basename(req.query.f)
  fs.readFile(path.join("/data", f), cb)
  exec("cat " + f)
})
''', ["taint.js.exec"], ["taint.js.fs"], []),

    ("javascript", "template engine compiled from input", '''
app.get("/p", (req, res) => {
  res.send(pug.compile(req.query.tpl)())
})
''', ["taint.js.template"], [], []),

    ("javascript", "taint into a named helper", '''
function run(cmd) { exec(cmd) }
app.get("/x", (req, res) => { run(req.query.c) })
''', ["taint.js.exec"], [], []),

    ("typescript", "typescript is analysed too", '''
app.get("/u", (req: Request, res: Response) => {
  const id: string = req.params.id
  models.sequelize.query(`SELECT * FROM Users WHERE id = '${id}'`)
})
''', ["taint.js.sql"], [], []),

    # --------------------------------------------------------------------- php
    ("php", "superglobal into system", '''<?php
function h() {
  $name = $_GET["n"];
  system("ls " . $name);
}''', ["taint.php.exec"], [], []),

    ("php", "escapeshellarg neutralises it", '''<?php
function h() {
  system("ls " . escapeshellarg($_GET["n"]));
}''', [], ["taint.php.exec"], []),

    ("php", "constant system call", '''<?php
function h() { system("uptime"); }''', [], ["taint.php.exec"], ["php.exec"]),

    ("php", "file read from request", '''<?php
function h() { echo file_get_contents($_GET["f"]); }''', ["taint.php.file"], [], []),

    # ---------------------------------------------------------- go / java / c#
    ("go", "tainted argument in a later position", '''package main
func handler(w http.ResponseWriter, r *http.Request) {
    name := r.FormValue("name")
    exec.Command("sh", "-c", "ls "+name).Run()
}''', ["taint.go.exec"], [], []),

    ("go", "filepath.Base stops traversal", '''package main
func handler(w http.ResponseWriter, r *http.Request) {
    safe := filepath.Base(r.FormValue("f"))
    os.Open(filepath.Join("/data", safe))
}''', [], ["taint.go.file"], []),

    ("go", "context.Context is not request input", '''package main
func fetch(ctx context.Context, metadataURL string) {
    ctx, cancel := context.WithTimeout(ctx, time.Second)
    defer cancel()
    http.NewRequestWithContext(ctx, "GET", metadataURL, nil)
}''', [], ["taint.go.ssrf_new_ctx"], []),

    # A tainted argument to a fixed non-shell program is still worth reporting - it is
    # argument injection, not command injection. The category carries that difference;
    # tests/precision_corpus.py is what pins it.
    ("go", "constant argument to a fixed program is silent", '''package main
const target = "https://example.com/"
func handler(w http.ResponseWriter, r *http.Request) {
    exec.Command("open", target)
}''', [], ["taint.go.exec"], ["go.exec"]),

    ("go", "request URL in NewRequestWithContext is SSRF input", '''package main
func handler(w http.ResponseWriter, r *http.Request) {
    target := r.FormValue("url")
    http.NewRequestWithContext(context.Background(), "GET", target, nil)
}''', ["taint.go.ssrf_new_ctx"], [], []),

    ("go", "context.WithTimeout does not transfer taint", '''package main
func fetch(ctx context.Context, target string) {
    ctx, cancel := context.WithTimeout(ctx, time.Second)
    defer cancel()
    http.NewRequestWithContext(ctx, "GET", defaultMetadataURL, nil)
}''', [], ["taint.go.ssrf_new_ctx"], []),

    ("java", "servlet parameter into sql", '''public class C {
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String q = request.getParameter("q");
    String sql = "SELECT * FROM t WHERE a='" + q + "'";
    stmt.executeQuery(sql);
  }
}''', ["taint.java.sql"], [], []),

    ("java", "constant query stays quiet", '''public class C {
  public void run() throws Exception { stmt.executeQuery("SELECT 1"); }
}''', [], ["taint.java.sql"], ["java.sql"]),

    ("csharp", "request query into Process.Start", '''public class C {
  public void Get() {
    var q = Request.Query["q"];
    var cmd = "ls " + q;
    Process.Start(cmd);
  }
}''', ["taint.cs.process"], [], []),

    ("ruby", "params into system", '''class C
  def show
    name = params[:name]
    system("ls #{name}")
  end
end''', ["taint.rb.exec"], [], []),
]


def run(only: str | None = None) -> int:
    cases = [c for c in CASES if not only or c[0] == only]
    if not cases:
        print("no cases for " + str(only))
        return 2
    failures = []
    for lang, name, code, expect, forbid, const_safe in cases:
        res = analyse_file(code, lang)
        got = {f.rule for f in res["findings"]}
        const_ids = {sid for _ln, sid, _cat in res["const_sinks"]}
        missing = [r for r in expect if r not in got]
        spurious = [r for r in forbid if r in got]
        no_const = [c for c in const_safe if c not in const_ids]
        ok = res["ok"] and not missing and not spurious and not no_const
        print(("  pass  " if ok else "  FAIL  ") + "[" + lang + "] " + name)
        if not ok:
            if not res["ok"]:
                print("           analysis failed: " + res["reason"])
            if missing:
                print("           expected but not reported: " + ", ".join(missing))
            if spurious:
                print("           reported but should not be: " + ", ".join(spurious))
            if no_const:
                print("           not proven constant: " + ", ".join(no_const))
            print("           reported: " + (", ".join(sorted(got)) or "nothing")
                  + "  | const-safe: " + (", ".join(sorted(const_ids)) or "none"))
            failures.append(name)
    print("\n" + str(len(cases) - len(failures)) + "/" + str(len(cases)) + " dataflow cases pass")
    if failures:
        print("failing: " + "; ".join(failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1] if len(sys.argv) > 1 else None))
