"""Labelled rule corpus: does a rule fire where it should, and stay quiet where it should not?

Every case is real code shape, most of them lifted verbatim from repositories the scanner was
run against. `hit` lists rules that must fire, `miss` lists rules that must not.

    python tests/rule_corpus.py            # all languages
    python tests/rule_corpus.py js         # one section
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from repoxray.score import analyse_file  # noqa: E402

# (section, name, lang, code, hit[], miss[])
CASES: list[tuple] = [

    # ---------------------------------------------------------------- command exec
    ("js", "regex exec is not a shell", "typescript", """
      const color = /^rgb\\((\\d+), ?(\\d+)\\)$/i.exec(style)
      if (new RegExp(`vuln-line.*${key}`).exec(lines[i])) { keep(i) }
    """, [], ["js.child_exec"]),

    ("js", "destructured child_process exec", "javascript", """
      const { exec } = require('child_process')
      exec('ls ' + req.query.dir, (err, stdout) => res.send(stdout))
    """, ["js.child_exec"], []),

    ("js", "execSync call", "javascript", """
      const globalRoot = execSync('npm root -g', { encoding: 'utf8' }).trim()
    """, ["js.child_exec"], []),

    ("js", "child_process member call", "javascript", """
      const cp = require('child_process')
      cp.execFile(userBinary, args)
    """, ["js.child_exec"], []),

    ("js", "spawn with shell true", "javascript", """
      spawn(cmd, args, { shell: true })
    """, ["js.spawn_shell"], []),

    # ------------------------------------------------------------------ http fetch
    ("js", "supertest request(app) is not ssrf", "typescript", """
      import request from 'supertest'
      const res = await request(app).get('/rest/user/whoami').set('Authorization', token)
    """, [], ["js.fetch_var"]),

    ("js", "server side fetch of a user url", "typescript", """
      const url = req.body.imageUrl
      const response = await fetch(url)
    """, ["js.fetch_var"], []),

    ("js", "axios to a template url", "javascript", """
      const r = await axios.get(`${base}/${req.params.id}`)
    """, ["js.fetch_var"], []),

    # -------------------------------------------------------------------- redirect
    ("js", "a variable named location is not a redirect", "typescript", """
      private readonly location = inject(Location)
      const location = TestBed.inject(Location)
    """, [], ["js.redirect_var"]),

    ("js", "window.location assignment", "javascript", """
      window.location.href = params.next
    """, ["js.redirect_var"], []),

    ("js", "express redirect to user value", "javascript", """
      res.redirect(req.query.to)
    """, ["js.redirect_var"], []),

    ("js", "redirect to a literal path is fine", "javascript", """
      res.redirect('/login')
    """, [], ["js.redirect_var"]),

    # ------------------------------------------------------------ prototype / mass
    ("js", "signal setter is not a deep merge", "typescript", """
      this.chatBotName.set(config.application.chatBot.name)
      this.sampleQuestions.set(config.application.chatBot.sampleQuestions)
    """, [], ["js.proto_pollute"]),

    ("js", "lodash merge into empty object", "javascript", """
      const opts = _.merge({}, defaults, req.body)
    """, ["js.proto_pollute"], []),

    ("js", "model built straight from body", "javascript", """
      await UserModel.create(req.body)
    """, ["js.mass_assign"], []),

    # ------------------------------------------------------------------- data layer
    ("js", "sequelize where clause is not nosql injection", "typescript", """
      const address = await AddressModel.findOne({ where: { id: req.params.id, UserId: user.id } })
    """, ["js.orm_idor"], ["js.mongo_req"]),

    ("js", "mongo query object from the request", "javascript", """
      const user = await db.collection('users').findOne(req.body)
    """, ["js.mongo_req"], []),

    ("js", "mongo where operator", "javascript", """
      db.users.find({ $where: 'this.name === ' + name })
    """, ["js.mongo_where"], []),

    ("js", "interpolated sql", "typescript", """
      models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email}'`)
    """, ["js.sql_template"], []),

    # ------------------------------------------------------- template injection (new)
    ("js", "pug.compile on a built template", "typescript", """
      const template = fs.readFileSync('views/profile.pug').toString()
      const fn = pug.compile(template)
      res.send(fn(user))
    """, ["js.ssti"], []),

    ("js", "res.render with a literal view is fine", "typescript", """
      res.render('dataErasureForm', { userEmail: loggedInUser.data.email })
    """, [], ["js.ssti"]),

    ("js", "res.render with a computed view", "javascript", """
      res.render(req.query.page, { user })
    """, ["js.ssti"], []),

    ("js", "handlebars compile", "javascript", """
      const tpl = handlebars.compile(source)
    """, ["js.ssti"], []),

    # ------------------------------------------------------------ angular xss (new)
    ("js", "DomSanitizer bypass", "typescript", """
      this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam)
    """, ["js.ng_bypass"], []),

    ("js", "sanitize is the safe path", "typescript", """
      this.searchValue = this.sanitizer.sanitize(SecurityContext.HTML, queryParam)
    """, [], ["js.ng_bypass"]),

    # ------------------------------------------------------- reflected output (new)
    ("js", "res.send of request data", "javascript", """
      res.send('<h1>' + req.query.q + '</h1>')
    """, ["js.res_reflect"], []),

    ("js", "header set from request data", "javascript", """
      res.setHeader('X-Forwarded-Host', req.headers.host)
    """, ["js.header_inject"], []),

    ("js", "static header is fine", "javascript", """
      res.setHeader('Content-Type', 'application/json')
    """, [], ["js.header_inject"]),

    # ------------------------------------------------------- dynamic require (new)
    ("js", "require with a variable", "javascript", """
      const mod = require(req.query.plugin)
    """, ["js.dyn_require"], []),

    ("js", "static require is fine", "javascript", """
      const express = require('express')
      const { promisify } = require('util')
    """, [], ["js.dyn_require"]),

    # ------------------------------------------------------------------- unchanged
    ("js", "eval", "javascript", "const answer = eval(expression)", ["js.eval"], []),
    ("js", "innerHTML sink", "javascript", "el.innerHTML = untrusted", ["js.innerhtml"], []),
    ("js", "dangerouslySetInnerHTML", "javascript",
     "<div dangerouslySetInnerHTML={{ __html: body }} />", ["js.dangerous_html"], []),
    ("js", "tls off", "javascript", "const agent = new https.Agent({ rejectUnauthorized: false })",
     ["js.tls_off"], []),
    ("js", "jwt decode without verify", "javascript", "const p = jwt.decode(token)",
     ["js.jwt_weak"], []),
    ("js", "path join from params", "javascript",
     "const p = path.join(__dirname, 'up', req.params.file)", ["js.path_req"], []),
    ("js", "vm sandbox", "javascript", "vm.runInNewContext(userCode, {})", ["js.vm"], []),
]


def run(section_filter: str | None = None) -> int:
    cases = [c for c in CASES if not section_filter or c[0] == section_filter]
    if not cases:
        print("no cases for section " + str(section_filter))
        return 2

    failures = []
    for section, name, lang, code, want_hit, want_miss in cases:
        rec = {
            "path": "corpus/" + name.replace(" ", "_") + (".ts" if lang == "typescript" else ".js"),
            "lang": lang, "kind": "code", "lines": code.count("\n") + 1, "size": len(code),
            "is_test": False, "is_vendored": False, "is_generated": False,
        }
        analyse_file(rec, code)
        fired = {h["rule"] for h in rec["hits"]}
        missing = [r for r in want_hit if r not in fired]
        spurious = [r for r in want_miss if r in fired]
        ok = not missing and not spurious
        print(("  pass  " if ok else "  FAIL  ") + "[" + section + "] " + name)
        if not ok:
            if missing:
                print("           expected but silent: " + ", ".join(missing))
            if spurious:
                print("           fired but should not: " + ", ".join(spurious))
            print("           actually fired: " + (", ".join(sorted(fired)) or "nothing"))
            failures.append(name)

    print("\n" + str(len(cases) - len(failures)) + "/" + str(len(cases)) + " cases pass")
    if failures:
        print("failing: " + "; ".join(failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1] if len(sys.argv) > 1 else None))
