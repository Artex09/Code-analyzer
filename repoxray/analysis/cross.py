"""Repo-level interprocedural pass: join a tainted call site in one file to a summary in another.

The per-file analysis produces two halves of a vulnerability and never sees them meet:

    routes/admin.js   app.post("/run", (req, res) => runJob(req.body.name))
    lib/jobs.js       exports.runJob = (name) => exec("./run " + name)

The first file records a *call site*: "untrusted data, argument 0, into `runJob`". The second
records a *summary*: "argument 0 of `runJob` reaches exec at line 4". Resolving `runJob` to
`lib/jobs.js` turns the pair into one finding with a trace that spans both files.

Summaries compose, so the chain is not limited to one hop: if `runJob` merely forwards its
argument to `shell.run`, the closure step pulls `shell.run`'s sinks into `runJob`'s summary
before the join happens, and the trace records every file it passed through.

What this pass deliberately does not do: guess. A call that resolves to nothing is dropped,
a call that resolves to several candidates reports each at reduced confidence, and recursion
is cut at MAX_HOPS rather than unrolled.
"""
from __future__ import annotations

import re
from dataclasses import replace

from .dataflow import LOCAL_KINDS
from .model import FileFacts, Finding, SinkRef, TraceStep
from .resolve import RepoIndex

MAX_HOPS = 4             # function boundaries one flow may cross
MAX_CANDIDATES = 4       # distinct functions one callee name may be taken to mean
MAX_CLOSURE_ROUNDS = 4
MAX_FINDINGS = 400       # repo-wide cap, highest weight first
STRONG = ("import", "same-package")
_SEP = re.compile(r"(?:->|::|\.|\$|@)+")


class CrossIndex:
    def __init__(self, index: RepoIndex) -> None:
        self.index = index
        self.facts: dict = {}          # path -> FileFacts
        self.fn_table: dict = {}       # (path, name) -> Summary
        self.by_name: dict = {}        # name -> [(path, name)]
        self.alias: dict = {}          # path -> {local name: [(path, remote name, strength)]}
        self.stats = {"callsites": 0, "resolved": 0, "unresolved": 0, "composed": 0,
                      "findings": 0, "weak_links": 0}

    # -------------------------------------------------------------- building

    def add(self, path: str, lang: str, result: dict, imports: list, exports: tuple) -> None:
        path = path.replace("\\", "/")
        facts = FileFacts(path=path, lang=lang, summaries=dict(result.get("summaries") or {}),
                          callsites=list(result.get("callsites") or []),
                          imports=list(imports or []), exports=tuple(exports or ()),
                          bindings=list(result.get("bindings") or []))
        self.facts[path] = facts
        for name, summary in facts.summaries.items():
            if name.startswith("<"):
                continue
            summary.path = path
            self.fn_table[(path, name)] = summary
            self.by_name.setdefault(name, []).append((path, name))
        self.stats["callsites"] += len(facts.callsites)

    def build_links(self) -> None:
        for path, facts in self.facts.items():
            table: dict = {}
            for kind, spec, aliases in facts.imports:
                targets = self.index.resolve(facts.lang, path, spec, kind)
                if not targets:
                    continue
                if kind == "relative":
                    # `require 'lib/runner.php'` does not bind one name: it pulls in every
                    # function the file declares, which is how most PHP and Ruby code is
                    # organised. Binding only the module's own stem would resolve nothing.
                    for tpath, strength in targets:
                        for name in self.facts.get(tpath, FileFacts()).summaries:
                            if name.startswith("<"):
                                continue
                            bucket = table.setdefault(name, [])
                            entry = (tpath, name, strength)
                            if entry not in bucket:
                                bucket.append(entry)
                for local, remote in aliases.items():
                    bucket = table.setdefault(local, [])
                    for tpath, strength in targets:
                        if tpath == path:
                            continue
                        entry = (tpath, remote, strength)
                        if entry not in bucket:
                            bucket.append(entry)
            # `constructor(private userService: UserService)` then `this.userService.find(x)`:
            # the field is only a name until the class it holds is matched to its import.
            for name, type_name in facts.bindings:
                entries = table.get(type_name)
                if not entries:
                    continue
                bucket = table.setdefault(name, [])
                for entry in entries:
                    if entry not in bucket:
                        bucket.append(entry)
            for tpath, strength in self.index.same_package(facts.lang, path):
                for name in self.facts.get(tpath, FileFacts()).summaries:
                    if name.startswith("<"):
                        continue
                    bucket = table.setdefault(name, [])
                    entry = (tpath, name, strength)
                    if entry not in bucket:
                        bucket.append(entry)
            self.alias[path] = table

    # ------------------------------------------------------------ resolution

    def targets(self, path: str, callee: str) -> list:
        """[((path, function), link strength)] a callee name could mean."""
        # php writes $obj->method and Klass::method, ruby writes Mod::fn
        parts = [p for p in _SEP.split(callee.replace("?", "")) if p]
        if not parts:
            return []
        base = parts[-1]
        table = self.alias.get(path, {})
        out: list = []

        def offer(key, strength):
            if key in self.fn_table and key[0] != path and (key, strength) not in out:
                out.append((key, strength))

        # Any segment before the method can be the thing that was imported: `util.run()`,
        # `this.userService.find()`, `helpers.db.query()`. `this` never is.
        heads = [p for p in parts[:-1] if p not in ("this", "self", "cls", "window")]
        for local in dict.fromkeys(heads + [base]):
            for tpath, remote, strength in table.get(local, []):
                offer((tpath, base), strength)
                if remote != base:
                    offer((tpath, remote), strength)
        if out:
            return out[:MAX_CANDIDATES]

        # Nothing resolved. A name defined exactly once in the whole repository is a fair
        # guess, and it is the only way to link languages with no usable import syntax.
        if len(base) >= 4 and not base.startswith("_"):
            cands = [c for c in self.by_name.get(base, []) if c[0] != path]
            if len(cands) == 1:
                out.append((cands[0], "name"))
        return out

    # --------------------------------------------------------------- closure

    def close(self) -> None:
        """Pull callees' sinks into their callers' summaries until nothing changes."""
        for _ in range(MAX_CLOSURE_ROUNDS):
            changed = False
            for (path, _name), summary in list(self.fn_table.items()):
                for idx, forwards in list(summary.param_forwards.items()):
                    for callee, arg, line in list(forwards):
                        for key, strength in self.targets(path, callee):
                            target = self.fn_table.get(key)
                            if target is None or target is summary:
                                continue
                            for ref in list(target.param_sinks.get(arg, [])):
                                if ref.hops >= MAX_HOPS:
                                    continue
                                grown = replace(
                                    ref, hops=ref.hops + 1, via=ref.via + (strength,),
                                    steps=(TraceStep(
                                        line=line, code="",
                                        note="handed to " + callee + "() in " + key[0],
                                        path=path),) + tuple(ref.steps))
                                bucket = summary.param_sinks.setdefault(idx, [])
                                if _novel(bucket, grown):
                                    bucket.append(grown)
                                    changed = True
                                    self.stats["composed"] += 1
            if not changed:
                break

    # -------------------------------------------------------------- findings

    def findings(self) -> dict:
        """{path: [Finding]} - the sink file gets the finding, the entry file a pointer."""
        out: dict = {}
        collected: list = []
        for path, facts in self.facts.items():
            for site in facts.callsites:
                resolved = self.targets(path, site.callee)
                if not resolved:
                    self.stats["unresolved"] += 1
                    continue
                self.stats["resolved"] += 1
                for (tpath, tname), strength in resolved:
                    target = self.fn_table.get((tpath, tname))
                    if target is None:
                        continue
                    for ref in target.param_sinks.get(site.arg, []):
                        if "*" in site.killed or ref.cat in site.killed:
                            continue
                        if "*" in ref.killed or ref.cat in ref.killed:
                            continue
                        collected.append((site, path, tpath, tname, ref, strength))
        collected.sort(key=lambda row: -row[4].weight)
        # One helper reached from six controllers is one finding with six entry points, not
        # six findings on the same line: the fix is in one place and the reviewer wants the
        # whole list in front of them.
        groups: dict = {}
        for row in collected:
            site, path, tpath, _tname, ref, _strength = row
            groups.setdefault((ref.path or tpath, ref.line, ref.sink_id), []).append(row)
        # On the *entry* side the unit is the call site, not the sink. One line handing a
        # workspace path to `verifyWindowsProtocolInput()` reached three dynamic imports
        # inside that module and printed three identical rows on the same line, with the
        # same rule and the same source. That is one thing to look at.
        emitted_entries: dict = {}
        for _key, rows in list(groups.items())[:MAX_FINDINGS]:
            rows.sort(key=lambda r: (r[5] not in STRONG, r[4].hops, r[0].confidence != "high"))
            site, path, tpath, tname, ref, strength = rows[0]
            weak = strength not in STRONG or "name" in ref.via
            if weak:
                self.stats["weak_links"] += 1
            sink_path = ref.path or tpath
            entries = []
            for other_site, other_path, _tp, _tn, _r, _s in rows:
                entry = {"path": other_path, "line": other_site.line,
                         "source": other_site.source, "function": other_site.scope}
                if entry not in entries:
                    entries.append(entry)
            sink_finding, entry_finding = _build(site, path, tpath, tname, ref, strength,
                                                 weak, sink_path, entries)
            out.setdefault(sink_path, []).append(sink_finding)
            self.stats["findings"] += 1
            for other_site, other_path, _tp, _tn, _r, _s in rows:
                if other_path == sink_path:
                    continue
                ekey = (other_path, other_site.line, ref.sink_id)
                seen = emitted_entries.get(ekey)
                if seen is not None:
                    seen.cross.setdefault("also_reaches", []).append(
                        sink_path + ":" + str(ref.line))
                    extra = len(seen.cross["also_reaches"])
                    seen.why = (seen.why.rstrip(".") + ", and to " + str(extra)
                                + " other place" + ("" if extra == 1 else "s")
                                + " in the same module.")
                    continue
                _, pointer = _build(other_site, other_path, tpath, tname, ref, strength,
                                    weak, sink_path, entries)
                emitted_entries[ekey] = pointer
                out.setdefault(other_path, []).append(pointer)
        return out

    def tainted_returns(self) -> dict:
        """{path: {local name, ...}} for imported functions that return untrusted data.

        The mirror image of the main pass: data coming *back* from another module. The
        caller has to be analysed again knowing this, which `score` does in a second round.
        """
        out: dict = {}
        for path, table in self.alias.items():
            names = set()
            for local, entries in table.items():
                for tpath, remote, _strength in entries:
                    for candidate in (remote, local):
                        summary = self.fn_table.get((tpath, candidate))
                        if summary is not None and summary.returns_source:
                            names.add(local)
            if names:
                out[path] = names
        return out


def _novel(bucket: list, ref: SinkRef) -> bool:
    return not any(r.sink_id == ref.sink_id and r.line == ref.line and r.path == ref.path
                   for r in bucket)


def _build(site, path: str, tpath: str, tname: str, ref: SinkRef, strength: str,
           weak: bool, sink_path: str, entries: list) -> tuple:
    trace = [TraceStep(line=s.line, code=s.code, note=s.note, path=path) for s in site.steps]
    trace.append(TraceStep(line=ref.line if not ref.steps else ref.steps[0].line, code="",
                           note="crosses into " + tpath + " as argument " + str(site.arg)
                                + " of " + tname + "()",
                           path=tpath))
    for step in ref.steps:
        trace.append(TraceStep(line=step.line, code=step.code, note=step.note,
                               path=step.path or tpath))

    conf = "high"
    if site.confidence != "high" or site.sanitized:
        conf = "medium"
    if weak or ref.hops > 1:
        conf = "medium"
    if weak and ref.hops > 1:
        conf = "low"
    weight = ref.weight
    source = site.source
    if site.kind in LOCAL_KINDS:
        weight = max(3, weight - 4)
        conf = "low"
        source += " (local input, not remotely reachable)"

    link_note = "resolved by " + ("import" if strength == "import" else strength)
    cross = {
        "entry_path": path, "entry_line": site.line, "entry_source": source,
        "sink_path": sink_path, "sink_line": ref.line, "function": tname,
        "arg": site.arg, "hops": ref.hops + 1, "link": strength, "weak": weak,
        "via": list(ref.via),
        "entries": entries[:8],
        "entry_count": len(entries),
    }
    sink_finding = Finding(
        rule="xtaint." + ref.sink_id,
        cat=ref.cat,
        title=ref.title + " (reached from another file)",
        why=ref.why + " The value arrives from " + path + ":" + str(site.line)
            + (" and " + str(len(entries) - 1) + " other call site(s)"
               if len(entries) > 1 else "")
            + ", which this file cannot see.",
        line=ref.line,
        snippet="",
        weight=weight,
        confidence=conf,
        engine="xtaint",
        source_label=source + " via " + path,
        sanitizers=tuple(site.sanitized) + tuple(ref.sanitized),
        trace=trace,
        guards=ref.guards,
        proof=link_note,
        cross=cross,
    )
    entry_finding = Finding(
        rule="xentry." + ref.sink_id,
        cat=ref.cat,
        title="untrusted input leaves this file and reaches " + ref.title,
        why="This file hands attacker-controlled data to " + tname + "(), which passes it to "
            + ref.title.lower() + " at " + sink_path + ":" + str(ref.line) + ".",
        line=site.line,
        snippet="",
        weight=max(3, weight - 2),
        confidence=conf,
        engine="xentry",
        source_label=source,
        sanitizers=tuple(site.sanitized),
        trace=trace,
        guards=ref.guards,
        proof=link_note,
        cross=cross,
    )
    return sink_finding, entry_finding
