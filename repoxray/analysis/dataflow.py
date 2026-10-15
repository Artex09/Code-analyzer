"""Forward may-taint dataflow over a condition-labelled CFG, driven by a language adapter.

What this buys over regex matching, in both directions:

  reduces false positives - `exec("npm root -g")` has a constant argument, so no finding is
  produced at all, where a regex sees `exec(` and shouts;

  reduces false negatives - `const q = "SELECT ..." + req.query.id; db.query(q)` never has the
  request object on the sink line, so no single-line pattern can ever catch it; following the
  assignment does.

Three things happen here that a plain reaching-taint pass does not do.

  Path conditions. Every CFG edge out of a branch carries the test and the polarity that
  takes it, and a statement that ends a path (`return`, `throw`, `break`) gets no successor.
  The conditions collected on the way to a sink go to Z3 in `pathcond`: a contradictory
  conjunction means the sink is unreachable, and a conjunction that cannot admit a payload
  means the value was validated. Both outcomes delete the finding instead of shipping it.

  Function summaries. Each parameter is also seeded with a symbolic "formal" taint. Sinks it
  reaches are not reported - they are recorded as "argument i of this function lands in
  `exec`". That summary is what makes a caller in another file analysable, and it composes
  through `param_forwards` when the parameter is handed on again.

  Call sites. A call passing untrusted data into something this file does not define is
  recorded with its trace, so the repo-level pass in `cross` can join it to the summary of
  whatever that name resolves to.

Honest scope: within a file this is context-insensitive and bounded; across files it is
summary-based, so a flow is followed through as many modules as the links resolve, while
recursion and dynamic dispatch are cut off rather than guessed at.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, replace

from . import binding, pathcond
from .model import (PAYLOAD_VALUES, TRUST_INFERRED, CallSite, Evidence, Finding,
                    ParamSource, SinkRef, Summary, TraceStep)
from .pathcond import Cond, PathChecker

MAX_STATEMENTS = 600        # give up on generated monsters
MAX_ROUNDS = 6              # fixpoint iterations per function
MAX_INTERPROC_ROUNDS = 3    # how often to re-run after learning a param is tainted
MAX_DEPTH = 40              # expression recursion guard
MAX_PATH_WORK = 4000        # CFG path-enumeration budget per sink

# sources that an internet attacker does not control
LOCAL_KINDS = {"cli", "env", "file"}

# Classes whose exploit is a string payload. A value that cannot be a free-form string -
# an integer id, an enum, a boolean - cannot produce one of these however untrusted it is.
STRING_PAYLOAD_CATS = {"cmd", "code", "sqli", "xss", "tmpl", "path", "ssrf", "redirect",
                       "nosql", "deser", "argv", "crlf", "upload", "xxe"}


# Naming is the only signal a secret has, and unlike a sink name it is a reliable one: a
# value read from `GITHUB_TOKEN` is a credential whatever else is true. Secrets get their
# own class because `secret -> log -> leak` is a different question from injection.
# No \b: the name is almost always `GITHUB_TOKEN` or `apiKey`, and `_` is a word character,
# so a word boundary never fires where it matters.
SECRET_NAME = re.compile(
    r"(?i)(secret|token|password|passwd|credential|api[_-]?key|apikey|privkey|"
    r"private[_-]?key|access[_-]?key|auth[_-]?key|signing[_-]?key|session[_-]?key|"
    r"encryption[_-]?key|bearer|dsn|connection[_-]?string|[_-]pwd\b|\bpwd[_-])")


def _secret_value(src, text: str) -> str:
    """`secret` only for a credential the application holds, never for request data.

    `req.cookies.token` contains the word token and is the *attacker's* input, not a
    credential to protect. Reading the name without asking where the value came from would
    have reclassified juice-shop's whole session-token flow as a disclosure question and
    suppressed the RCE at the end of it - the same name-only mistake this round is about.
    """
    if src.kind == "request":
        return src.value
    return "secret" if SECRET_NAME.search(text) else src.value


def _value_phrase(value: str) -> str:
    return {"id": "an identifier (integer or hash)", "enum": "one of a fixed set of values",
            "bool": "a boolean", "trigger": "an event name, not data",
            "secret": "a secret"}.get(value, "not free-form text")


def _guard_state(verdict, taint) -> str:
    """How much the checks on the path are worth, by what kind of check they are.

    An `if` is not automatically a security guard, and the kinds are not interchangeable:

      validator-opaque  a function named like a validator gates the path and its body is
                        not visible. The value may already be checked, so the honest answer
                        is that the question is open.
      authorization     the check gates *who* can reach the path, not what the value is.
                        The bug is real and conditional - say which condition.
      partial           a filter that removes some of what a payload needs.
      bypass-required   the solver produced a value that satisfies every check.
    """
    kinds = tuple(getattr(verdict, "kinds", ()) or ())
    if taint is not None and taint.partial:
        return "partial"
    if verdict.witness:
        # the solver got through the checks it could read; an unreadable one still stands
        if "validator" in kinds:
            return "validator-opaque"
        return "bypass-required" if verdict.guards else "none"
    if "validator" in kinds:
        return "validator-opaque"
    if "authorization" in kinds:
        return "authorization"
    if verdict.guards and set(kinds) - {"existence"}:
        return "present"
    return "none"


@dataclass(frozen=True)
class Taint:
    source: str             # human label of where it came from
    kind: str               # request | cli | env | formal | param | ...
    steps: tuple = ()       # TraceStep tuple, oldest first
    sanitized: tuple = ()   # sanitizer labels seen on the way
    killed: tuple = ()      # categories those sanitizers neutralise; "*" means all
    confidence: str = "high"
    syms: tuple = ()        # storage keys this value has been held in
    formal: tuple = ()      # (function name, parameter index) when this is a summary probe
    # what the value can be, and how much the claim is worth
    value: str = "text"     # text | opaque | id | enum | bool | secret | trigger
    trust: str = "known"    # known = modelled framework surface, inferred = a name guess
    assumed: int = 0         # hops through a call whose body we never saw
    removed: tuple = ()     # characters a partial sanitizer took out of the payload
    partial: tuple = ()     # labels of the partial sanitizers applied


def _txt(node, data: bytes) -> str:
    try:
        return data[node.start_byte:node.end_byte].decode("utf-8", "replace")
    except Exception:
        return ""


def _line(node) -> int:
    return node.start_point[0] + 1


# how to finish the sentence "... which is not X"
_FAMILY_IS = {
    binding.SHELL: "a shell",
    binding.ARGV: "a way of starting a process",
    binding.DB: "a database call",
    binding.CODE: "an evaluator",
    binding.HTTP: "an HTTP client",
}


class Analyzer:
    def __init__(self, spec, data: bytes, lines: list, path: str = "",
                 tainted_returns=(), bindings=None, dep_kind: str = ""):
        self.spec = spec
        self.bindings = bindings or {}
        self.dep_kind = dep_kind
        self.ad = spec.adapter
        self.data = data
        self.lines = lines
        self.path = path
        self.src_res = [(s, re.compile(s.pattern)) for s in spec.sources]
        self.sink_res = [(s, re.compile(s.pattern)) for s in spec.sinks]
        self.san_res = [(s, re.compile(s.pattern)) for s in spec.sanitizers]
        self.prop_res = [(p, re.compile(p.pattern)) for p in spec.propagators]
        self.guard_res = [(g, re.compile(g.pattern)) for g in spec.guards]
        self.barrier_res = [(b, re.compile(b.pattern)) for b in spec.barriers]
        self.param_src = [(ps, re.compile(ps.type_pattern) if ps.type_pattern else None,
                           re.compile(ps.name_pattern) if ps.name_pattern else None)
                          for ps in spec.param_sources]
        # A name match is a convention, so the framework it is a convention of has to be
        # in the file. Compiled once and tested against the whole source, because an
        # import can sit anywhere above the handler.
        whole = "\n".join(lines)
        self.framework_present = {
            ps.id: bool(re.search(ps.requires, whole)) for ps in spec.param_sources
            if ps.requires}
        for pattern in spec.handler_params:
            if not any(ps.name_pattern == pattern for ps, _t, _n in self.param_src):
                self.param_src.append((
                    ParamSource(id="handler", label="handler parameter",
                                name_pattern=pattern, kind="request", value="text"),
                    None, re.compile(pattern)))
        self.const_call_res = [re.compile(p) for p in self.ad.const_calls]
        self.const_ident_res = [re.compile(p) for p in self.ad.const_idents]
        self.never_param_res = [re.compile(p) for p in spec.never_params]
        self.registrar_res = [re.compile(p) for p in spec.handler_registrars]
        self.handler_fns: set = set()
        self.shell_res = [re.compile(p) for p in spec.shells]
        self.replacer_res = [(re.compile(p), n, r) for p, n, r in spec.replacers]
        self.term_res = [re.compile(p) for p in self.ad.terminator_calls]
        # A sink inside a nested block is its own CFG node, so the enclosing `if` must not
        # also claim it: reporting from the outer statement would attach the path conditions
        # of the branch rather than of the branch's body, and lose every guard.
        self._scan_stop = tuple(set(self.ad.function_nodes) | set(self.ad.block_nodes))
        self.handler_res = [re.compile(p) for p in spec.handler_params]
        self.implicit_res = [re.compile(p) for p in spec.implicit_sources]
        self.findings: list = []
        self.const_sinks: set = set()   # (line, sink_id) proven to take only constants
        self.suppressed: list = []      # (line, sink_id, reason) stopped before the sink
        # (line, sink_id, reason) where the *name* matched and the function did not.
        # Kept apart from `suppressed`, which means "a sanitizer or a path condition
        # killed it": that is a claim about the data, and this is a claim about which
        # function this is. Counting them together printed one as the other.
        self.misidentified: list = []
        self.functions: dict = {}       # name -> node
        self.returns_taint: set = set()
        self.param_taint: dict = {}     # (fn_name, index) -> Taint
        # interprocedural + path-sensitivity bookkeeping
        self.summaries: dict = {}       # fn name -> Summary
        self.callsites: list = []       # CallSite, for the cross-file pass
        self.literals: dict = {}        # symbol -> tuple of string literals (allow-lists)
        self.consts: set = set()        # symbols proven to hold a fixed value in this file
        self.loop_values: dict = {}     # loop variable -> the literal set it ranges over
        self.checker = PathChecker(self.ad, self.txt, self.guard_res, self.literals)
        self._pc_cache: dict = {}
        self._dropped: set = set()
        self._sites: set = set()

    # ------------------------------------------------------------- utilities

    def txt(self, node) -> str:
        return _txt(node, self.data)

    def code_at(self, line: int) -> str:
        return self.lines[line - 1].strip()[:200] if 0 < line <= len(self.lines) else ""

    def step(self, node, note: str) -> TraceStep:
        ln = _line(node)
        return TraceStep(line=ln, code=self.code_at(ln), note=note)

    def symbol(self, node) -> str:
        """A stable key for a storage location: x, obj.prop, obj[...]"""
        t = node.type
        if t in self.ad.identifier_nodes:
            return self.txt(node)
        if t in self.ad.member_nodes:
            obj = node.child_by_field_name(self.ad.member_obj_field)
            prop = node.child_by_field_name(self.ad.member_prop_field)
            if obj is not None and prop is not None:
                return self.symbol(obj) + "." + self.txt(prop)
        if t in self.ad.index_nodes:
            kids = [c for c in node.named_children]
            if kids:
                return self.symbol(kids[0]) + "[]"
        return self.txt(node).strip()

    def callee_text(self, call) -> str:
        fn = call.child_by_field_name(self.ad.call_fn_field)
        if fn is None:
            # ruby-style: receiver + method fields
            recv = call.child_by_field_name("receiver")
            meth = call.child_by_field_name("method")
            if meth is not None:
                return ((self.txt(recv) + ".") if recv is not None else "") + self.txt(meth)
            return ""
        return re.sub(r"\s+", "", self.txt(fn))

    def arg_nodes(self, call) -> list:
        args = call.child_by_field_name(self.ad.call_args_field)
        if args is None:
            return []
        out = []
        for c in args.named_children:
            if c.type == "comment":
                continue
            if c.type in self.ad.arg_wrapper_nodes:
                inner = [g for g in c.named_children if g.type != "comment"]
                out.append(inner[-1] if inner else c)
                continue
            out.append(c)
        return out

    def _has_interp(self, node) -> bool:
        if not self.ad.interp_inner_nodes:
            return False
        return any(c.type in self.ad.interp_inner_nodes for c in _descendants(node, 4))

    def is_const(self, node, depth: int = 0) -> bool:
        """True when the expression cannot carry outside data."""
        if node is None or depth > MAX_DEPTH:
            return False
        t = node.type
        if t in self.ad.identifier_nodes or t in self.ad.member_nodes:
            if self.consts and self.symbol(node) in self.consts:
                return True
            text = self.txt(node).strip()
            if any(rx.match(text) for rx in self.const_ident_res):
                return True
        # A pure path or string builder is constant exactly when its arguments are.
        if t in self.ad.call_nodes and self.const_call_res:
            callee = self.callee_text(node)
            if callee and any(rx.search(callee) for rx in self.const_call_res):
                args = self.arg_nodes(node)
                return bool(args) and all(self.is_const(a, depth + 1) for a in args)
        # order matters: an f-string / template literal is also a "string" node
        if t in self.ad.interp_string_nodes:
            return not self._has_interp(node)
        if t in self.ad.string_nodes or t in self.ad.number_nodes or t in self.ad.extra_const_nodes:
            return True
        if t in self.ad.concat_nodes:
            kids = [c for c in node.named_children]
            return bool(kids) and all(self.is_const(c, depth + 1) for c in kids)
        # Grammars wrap values: go puts every `const x = "y"` initialiser in an
        # expression_list, so without looking through the wrapper no Go constant is ever
        # recognised as one.
        if t in _TRANSPARENT:
            kids = [c for c in node.named_children if c.type != "comment"]
            return bool(kids) and all(self.is_const(c, depth + 1) for c in kids)
        return False

    # --------------------------------------------------------------- sources

    def source_of(self, text: str):
        for src, rx in self.src_res:
            if rx.search(text):
                return src
        return None

    def barrier_of(self, callee: str):
        """A call whose result carries none of its arguments' taint."""
        for bar, rx in self.barrier_res:
            if rx.search(callee):
                return bar
        return None

    def is_shell(self, text: str) -> bool:
        """Does this program interpret its arguments as a command line?"""
        clean = text.strip().strip("\"'`")
        return any(rx.search(clean) for rx in self.shell_res)

    def sanitizer_of(self, callee: str):
        for san, rx in self.san_res:
            if rx.search(callee):
                return san
        return None

    def is_propagator(self, callee: str) -> bool:
        return any(rx.search(callee) for _, rx in self.prop_res)

    # ------------------------------------------------- expression evaluation

    def eval_taint(self, node, state: dict, depth: int = 0):
        """Return Taint if this expression may carry untrusted data."""
        if node is None or depth > MAX_DEPTH:
            return None
        t = node.type

        # a literal can never be tainted, and saying so early is what kills the noise
        if t in self.ad.number_nodes:
            return None
        if t in self.ad.string_nodes and not (
                t in self.ad.interp_string_nodes and self._has_interp(node)):
            return None

        # A source is an *accessor* - req.query.id, $_GET['x'], request.args.get('n') - not any
        # expression whose text happens to contain one. Matching the whole text made
        # path.basename(req.query.f) look like a bare source, so the sanitizer never applied.
        if t in self.ad.member_nodes or t in self.ad.index_nodes \
                or t in self.ad.identifier_nodes:
            text = re.sub(r"\s+", "", self.txt(node))
            src = self.source_of(text)
            if src is not None:
                value = _secret_value(src, text)
                return Taint(source=src.label, kind=src.kind, value=value,
                             trust=src.trust,
                             steps=(self.step(node, ("credential: " if value == "secret"
                                                     else "untrusted input: ") + src.label),),
                             syms=(self.symbol(node),))

        # a known-tainted variable or member
        sym = self.symbol(node)
        if sym in state:
            return state[sym]
        # obj.prop where obj itself is tainted (req.body.x when req.body is tainted)
        if t in self.ad.member_nodes or t in self.ad.index_nodes:
            kids = [c for c in node.named_children]
            if kids:
                inner = self.eval_taint(kids[0], state, depth + 1)
                if inner is not None:
                    return replace(inner, syms=_add(inner.syms, sym))

        if t in self.ad.call_nodes:
            callee = self.callee_text(node)
            # A barrier returns something unrelated to what went in. `context.WithTimeout`
            # yields a cancellation scope, not the data, and letting taint ride through it
            # produced traces that read `through context.WithTimeout` on the way to an SSRF
            # that was never there.
            if self.barrier_of(callee) is not None:
                return None
            san = self.sanitizer_of(callee)
            args = self.arg_nodes(node)
            inner = None
            for a in args:
                inner = self.eval_taint(a, state, depth + 1) or inner
            # a method on a tainted receiver keeps the taint (str.strip(), .toLowerCase())
            fn = node.child_by_field_name(self.ad.call_fn_field)
            if fn is not None and fn.type in self.ad.member_nodes:
                obj = fn.child_by_field_name(self.ad.member_obj_field)
                inner = self.eval_taint(obj, state, depth + 1) or inner
            # an accessor call such as request.args.get('n') or request.get_json()
            src = self.source_of(callee)
            if src is not None and san is None:
                # `os.Getenv("GITHUB_TOKEN")` is a credential, not free-form input: the
                # name is in the call, so read it
                whole = re.sub(r"\s+", "", self.txt(node))[:160]
                value = _secret_value(src, whole)
                return Taint(source=src.label, kind=src.kind, value=value,
                             trust=src.trust,
                             steps=(self.step(node, ("credential: " if value == "secret"
                                                     else "untrusted input: ")
                                              + src.label),))
            if san is not None:
                if inner is None:
                    return None
                if san.partial:
                    # narrows the payload, does not remove it
                    phrase = ("partly filtered by " + san.label
                              + (": " + " ".join(san.removes) + " removed, nothing else"
                                 if san.removes else ""))
                    return replace(
                        inner, partial=inner.partial + (phrase,),
                        removed=inner.removed + tuple(san.removes),
                        steps=inner.steps + (self.step(node, phrase),))
                killed = inner.killed + (tuple(san.kills) if san.kills else ("*",))
                return replace(inner, sanitized=inner.sanitized + (san.label,),
                               killed=killed,
                               steps=inner.steps + (self.step(node, "passed through "
                                                              + san.label),))
            if inner is not None:
                # A replace-style call is a filter whose effect is written down in its own
                # arguments. Reading them is the difference between "sanitized" and "& is
                # escaped for cmd.exe, and | > < " are not touched".
                effect = self._replacement_effect(node, callee)
                if effect is not None:
                    gone, label = effect
                    return replace(
                        inner, partial=inner.partial + (label,),
                        removed=inner.removed + gone,
                        steps=inner.steps + (self.step(node, label),))
                if self.is_propagator(callee):
                    return replace(inner, steps=inner.steps
                                   + (self.step(node, "through " + callee),))
                # An unknown callee *might* pass the value through. Keeping the flow is what
                # catches a taint that crosses a database round-trip; counting the hop is
                # what stops the result being announced as certain.
                return replace(inner, assumed=inner.assumed + 1,
                               steps=inner.steps + (self.step(
                                   node, "assumed to pass through " + callee
                                   + " (body not analysed)"),))
            # a local function that returns tainted data
            base = callee.split(".")[-1]
            if base in self.returns_taint:
                return Taint(source="return value of " + base + "()", kind="param",
                             trust="inferred",
                             steps=(self.step(node, "returns untrusted data"),),
                             confidence="medium")
            return None

        if t in self.ad.interp_string_nodes or t in self.ad.concat_nodes:
            for c in node.named_children:
                got = self.eval_taint(c, state, depth + 1)
                if got is not None:
                    return replace(got, steps=got.steps + (self.step(node, "built into a string"),))
            return None

        # containers, parens, await, ternaries: look inside
        if t in _TRANSPARENT or t in self.ad.interp_inner_nodes:
            for c in node.named_children:
                got = self.eval_taint(c, state, depth + 1)
                if got is not None:
                    return got
        return None

    # ----------------------------------------------------------------- CFG

    def _cond_node(self, stmt):
        """The test of a branch, unwrapped from any parentheses the grammar keeps."""
        if stmt.type not in self.ad.if_nodes and stmt.type not in self.ad.loop_nodes:
            return None
        node = stmt.child_by_field_name(self.ad.cond_field)
        if node is None:
            return None
        for _ in range(3):
            kids = [c for c in node.named_children if c.type != "comment"]
            if node.type in ("parenthesized_expression", "condition_clause",
                             "parenthesized_statement") and len(kids) == 1:
                node = kids[0]
                continue
            break
        return node

    def _arms(self, stmt) -> list:
        """[(node to build, polarity)] for a branch, or [] when the shape is unknown.

        Polarity is what the solver needs: True for the arm taken when the test holds.
        Where a grammar does not expose consequence/alternative fields the arms are still
        found by looking for block children, but with polarity None - the CFG is then as
        precise as it was before and simply carries no path condition.
        """
        is_branch = stmt.type in self.ad.if_nodes or stmt.type in self.ad.loop_nodes
        if is_branch:
            conseq = stmt.child_by_field_name(self.ad.consequence_field)
            if conseq is None:
                conseq = stmt.child_by_field_name("body")
            if conseq is not None:
                arms = [(conseq, True)]
                for node in _field_children(stmt, self.ad.alternative_field):
                    arms.append((_unwrap_else(node, self.ad), False))
                return [(a, p) for a, p in arms if a is not None]

        inner = [c for c in stmt.named_children if c.type in self.ad.block_nodes]
        if not inner:
            for c in stmt.named_children:
                inner += [g for g in c.named_children if g.type in self.ad.block_nodes]
        return [(b, None) for b in inner]

    def build_cfg(self, body) -> tuple:
        """Statement-level CFG with condition-labelled edges.

        Returns (blocks, preds) where preds[i] lists (source index, Cond or None) - the
        predecessors of block i and the branch each edge needs to be true to be taken.
        """
        blocks: list = []
        preds: list = []

        def add(stmt) -> int:
            blocks.append({"stmt": stmt})
            preds.append([])
            return len(blocks) - 1

        def link(src: int, dst: int, cond) -> None:
            preds[dst].append((src, cond))

        def stmts_of(node, depth: int = 0) -> list:
            if node is None:
                return []
            if node.type in self.ad.block_nodes and depth < 6:
                out = []
                for c in node.named_children:
                    if c.type == "comment":
                        continue
                    # go nests a statement_list inside every block; without unwrapping it the
                    # whole function body collapses into one CFG node and every branch
                    # condition is lost
                    if c.type in self.ad.block_nodes:
                        out.extend(stmts_of(c, depth + 1))
                    else:
                        out.append(c)
                return out
            return [node]

        def build(stmt_list) -> tuple:
            entry = None
            pending: list = []          # [(index, Cond or None)] waiting for the next statement
            for stmt in stmt_list:
                if len(blocks) >= MAX_STATEMENTS:
                    break
                idx = add(stmt)
                if entry is None:
                    entry = idx
                for src, cond in pending:
                    link(src, idx, cond)
                pending = []

                if stmt.type in self.ad.terminator_nodes or self._is_terminator(stmt):
                    continue            # nothing downstream of a return/throw/break/die

                cond_node = self._cond_node(stmt)
                cond_text = self.txt(cond_node).strip()[:160] if cond_node is not None else ""
                arms = self._arms(stmt)
                if not arms:
                    pending = [(idx, None)]
                    continue

                is_loop = stmt.type in self.ad.loop_nodes
                has_else = any(p is False for _, p in arms)
                exits: list = []
                for arm, polarity in arms:
                    sub_entry, sub_exits = build(stmts_of(arm))
                    if sub_entry is None:
                        continue
                    edge = None
                    if cond_node is not None and polarity is not None:
                        edge = Cond(cond_node, polarity, _line(stmt), cond_text)
                    link(idx, sub_entry, edge)
                    if is_loop:
                        for e, _c in sub_exits:
                            link(e, idx, None)      # back edge
                    exits += sub_exits
                if is_loop or not has_else:
                    # the branch can also be skipped: zero iterations, or no else arm
                    skip = Cond(cond_node, False, _line(stmt), cond_text) \
                        if cond_node is not None else None
                    exits.append((idx, skip))
                pending = exits
            return entry, pending

        build(stmts_of(body))
        return blocks, preds

    def paths_to(self, preds: list, target: int) -> list:
        """Up to MAX_PATHS condition sequences that lead from the entry to this block."""
        out: list = []
        work = [0]

        def walk(node: int, acc: list, seen: frozenset) -> None:
            if len(out) >= pathcond.MAX_PATHS or work[0] > MAX_PATH_WORK:
                return
            work[0] += 1
            sources = [(s, c) for s, c in preds[node] if s not in seen]
            if node == 0 or not sources or len(acc) >= pathcond.MAX_PATH_LEN:
                out.append(list(reversed(acc)))
                return
            for src, cond in sources:
                walk(src, acc + ([cond] if cond is not None else []), seen | {src})

        walk(target, [], frozenset({target}))
        if not out:
            out.append([])
        # identical guard sequences are the same question asked twice
        seen_keys = set()
        uniq = []
        for path in out:
            key = tuple((c.line, c.polarity, c.text) for c in path)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            uniq.append(path)
        return uniq

    # ------------------------------------------------------------ transfer

    def transfer(self, stmt, state: dict) -> dict:
        """Apply one statement's assignments to the incoming state."""
        out = dict(state)
        for node in _descendants(stmt, 6, stop=self._scan_stop):
            if node.type in self.ad.assign_nodes:
                target = node.child_by_field_name(self.ad.assign_target_field)
                value = node.child_by_field_name(self.ad.assign_value_field)
                self._assign(out, target, value)
            elif node.type in self.ad.declarator_nodes:
                target = node.child_by_field_name(self.ad.declarator_name_field)
                value = node.child_by_field_name(self.ad.declarator_value_field)
                # c# declarators carry no value field: the initialiser is simply the last child
                kids = [c for c in node.named_children if c.type != "comment"]
                if target is None and kids:
                    target = kids[0]
                if value is None and len(kids) > 1:
                    value = kids[-1]
                self._assign(out, target, value)
        return out

    def _assign(self, state: dict, target, value) -> None:
        if target is None or value is None:
            return
        taint = self.eval_taint(value, state)
        targets = self._target_symbols(target)
        for sym in targets:
            if taint is None:
                state.pop(sym, None)
            else:
                state[sym] = replace(
                    taint, syms=_add(taint.syms, sym),
                    steps=taint.steps + (self.step(target, sym + " now holds it"),))

    def _target_symbols(self, target) -> list:
        """Handle plain names, members, and simple destructuring."""
        t = target.type
        if t in self.ad.identifier_nodes or t in self.ad.member_nodes or t in self.ad.index_nodes:
            return [self.symbol(target)]
        out = []
        for c in _descendants(target, 3):
            if c.type in self.ad.identifier_nodes:
                out.append(self.txt(c))
        return out or [self.symbol(target)]

    # -------------------------------------------------------------- analysis

    def _decl_pair(self, node) -> tuple:
        """(target, value) for an assignment or a declarator, whatever the grammar calls it."""
        if node.type in self.ad.assign_nodes:
            return (node.child_by_field_name(self.ad.assign_target_field),
                    node.child_by_field_name(self.ad.assign_value_field))
        if node.type in self.ad.declarator_nodes:
            target = node.child_by_field_name(self.ad.declarator_name_field)
            value = node.child_by_field_name(self.ad.declarator_value_field)
            kids = [c for c in node.named_children if c.type != "comment"]
            if target is None and kids:
                target = kids[0]
            if value is None and len(kids) > 1:
                value = kids[-1]
            return target, value
        return None, None

    def collect_consts(self, root) -> None:
        """Names whose value is fixed in this file, so a sink taking one is provably safe.

        `tokenEndpoint := defaultMetadataTokenEndpoint` is a constant reaching an HTTP
        request. Without following the assignment the analyser only sees a variable with a
        sensitive-looking name and reports an SSRF that cannot exist. Iterated to a fixpoint
        so a chain of constant assignments resolves, and a symbol assigned anything
        non-constant anywhere in the file is never considered constant.
        """
        assigned: dict = {}
        for node in _descendants(root, 40):
            target, value = self._decl_pair(node)
            if target is None:
                continue
            for sym in self._target_symbols(target):
                assigned.setdefault(sym, []).append(value)
        for _ in range(3):
            changed = False
            for sym, values in assigned.items():
                if sym in self.consts or not values:
                    continue
                if all(v is not None and self.is_const(v) for v in values):
                    self.consts.add(sym)
                    changed = True
            if not changed:
                break

    def collect_literals(self, root) -> None:
        """Allow-list arrays, so the solver can reason about `ALLOWED.includes(x)`."""
        for node in _descendants(root, 30):
            target = value = None
            if node.type in self.ad.assign_nodes:
                target = node.child_by_field_name(self.ad.assign_target_field)
                value = node.child_by_field_name(self.ad.assign_value_field)
            elif node.type in self.ad.declarator_nodes:
                target = node.child_by_field_name(self.ad.declarator_name_field)
                value = node.child_by_field_name(self.ad.declarator_value_field)
                kids = [c for c in node.named_children if c.type != "comment"]
                if target is None and kids:
                    target = kids[0]
                if value is None and len(kids) > 1:
                    value = kids[-1]
            if target is None or value is None:
                continue
            # go wraps the right-hand side of `:=` in an expression_list, so the literal
            # was never reached
            for _ in range(3):
                if value.type not in ("expression_list", "parenthesized_expression"):
                    break
                kids = [k for k in value.named_children if k.type != "comment"]
                if len(kids) != 1:
                    break
                value = kids[0]
            if value.type not in ("array", "array_literal", "list", "tuple", "set",
                                  "array_creation_expression", "composite_literal",
                                  "array_expression"):
                continue
            items = self._literal_list(value)
            if items:
                self.literals[self.symbol(target)] = items

    def _literal_list(self, value) -> tuple:
        """The string elements of a list literal, or () when it is not one.

        Grammars wrap the elements differently: go writes `[]string{...}` as a
        composite_literal whose first child is the *type* and whose second is a
        literal_value holding the elements, and php puts an array_element_initializer
        around each one. Reading the children naively saw `[]string` first and gave up.
        """
        kids = [k for k in value.named_children if k.type != "comment"]
        # skip a leading type node and descend through a single wrapper
        if len(kids) == 2 and kids[0].type in ("slice_type", "array_type", "map_type",
                                               "generic_type", "qualified_type",
                                               "type_identifier"):
            kids = [k for k in kids[1].named_children if k.type != "comment"]
        elif len(kids) == 1 and kids[0].type in ("literal_value", "initializer_expression",
                                                 "array_initializer"):
            kids = [k for k in kids[0].named_children if k.type != "comment"]
        items = []
        for c in kids:
            raw = self.txt(c).strip()
            if len(raw) >= 2 and raw[0] in "\"'`" and raw[-1] == raw[0]:
                items.append(raw[1:-1])
                continue
            inner = [g for g in c.named_children if g.type != "comment"]
            if len(inner) == 1:
                raw = self.txt(inner[0]).strip()
                if len(raw) >= 2 and raw[0] in "\"'`" and raw[-1] == raw[0]:
                    items.append(raw[1:-1])
                    continue
            return ()
        return tuple(items)

    def analyse_function(self, fn_node, name: str, entry_taint: dict) -> None:
        body = fn_node.child_by_field_name(self.ad.function_body_field) if fn_node else None
        if body is None and fn_node is not None and fn_node.type in self.ad.block_nodes:
            body = fn_node
        if body is None:
            return

        blocks, preds = self.build_cfg(body)
        if not blocks:
            return

        seed = dict(entry_taint)
        n = len(blocks)
        ins: list = [dict() for _ in range(n)]
        outs: list = [dict() for _ in range(n)]
        ins[0] = dict(seed)

        for _ in range(MAX_ROUNDS):
            changed = False
            for i in range(n):
                merged = dict(ins[i])
                for j, _cond in preds[i]:
                    for k, v in outs[j].items():
                        if k not in merged:
                            merged[k] = v
                            changed = True
                if i == 0:
                    for k, v in seed.items():
                        merged.setdefault(k, v)
                ins[i] = merged
                new_out = self.transfer(blocks[i]["stmt"], merged)
                if new_out != outs[i]:
                    outs[i] = new_out
                    changed = True
            if not changed:
                break

        # report with each statement's incoming state
        for i, blk in enumerate(blocks):
            self.check_sinks(blk["stmt"], ins[i], name, preds, i)
            self.note_calls(blk["stmt"], ins[i], name)

        # what does this function hand back to its caller?
        final = outs[-1] if outs else {}
        for node in _descendants(body, 8, stop=self.ad.function_nodes):
            if node.type not in self.ad.return_nodes:
                continue
            for c in node.named_children:
                got = self.eval_taint(c, final)
                if got is None:
                    continue
                if got.formal:
                    fn, idx = got.formal
                    summary = self._summary(fn)
                    summary.param_returns = tuple(sorted(set(summary.param_returns) | {idx}))
                else:
                    self.returns_taint.add(name)
                    if name in self.functions:
                        self._summary(name).returns_source = got.source

    def _summary(self, name: str) -> Summary:
        if name not in self.summaries:
            node = self.functions.get(name)
            self.summaries[name] = Summary(
                path=self.path, name=name, line=_line(node) if node is not None else 0,
                params=tuple(self._param_names(node)) if node is not None else ())
        return self.summaries[name]

    def note_calls(self, stmt, state: dict, scope: str) -> None:
        """Record where tainted arguments go: into a local function, or out of this file."""
        for node in _descendants(stmt, 6, stop=self._scan_stop):
            if node.type not in self.ad.call_nodes:
                continue
            callee = self.callee_text(node)
            if not callee:
                continue
            base = callee.split(".")[-1]
            local = base in self.functions and base != scope
            for pos, arg in enumerate(self.arg_nodes(node)):
                taint = self.eval_taint(arg, state)
                if taint is None:
                    continue
                if local:
                    key = (base, pos)
                    if key not in self.param_taint and not taint.formal:
                        self.param_taint[key] = replace(
                            taint,
                            steps=taint.steps + (self.step(node, "passed to " + base + "()"),))
                    if taint.formal:
                        self._forward(taint, callee, pos, _line(node))
                    continue
                if (self.sanitizer_of(callee) is not None or self.is_propagator(callee)
                        or self._is_guard(callee)):
                    continue
                if taint.formal:
                    # this file hands its own parameter on; the repo pass composes the chain
                    self._forward(taint, callee, pos, _line(node))
                    continue
                site_key = (_line(node), callee, pos)
                if site_key in self._sites:
                    continue
                self._sites.add(site_key)
                self.callsites.append(CallSite(
                    path=self.path, line=_line(node), callee=callee, arg=pos,
                    source=taint.source, kind=taint.kind, confidence=taint.confidence,
                    steps=taint.steps + (self.step(node, "passed to " + callee + "()"),),
                    sanitized=taint.sanitized, killed=taint.killed, scope=scope))

    def _is_guard(self, callee: str) -> bool:
        """`isset($x)` / `preg_match(...)` test a value, they do not forward it."""
        return any(rx.search(callee) for _g, rx in self.guard_res)

    def _forward(self, taint, callee: str, pos: int, line: int) -> None:
        fn, idx = taint.formal
        summary = self._summary(fn)
        entries = summary.param_forwards.setdefault(idx, [])
        if (callee, pos, line) not in entries:
            entries.append((callee, pos, line))

    def _is_terminator(self, stmt) -> bool:
        """`die('no')` and `sys.exit(1)` end a path as surely as a return statement.

        Only a plain statement can be one. A branch is never a terminator even when its arm
        is: `if (!ok) die();` without braces holds the call as a direct child, and treating
        the `if` as the end of the path would strand every statement after it.
        """
        if not self.term_res or stmt.type in self.ad.if_nodes                 or stmt.type in self.ad.loop_nodes or stmt.type in self.ad.try_nodes:
            return False
        for node in _descendants(stmt, 3, stop=self._scan_stop):
            if node.type not in self.ad.call_nodes:
                continue
            callee = self.callee_text(node)
            if callee and any(rx.search(callee) for rx in self.term_res):
                return True
        return False

    def _identity(self, sink, callee: str) -> tuple:
        """(sink, "") to go on, or (None, reason) when the name is not that function.

        A sink pattern over a callee name is a claim about identity, and the name is often
        shared by something harmless. Three answers come out of this:

          the same sink, because nothing contradicted it (the common case, and the only
          one when `binding` could not resolve the name - an unresolved name gets the
          benefit of the doubt);

          a *reclassified* sink, when the name is a real execution primitive of the other
          kind: `exec = promisify(execFile)` runs a program with an argument vector, so
          the finding becomes argument injection and the engine's argv reasoning applies;

          no sink at all, when the name belongs to a different world entirely -
          `/^[0-9]+$/u.exec(literal)` is RegExp.prototype.exec, and
          `execute(compiler, ["version"])` where `execute` is a promisified execFile is
          not a database call.
        """
        if not sink.identity:
            return sink, ""
        got = binding.callee_family(callee, self.bindings)
        if got is None or not got.family or got.family == sink.identity:
            return sink, ""
        said = got.detail + (" (" + got.where + ")" if got.where else "")
        if sink.identity == binding.SHELL and got.family == binding.ARGV:
            return replace(
                sink, shell="argv", title="process run with an untrusted argument",
                why="`" + callee.strip() + "` here is " + said + ", not child_process.exec. "
                    "There is no shell in that path: the arguments go to the program as an "
                    "argv vector, so a value holding ; or $( ) arrives as one literal "
                    "argument. What is left to judge is which program runs and what it "
                    "does with the argument.", weight=max(4, sink.weight - 3)), ""
        if sink.identity == binding.ARGV and got.family == binding.SHELL:
            return replace(
                sink, shell="always",
                why="`" + callee.strip() + "` here is " + said + ", which does hand the "
                    "string to a shell."), ""
        return None, ("`" + callee.strip() + "` is " + said + ", which is not "
                      + _FAMILY_IS.get(sink.identity, sink.identity)
                      + ", so this pattern matched the name and not the thing")

    def check_sinks(self, stmt, state: dict, scope: str, preds: list, block: int) -> None:
        for node in _descendants(stmt, 8, stop=self._scan_stop):
            if node.type not in self.ad.call_nodes:
                continue
            callee = self.callee_text(node)
            if not callee:
                continue
            for sink, rx in self.sink_res:
                if not rx.search(callee):
                    continue
                real, why_not = self._identity(sink, callee)
                if real is None:
                    entry = (_line(node), sink.id, why_not)
                    if entry not in self.misidentified:
                        self.misidentified.append(entry)
                    continue
                sink = real
                args = self.arg_nodes(node)
                picks = sink.danger_positions(len(args))

                if not sink.needs_taint:
                    self._report(sink, node, None, "config", preds, block, scope)
                    break

                hit = False
                for i in picks:
                    taint = self.eval_taint(args[i], state)
                    if taint is None:
                        continue
                    marked = replace(taint, syms=_add(taint.syms, self.symbol(args[i])))
                    role = sink.role_of(i) or ("arg " + str(i))
                    self._report(sink, node, marked, role, preds, block, scope,
                                 arg_index=i, args=args)
                    hit = True
                    break
                if not hit and sink.receiver_counts:
                    fn = node.child_by_field_name(self.ad.call_fn_field)
                    if fn is not None and fn.type in self.ad.member_nodes:
                        obj = fn.child_by_field_name(self.ad.member_obj_field)
                        taint = self.eval_taint(obj, state)
                        if taint is not None:
                            self._report(sink, node, taint, "receiver", preds, block, scope)
                            hit = True
                if not hit:
                    all_const = bool(picks) and all(self.is_const(args[i]) for i in picks)
                    if all_const:
                        self.const_sinks.add((_line(node), sink.id, sink.cat))
                    # Keep looking. `requests.request("GET", url)` matches a general sink
                    # whose danger position is argument 0 - the method, which is constant -
                    # and stopping there hid the specific sink that knows the URL is
                    # argument 1.
                    continue
                break

    # ------------------------------------------------------------ reporting

    def _path_verdict(self, sink, node, taint, preds, block, scope):
        key = (block, sink.id, _line(node), scope)
        if key in self._pc_cache:
            return self._pc_cache[key]
        verdict = pathcond.Verdict("reachable", "no-solver")
        if taint is not None and self.checker.live:
            paths = self.paths_to(preds, block)
            syms = tuple(dict.fromkeys(taint.syms))
            verdict = self.checker.check(paths, syms, sink.cat,
                                         removed=tuple(dict.fromkeys(taint.removed)))
        self._pc_cache[key] = verdict
        return verdict

    def _known_values(self, node) -> tuple:
        """The literal values an expression can take, when that set is knowable.

        Covers a loop variable ranging over a literal list, and a plain reference to one.
        `providers := []string{"xdg-open", "x-www-browser"}` followed by
        `for _, provider := range providers` means `provider` has three possible values,
        which is enough to answer whether any of them is a shell.
        """
        if node is None or not self.literals:
            return ()
        sym = self.symbol(node)
        if sym in self.literals:
            return self.literals[sym]
        if sym in self.loop_values:
            return self.loop_values[sym]
        return ()

    def collect_loop_values(self, root) -> None:
        """Loop variables bound to a known literal list."""
        for node in _descendants(root, 40):
            if node.type not in ("range_clause", "for_in_statement", "for_statement",
                                 "for_each_statement", "enhanced_for_statement"):
                continue
            kids = [c for c in node.named_children if c.type != "comment"]
            if len(kids) < 2:
                continue
            source = self._known_values(kids[-1])
            if not source:
                continue
            for target in kids[:-1]:
                for inner in _descendants(target, 3):
                    if inner.type in self.ad.identifier_nodes:
                        name = self.txt(inner)
                        if name and name != "_":
                            self.loop_values.setdefault(name, source)

    def _replacement_effect(self, node, callee: str):
        """(removed sequences, description) for a replace-style call, or None.

        Two outcomes, and they are not the same defence:
          removed  - the replacement does not contain the needle, so that character is gone
          escaped  - the replacement contains the needle (`"&"` -> `"^&"`), so the character
                     is still there and only neutral in one particular shell
        Either way it covers exactly what it covers, which is the point of reporting it.
        """
        for pattern, needle_at, repl_at in self.replacer_res:
            if not pattern.search(callee):
                continue
            args = self.arg_nodes(node)
            if needle_at >= len(args):
                return None
            needle = self._literal_of(args[needle_at])
            if not needle:
                return None
            repl = self._literal_of(args[repl_at]) if repl_at < len(args) else None
            if repl is None:
                return None
            if needle in repl:
                return (), ("escaped by " + callee + ": " + needle + " becomes " + repl
                            + ", which neutralises it only where that escape applies")
            return (needle,), ("filtered by " + callee + ": " + needle + " removed, "
                               "nothing else")
        return None

    def _literal_of(self, node):
        """The string value of a literal argument, or None when it is not one."""
        if node is None:
            return None
        raw = self.txt(node).strip()
        # a regex literal /&/g in javascript
        m = re.fullmatch(r"/(.+)/[gimsuy]*", raw)
        if m and node.type in getattr(self.ad, "regex_nodes", ()):
            body = m.group(1)
            return body if re.fullmatch(r"[^\\[\](){}|*+?^$.]+", body) else None
        if len(raw) >= 2 and raw[0] in "\"'`" and raw[-1] == raw[0]:
            body = raw[1:-1]
            try:
                return body.encode("utf-8", "replace").decode("unicode_escape", "replace")
            except Exception:
                return body
        return None

    def _kwarg_text(self, call, name: str):
        """The source text of a keyword/named argument, or None when it is absent."""
        if not name:
            return None
        args = call.child_by_field_name(self.ad.call_args_field)
        if args is None:
            return None
        for child in args.named_children:
            if child.type in ("keyword_argument", "named_argument", "argument",
                              "pair", "assignment_expression", "shorthand_property"):
                kids = [c for c in child.named_children if c.type != "comment"]
                if len(kids) >= 2 and re.sub(r"\s+", "", self.txt(kids[0])) == name:
                    return self.txt(kids[-1])
            # node passes options as an object literal: { shell: true }
            if child.type in ("object", "dictionary"):
                for pair in _descendants(child, 3):
                    kids = [c for c in pair.named_children if c.type != "comment"]
                    if pair.type in ("pair",) and len(kids) >= 2 \
                            and re.sub(r"\s+", "", self.txt(kids[0])).strip("'\"") == name:
                        return self.txt(kids[-1])
        return None

    def _shell_semantics(self, sink, node, arg_index: int, args: list) -> tuple:
        """(category, title, weight delta, note) for an argv-style execution sink.

        `exec.Command("sh", "-c", userInput)` and `exec.Command("open", userInput)` are not
        the same bug. In the first the value is a command line; in the second it is one
        argv entry to a fixed program, which is argument injection at worst and depends
        entirely on what that program does with it.
        """
        mode = sink.shell
        if mode == "conditional":
            # `subprocess.run(x, shell=True)` is a shell command; `subprocess.run([prog, x])`
            # is an argument vector. Same function, two different bugs, and the flag is the
            # only thing that tells them apart.
            flag = self._kwarg_text(node, sink.shell_kwarg)
            if flag is None:
                mode = "argv"
            elif flag.strip().lower() in ("true", "1", "yes"):
                mode = "always"
            else:
                mode = "argv"
        if mode == "always":
            return sink.cat, sink.title, 0, "the value is handed to a shell"
        if mode != "argv" or arg_index < 0:
            return sink.cat, sink.title, 0, ""
        prog_at = sink.program_arg if sink.program_arg >= 0 else 0
        # an argv-style call whose first argument is a list: the program is its first element
        if prog_at < len(args):
            inner = [c for c in args[prog_at].named_children if c.type != "comment"]
            if args[prog_at].type in ("list", "array", "array_literal", "tuple") and inner:
                program = self.txt(inner[0])
                if self.is_shell(program):
                    return sink.cat, sink.title, 0, \
                        "argument of " + program.strip() + ", which interprets it"
                if self.is_const(inner[0]):
                    return "argv", "untrusted value passed as an argument to " \
                        + program.strip(), -3, \
                        ("the program is fixed and is not a shell, so this is argument "
                         "injection rather than command injection")
        if arg_index == prog_at:
            return sink.cat, "program name chosen by untrusted input", 0, \
                "the value selects which binary runs"
        program = self.txt(args[prog_at]) if prog_at < len(args) else ""
        if self.is_shell(program):
            return sink.cat, sink.title, 0, \
                "argument of " + program.strip() + ", which interprets it as a command line"
        if self.is_const(args[prog_at]) if prog_at < len(args) else False:
            return "argv", "untrusted value passed as an argument to " + program.strip(), -3, \
                ("the program is fixed and is not a shell, so this is argument injection "
                 "rather than command injection: it matters only if " + program.strip()
                 + " interprets the value")
        # `for _, provider := range providers` where providers is a literal slice: the
        # program is not a constant, but the set it can come from is known, so whether any
        # member of that set is a shell is a question with an answer.
        choices = self._known_values(args[prog_at]) if prog_at < len(args) else ()
        if choices:
            shells = [c for c in choices if self.is_shell(c)]
            if not shells:
                return "argv", ("untrusted value passed as an argument to one of "
                                + ", ".join(choices[:4])), -3, \
                    ("the program comes from a fixed list (" + ", ".join(choices[:4])
                     + ") and none of them is a shell, so this is argument injection")
            return sink.cat, sink.title, 0, \
                "the program may be " + shells[0] + ", which interprets its arguments"
        return sink.cat, sink.title, -1, "the program being run could not be determined"

    def _report(self, sink, node, taint, where: str, preds: list, block: int,
                scope: str, arg_index: int = -1, args: list | None = None) -> None:
        ln = _line(node)
        drop_key = (ln, sink.id, scope)
        if drop_key in self._dropped:
            return
        if taint is not None and ("*" in taint.killed or sink.cat in taint.killed):
            self._suppress(ln, sink.id, "neutralised by "
                           + (taint.sanitized[-1] if taint.sanitized else "a sanitizer"))
            return
        # A sink can declare which value kinds it is a sink *for*. A logging call only
        # matters for a credential; a shell only matters for free-form text. Checked first,
        # so a disclosure sink is not turned away by the injection rules below.
        if sink.value_kinds:
            if taint is None or taint.value not in sink.value_kinds:
                return
        elif taint is not None and taint.value == "secret":
            self._suppress(ln, sink.id,
                           "the value is a credential, so the question is disclosure - who "
                           "can read it - and not injection")
            return
        # An integer, an enum or a boolean is attacker-chosen and still cannot carry a
        # string payload. `PR_NUMBER=${{ github.event.pull_request.number }}` reaching a
        # shell is not command injection, and saying it is drowns the real findings.
        elif taint is not None and taint.value not in PAYLOAD_VALUES \
                and sink.cat in STRING_PAYLOAD_CATS:
            self._suppress(ln, sink.id, "the value is " + _value_phrase(taint.value)
                           + ", which cannot carry a payload for this class")
            return


        verdict = self._path_verdict(sink, node, taint, preds, block, scope)
        if verdict.drop:
            reason = ("the guards on this path contradict each other"
                      if verdict.status == "unreachable"
                      else "the checks on this path exclude every payload")
            self._suppress(ln, sink.id, reason)
            self._dropped.add(drop_key)
            return

        # Execution semantics are decided before anything is recorded, so a summary that
        # another file joins onto carries the right class: `exec.Command("open", x)` has to
        # stay argument injection even when the caller is in a different module.
        cat, title, wdelta, semantics = self._shell_semantics(
            sink, node, arg_index, args or [])

        # A formal parameter reaching a sink is a summary, not a finding: it only becomes a
        # finding once a caller is shown to pass untrusted data into that parameter.
        if taint is not None and taint.formal:
            fn, idx = taint.formal
            summary = self._summary(fn)
            refs = summary.param_sinks.setdefault(idx, [])
            if not any(r.line == ln and r.sink_id == sink.id for r in refs):
                refs.append(SinkRef(
                    sink_id=sink.id, cat=cat, title=title, why=sink.why,
                    weight=max(2, sink.weight + wdelta), line=ln, path=self.path,
                    steps=_strip_formal(taint.steps) + (
                        self.step(node, "reaches " + title + " here (" + where + ")"
                                  + ("; " + semantics if semantics else "")),),
                    guards=verdict.guards, sanitized=taint.sanitized, killed=taint.killed))
            return

        if any(f.line == ln and f.rule == "taint." + sink.id for f in self.findings):
            return

        trace = _compact(list(taint.steps) if taint else [])
        trace.append(self.step(node, "reaches " + title + " here (" + where + ")"))
        notes: list = []
        if semantics:
            notes.append(semantics)

        # ---- the evidence, stated separately so it can be argued with -----------
        ev = Evidence(
            source=("unknown" if taint is None else taint.trust),
            value=("opaque" if taint is None else taint.value),
            sink=("argv" if cat == "argv" else
                  "unknown" if "could not be determined" in semantics else "direct"),
            role=where,
            flow=("direct" if taint is None or taint.assumed == 0 else "assumed"),
            hops=(0 if taint is None else taint.assumed),
            guard=_guard_state(verdict, taint),
            payload_required=not bool(sink.value_kinds),
        )
        if taint is None:
            ev.source = "known"        # a dangerous configuration needs no input at all
            ev.notes = ("dangerous regardless of input",)
        if taint is not None and taint.assumed:
            notes.append("passes through " + str(taint.assumed)
                         + " call(s) whose body was not analysed, so the connection is "
                           "assumed rather than shown")
        if taint is not None and taint.trust == TRUST_INFERRED:
            notes.append("the source was matched by parameter name, not by a declared type "
                         "or a framework registration")
        for phrase in (dict.fromkeys(taint.partial) if taint is not None else ()):
            notes.append(phrase)
        if ev.guard == "authorization":
            notes.append("reachable only if the authorization check on this path is "
                         "bypassed or already satisfied - it gates who gets here, it does "
                         "not constrain the value")
        elif ev.guard == "validator-opaque":
            notes.append("a validator on this path is not visible to the analyser, so "
                         "whether the value is already checked is an open question")
        elif verdict.guards and not verdict.witness:
            notes.append("reachable only if these checks are satisfied or bypassed")
        ev.notes = tuple(notes) + ev.notes

        conf = ev.confidence()
        weight = max(2, sink.weight + wdelta)
        source_label = taint.source if taint else "no input needed"
        # A build script passing $CFLAGS to subprocess is dataflow-true and worthless: whoever
        # sets the environment already owns the shell. Only remotely reachable sources carry
        # full weight, otherwise configure.py outranks the actual request handlers.
        force_lead = False
        if taint is not None and taint.kind in LOCAL_KINDS and not sink.value_kinds:
            conf = "low"
            weight = max(2, weight - 4)
            source_label += " (local input, not remotely reachable)"
            # "Not remotely reachable" was as far as this went, and it was not far enough:
            # a verification script reading `process.argv[2]` and loading a module from
            # under it still scored in the medium band. In a tool the user starts, the
            # command line and the environment *are* the operator - the person supplying
            # the value is the person running the program, and there is no one else to be
            # the attacker. It stays on the page as a lead, because the premise is the
            # deployment type, and a wrapper, a service that re-executes this, or a setuid
            # bit would change it.
            # Only argv and the environment. A *file* the tool reads is the one thing an
            # attacker in a CLI does control - the binary, the archive, the repository you
            # hand it - and `deployment.gate` keeps command and path findings at 0.6 for
            # exactly that reason. Clamping a file-borne flow here would contradict it.
            if taint.kind in ("cli", "env") and self.dep_kind in ("cli", "library"):
                weight = 2
                force_lead = True
                ev.no_attacker = ("the input is the operator's own, in "
                                  + ("a command-line tool" if self.dep_kind == "cli"
                                     else "a library"))
                ev.notes = ev.notes + (
                    "this is " + ("a command-line tool" if self.dep_kind == "cli"
                                  else "a library") + ", so "
                    + ("the command line and the environment belong to the operator"
                       if self.dep_kind == "cli" else
                       "the caller supplying this is the operator")
                    + ": whoever provides this value already runs the code. It becomes a "
                      "finding if something else feeds that input - a wrapper, a service "
                      "that re-executes this, a setuid bit",)
        if verdict.witness and ev.verdict() == "finding":
            conf = "high"       # the solver produced a value that passes every check
        # Weight is severity if real; confidence is how sure we are. They are different
        # questions and the score combines them once, in score.CONF_FACTOR. Discounting the
        # weight here as well buried an eval() behind an open redirect - a reviewer would
        # rather look at an RCE they are unsure of than a redirect they are certain of.
        lead = force_lead or ev.verdict() == "lead"
        self.findings.append(Finding(
            rule="taint." + sink.id,
            cat=cat,
            title=("LEAD: " + title) if lead else title,
            why=sink.why,
            line=ln,
            snippet=self.code_at(ln),
            weight=weight,
            confidence=conf,
            source_label=source_label,
            sanitizers=tuple(taint.sanitized) if taint else (),
            trace=trace,
            guards=verdict.guards,
            witness=verdict.witness,
            proof=verdict.proof,
            evidence=ev,
        ))

    def _suppress(self, line: int, sink_id: str, reason: str) -> None:
        entry = (line, sink_id, reason)
        if entry not in self.suppressed:
            self.suppressed.append(entry)

    # ------------------------------------------------------------------ run

    def _param_names(self, fn_node) -> list:
        return [name for name, _type in self._params(fn_node)]

    def _params(self, fn_node) -> list:
        """[(name, declared type)] for one function, type empty when not annotated.

        The type is the whole point. Seeding by name made every `ctx context.Context` in a
        Go repository a request source, and that single mistake was behind most of the
        noise: cancellation scopes are not user input.
        """
        params = fn_node.child_by_field_name(self.ad.function_params_field) \
            if fn_node is not None else None
        plist = []
        if params is None:
            return plist
        for c in params.named_children:
            if c.type == "comment":
                continue
            if c.type in self.ad.identifier_nodes:
                plist.append((self.txt(c), ""))
                continue
            # a typed or defaulted parameter wraps the name: `name string` in go,
            # `String name` in java, `name: string = "x"` in typescript. Taking the whole
            # node text would make the parameter name "name string", which matches nothing.
            name = ""
            named = c.child_by_field_name("name")
            if named is not None:
                name = self.txt(named)
            else:
                for g in _descendants(c, 3):
                    if g is not c and g.type in self.ad.identifier_nodes:
                        name = self.txt(g)
                        break
            plist.append((name, self._type_text(c, name)))
        return plist

    def _type_text(self, param_node, name: str) -> str:
        """The declared type of a parameter, normalised to a comparable string."""
        node = param_node.child_by_field_name("type")
        if node is None:
            for child in param_node.named_children:
                if child.type in ("type_annotation", "type_identifier", "qualified_type",
                                  "pointer_type", "generic_type", "named_type",
                                  "predefined_type", "union_type", "nullable_type",
                                  "primitive_type", "array_type"):
                    node = child
                    break
        if node is None:
            return ""
        text = self.txt(node)
        # `: express.Request` in typescript, `*http.Request` in go, `?Foo` in php
        text = text.lstrip(":").strip()
        if name and text.startswith(name):
            text = text[len(name):].strip()
        return re.sub(r"\s+", "", text)

    def run(self, root) -> dict:
        self.collect_consts(root)
        self.collect_literals(root)
        self.collect_loop_values(root)
        # Catalogue every function so calls between them can be followed. Anonymous ones
        # matter most in JS: an express route handler IS an arrow function, and skipping it
        # would mean never analysing the code that actually touches the request.
        for node in _descendants(root, 30):
            if node.type not in self.ad.function_nodes:
                continue
            name = None
            nm = node.child_by_field_name(self.ad.function_name_field)
            if nm is not None:
                name = self.txt(nm)
            else:
                parent = node.parent
                if parent is not None and parent.type in self.ad.declarator_nodes:
                    pn = parent.child_by_field_name(self.ad.declarator_name_field)
                    if pn is not None:
                        name = self.txt(pn)
                elif parent is not None and parent.type in self.ad.assign_nodes:
                    tn = parent.child_by_field_name(self.ad.assign_target_field)
                    if tn is not None:
                        name = self.symbol(tn).split(".")[-1]
            if name is None:
                name = "<anon@" + str(_line(node)) + ">"
            self.functions.setdefault(name, node)

        self.mark_handlers(root)

        # module scope first: top-level code and handler registrations
        self.analyse_function(root, "<module>", {})

        pending = list(self.functions.items())
        for _rnd in range(MAX_INTERPROC_ROUNDS):
            before = self._progress()
            known = set(self.param_taint)
            for name, node in pending:
                entry = self.seed_params(node, name)
                self.analyse_function(node, name, entry)
            if self._progress() == before:
                break
            # only the functions that just learned a tainted parameter can say anything new
            learned = {key[0] for key in set(self.param_taint) - known}
            pending = [(n, node) for n, node in self.functions.items() if n in learned]
            if not pending:
                break

        return {
            "findings": self.findings,
            "const_sinks": sorted(self.const_sinks),
            "suppressed": self.suppressed,
            "misidentified": self.misidentified,
            "functions": len(self.functions),
            "summaries": self.summaries,
            "callsites": self.callsites,
            "path": self.checker.stats(),
        }

    def _progress(self) -> tuple:
        return (len(self.findings), len(self.param_taint), len(self.returns_taint),
                len(self.callsites),
                sum(len(v) for s in self.summaries.values() for v in s.param_sinks.values()),
                sum(len(v) for s in self.summaries.values() for v in s.param_forwards.values()))

    def mark_handlers(self, root) -> None:
        """Find the functions the framework will call with a request.

        `(req, res) => ...` is only a request handler because something registered it. The
        registration is the evidence; the parameter name on its own is a convention that
        any function can accidentally follow.
        """
        if not self.registrar_res:
            return
        by_node = {id(node): name for name, node in self.functions.items()}
        for node in _descendants(root, 30):
            # a function passed to app.get("/x", handler) or http.HandleFunc(...)
            if node.type in self.ad.call_nodes:
                callee = self.callee_text(node)
                if not callee or not any(rx.search(callee) for rx in self.registrar_res):
                    continue
                for arg in self.arg_nodes(node):
                    for inner in _descendants(arg, 4):
                        if inner.type in self.ad.function_nodes:
                            name = by_node.get(id(inner))
                            if name:
                                self.handler_fns.add(name)
                        elif inner.type in self.ad.identifier_nodes:
                            text = self.txt(inner)
                            if text in self.functions:
                                self.handler_fns.add(text)
                continue
            # a decorated definition: @app.route("/x") / @router.post(...)
            if node.type in ("decorated_definition", "decorated_method", "attribute_list"):
                text = re.sub(r"\s+", "", self.txt(node)[:400])
                if not any(rx.search(text) for rx in self.registrar_res):
                    continue
                for inner in _descendants(node, 3):
                    if inner.type in self.ad.function_nodes:
                        name = by_node.get(id(inner))
                        if name:
                            self.handler_fns.add(name)

    def _param_source(self, pname: str, ptype: str, registered: bool):
        """Match a parameter against the modelled framework surface, type first.

        Three tiers, and the difference between them is the whole point:

          declared type matches   - evidence. `r *http.Request` is an HTTP request.
          name matches, and the enclosing function is registered as a route handler -
            evidence. `(req, res)` passed to `app.get(...)` is the express convention, and
            the registration is what makes it a fact rather than a hunch.
          name matches, nothing else - a guess. Reported as a lead, never as a finding.

        A parameter that *has* a declared type which does not match is not a source at all,
        whatever it is called. That one rule is what stops `ctx context.Context` from
        turning every Go function into a request handler.
        """
        for spec, type_rx, _name_rx in self.param_src:
            if type_rx is not None and ptype and type_rx.search(ptype):
                return spec
        for spec, type_rx, name_rx in self.param_src:
            if name_rx is None or not name_rx.search(pname):
                continue
            if ptype:
                continue        # a type was declared and it was not this
            if self.framework_present.get(spec.id) is False:
                continue        # the convention of a framework this file does not use
            return spec if registered else replace(spec, trust=TRUST_INFERRED)
        return None

    def seed_params(self, fn_node, name: str) -> dict:
        """Seed parameters: real taint when a caller is known, otherwise a summary probe.

        The probe is what produces function summaries. It is tracked separately from real
        taint (`kind == "formal"`) so a sink it reaches is recorded as "argument i lands
        here" rather than announced as a finding nobody can act on yet.
        """
        seed: dict = {}
        params = self._params(fn_node)
        if params and name in self.functions:
            self._summary(name).params = tuple(n for n, _t in params)
        anonymous = name.startswith("<anon@") or name == "<module>"
        for pos, (pname, ptype) in enumerate(params):
            if not pname:
                continue
            # Never a source, whatever it is called: a cancellation scope, a logger, a test
            # harness, `self`. Checked before anything else so no heuristic can override it.
            if any(rx.search(ptype) or rx.fullmatch(pname) for rx in self.never_param_res):
                continue
            matched = self._param_source(pname, ptype, name in self.handler_fns)
            if matched is not None:
                seed[pname] = Taint(
                    source=matched.label + " (" + pname + ")", kind=matched.kind,
                    value=matched.value, trust=matched.trust, syms=(pname,),
                    confidence="high" if matched.trust == "known" else "medium",
                    steps=(TraceStep(line=_line(fn_node), code=self.code_at(_line(fn_node)),
                                     note=matched.label + " arrives as " + pname
                                     + (" : " + ptype if ptype else "")),))
                continue
            key = (name, pos)
            if key in self.param_taint:
                t = self.param_taint[key]
                seed[pname] = replace(t, confidence="medium", syms=_add(t.syms, pname),
                                      steps=t.steps + (TraceStep(
                                          line=_line(fn_node), code=self.code_at(_line(fn_node)),
                                          note="arrives as parameter " + pname),))
                continue
            if not anonymous:
                seed[pname] = Taint(
                    source="parameter " + pname, kind="formal", formal=(name, pos),
                    syms=(pname,),
                    steps=(TraceStep(line=_line(fn_node), code=self.code_at(_line(fn_node)),
                                     note="argument " + str(pos) + " arrives as " + pname),))
        return seed


_TRANSPARENT = {
    "parenthesized_expression", "await", "await_expression", "unary_expression",
    "conditional_expression", "ternary_expression", "array", "array_literal", "list",
    "tuple", "object", "dictionary", "pair", "spread_element", "argument_list",
    "arguments", "expression_statement", "as_expression", "non_null_expression",
    "type_assertion", "assignment_expression",
    # go wraps both sides of := in an expression_list; c# wraps each argument
    "expression_list", "argument", "bracketed_argument_list", "variable_declaration",
    "local_declaration_statement", "keyed_element", "literal_value", "composite_literal",
    "element", "array_creation_expression", "initializer_expression", "hash", "pair_pattern",
    "interpolation", "template_substitution", "string_interpolation", "encapsed_string",
}


def _add(syms: tuple, sym: str) -> tuple:
    """Remember which names have held this value, newest last and bounded."""
    if not sym or sym in syms:
        return syms
    return (syms + (sym,))[-8:]


def _strip_formal(steps: tuple) -> tuple:
    """Drop the "argument N arrives as x" hop: the cross-file pass writes a better one that
    names the calling file, and keeping both prints the same hop twice."""
    return tuple(s for s in steps if "arrives as" not in s.note)


def _field_children(stmt, field: str) -> list:
    """Every child bound to `field`, for grammars that repeat it (python elif/else)."""
    out = []
    try:
        count = stmt.named_child_count
    except Exception:
        return out
    for i in range(count):
        try:
            if stmt.field_name_for_named_child(i) == field:
                out.append(stmt.named_child(i))
        except Exception:
            break
    if not out:
        node = stmt.child_by_field_name(field)
        if node is not None:
            out.append(node)
    return out


def _unwrap_else(node, ad):
    """An else_clause wraps the block that actually runs; an elif clause does not."""
    if node is None:
        return None
    if node.type in ad.else_nodes:
        kids = [c for c in node.named_children if c.type != "comment"]
        for c in kids:
            if c.type in ad.block_nodes:
                return c
        return kids[-1] if kids else None
    return node


def _descendants(node, max_depth: int, stop: tuple = ()):  # noqa: D401
    """Yield node and its descendants, not entering `stop` node types below the root."""
    out = []
    stack = [(node, 0)]
    while stack:
        cur, d = stack.pop()
        out.append(cur)
        if d >= max_depth:
            continue
        for c in reversed(cur.named_children):
            if c is not node and c.type in stop:
                continue
            stack.append((c, d + 1))
    return out


MAX_TRACE = 9


def _compact(steps: list) -> list:
    """One hop per line, and elide the middle of a long chain.

    A 20-step trace through ten chained .replace() calls is true but unreadable, and it is
    the ends that matter: where the data came in, and where it lands.
    """
    out: list = []
    for s in steps:
        if out and out[-1].line == s.line and out[-1].path == s.path:
            out[-1] = TraceStep(line=s.line, code=s.code, note=out[-1].note, path=s.path)
            continue
        out.append(s)
    if len(out) > MAX_TRACE:
        hidden = len(out) - (MAX_TRACE - 1)
        out = out[:4] + [TraceStep(line=out[4].line, code="",
                                   note="... " + str(hidden) + " more hops through the same value")] \
            + out[-(MAX_TRACE - 5):]
    return out


def analyse(spec, root, data: bytes, text: str, path: str = "",
            tainted_returns=(), bindings=None, dep_kind: str = "") -> dict:
    lines = text.split("\n")
    return Analyzer(spec, data, lines, path, tainted_returns,
                    bindings=bindings, dep_kind=dep_kind).run(root)
