"""Shapes shared by the AST/dataflow layer: language adapters, rule specs, findings."""
from __future__ import annotations

from dataclasses import dataclass, field


# --------------------------------------------------------------------- adapter

@dataclass
class Adapter:
    """How one grammar spells the handful of constructs the engine needs.

    Keeping this as data rather than code is what makes "analysis per language" tractable:
    the dataflow engine never mentions a node type, it asks the adapter.
    """
    lang: str

    # calls
    call_nodes: tuple = ()              # node types that are a call/invocation
    call_fn_field: str = "function"     # field holding the callee
    call_args_field: str = "arguments"  # field holding the argument list
    arg_wrapper_nodes: tuple = ()       # php wraps each argument in an `argument` node

    # names and member access
    identifier_nodes: tuple = ("identifier",)
    member_nodes: tuple = ()            # obj.prop
    member_obj_field: str = "object"
    member_prop_field: str = "property"
    index_nodes: tuple = ()             # obj[key]

    # assignment / declaration
    assign_nodes: tuple = ()            # a = b
    assign_target_field: str = "left"
    assign_value_field: str = "right"
    declarator_nodes: tuple = ()        # var a = b
    declarator_name_field: str = "name"
    declarator_value_field: str = "value"

    # functions
    function_nodes: tuple = ()
    function_name_field: str = "name"
    function_params_field: str = "parameters"
    function_body_field: str = "body"
    param_nodes: tuple = ("identifier",)

    # literals and string building
    string_nodes: tuple = ()
    number_nodes: tuple = ()
    interp_string_nodes: tuple = ()     # template literals / f-strings
    interp_inner_nodes: tuple = ()      # the ${...} part
    concat_nodes: tuple = ()            # binary + etc
    concat_operators: tuple = ("+",)

    # control flow, for the CFG
    if_nodes: tuple = ()
    loop_nodes: tuple = ()
    try_nodes: tuple = ()
    block_nodes: tuple = ()
    return_nodes: tuple = ()

    # --- path sensitivity -------------------------------------------------
    # Branch conditions are what the solver reasons about, so the CFG has to know which
    # child of an `if` is the test, which is the taken arm, and which statements end a
    # path (an early `return` is the most common guard in real code).
    cond_field: str = "condition"
    consequence_field: str = "consequence"
    alternative_field: str = "alternative"
    else_nodes: tuple = ()              # else_clause / elif_clause / else_if_clause wrappers
    terminator_nodes: tuple = ()        # return / throw / raise / break / continue
    terminator_calls: tuple = ()        # regexes: die(), exit(), abort(), os.Exit()
    binary_nodes: tuple = ()            # a == b, a && b
    unary_nodes: tuple = ()             # !a, not a
    operator_field: str = "operator"
    and_operators: tuple = ("&&", "and")
    or_operators: tuple = ("||", "or")
    not_operators: tuple = ("!", "not")
    true_literals: tuple = ("true", "True")
    false_literals: tuple = ("false", "False")
    null_literals: tuple = ("null", "undefined", "none", "nil", "None")
    length_props: tuple = ("length", "size")       # x.length
    length_fns: tuple = ()                         # len(x) / strlen(x) / count(x)
    regex_nodes: tuple = ()                        # /abc/ literal
    in_operators: tuple = ()                       # python `in`, php `in`
    regex_operators: tuple = ()                    # ruby `=~`
    # Conversions a guard can be read *through*: `if not str(page).isdigit()` constrains
    # `page`. Only strict conversions belong here - JS `parseInt("5;id")` returns 5, so
    # treating a check on it as a check on the original would silence a real finding.
    transparent_calls: tuple = ()

    # Constness that survives a call. `exec(compile(open(os.path.join(
    # os.path.dirname(__file__), "launch_impl.py"), "rb").read(), ...))` loads this
    # package's own fixed sibling, and was reported as code execution because the path is
    # built by two function calls. A path builder is pure: if every argument is constant
    # the result is constant. `const_idents` are the leaves - `__file__` is not input.
    #
    # Only exact, pure builders belong here. The rule is "all arguments constant", so
    # `path.join(uploadDir, req.body.name)` is still not constant and cannot become so.
    const_calls: tuple = ()             # regexes over the callee text
    const_idents: tuple = ()            # regexes over an identifier or member expression

    # per-language escape hatches
    extra_const_nodes: tuple = ()
    depth: str = "taint"                # "taint" = full dataflow, "sink" = argument check only


# ------------------------------------------------------------------ rule specs

# What a value can be used for, which is not the same question as where it came from.
# An integer PR number is attacker-chosen and still cannot carry `; whoami`, so it must not
# satisfy a string-injection sink. Only these two can.
PAYLOAD_VALUES = ("text", "opaque")
VALUE_KINDS = ("text", "opaque", "id", "enum", "bool", "secret", "trigger")

# How much the source itself is worth. A framework object matched by its declared type is
# evidence; a parameter that merely happens to be called `req` is a guess, and a finding
# resting on one is a lead rather than a result.
TRUST_KNOWN = "known"
TRUST_INFERRED = "inferred"


@dataclass
class Source:
    """Where untrusted data enters. Matched against the dotted text of an expression."""
    id: str
    pattern: str                 # regex over the expression text, e.g. r"req\\.(query|body)"
    label: str
    kind: str = "request"        # request | cli | env | file | network | param
    value: str = "text"          # see VALUE_KINDS - what the value can carry
    trust: str = TRUST_KNOWN     # known = modelled framework surface, inferred = a guess


@dataclass
class ParamSource:
    """An untrusted value that arrives as a function parameter, matched by its *type*.

    Matching `ctx` by name made `context.Context` a request source in every Go function in
    the repository, which is where most of the noise came from. A declared type is a fact;
    a parameter name is a convention.

    `requires` is what keeps the convention honest. A parameter named `request` is a Flask
    request only in a file that has Flask in it; in `bridge/pwndbg/core_context.py` it was
    the parsed JSON of a debugger request file, and the engine reported
    `exec(compile(...))` as *"flask request reaches eval"* in a repository with no web
    framework anywhere. The pattern is checked against the file for a name match only -
    a declared type needs no corroboration, because it names the framework itself.
    """
    id: str
    label: str
    type_pattern: str = ""       # regex over the declared type, e.g. r"^\\*?http\\.Request$"
    name_pattern: str = ""       # fallback for languages without annotations
    requires: str = ""           # must appear in the file for a *name* match to count
    kind: str = "request"
    value: str = "text"
    trust: str = TRUST_KNOWN


@dataclass
class Barrier:
    """A call whose result carries none of its arguments' taint.

    Not a sanitizer - nothing is being cleaned. `context.WithTimeout(ctx, d)` returns a
    cancellation scope, and treating its result as "the tainted thing, still tainted" is a
    category error that produced traces reading `through context.WithTimeout` on the way to
    an SSRF that did not exist.
    """
    id: str
    pattern: str
    label: str = ""


@dataclass
class Sink:
    """A dangerous operation, and specifically *which* of its arguments is dangerous.

    `roles` names each positional argument so the engine can say "the taint is in the
    context, not the URL" instead of "argument 0 of an SSRF sink". Where roles are given,
    `danger_roles` replaces `args`.

    `shell` describes execution semantics, which decides what a tainted argument means:
      always - the whole string is handed to a shell (os.system, exec, shell=True)
      argv   - program plus argument vector; a tainted argv entry is argument injection,
               not command injection, unless the program itself is a shell
      never  - no execution
    """
    id: str
    pattern: str                 # regex over the callee text
    cat: str                     # category id from rules.CATEGORIES
    title: str
    why: str
    args: tuple = (0,)           # -1 means "any argument"
    weight: int = 8
    needs_taint: bool = True     # False = dangerous regardless of input (e.g. verify=False)
    receiver_counts: bool = False  # a tainted receiver also triggers it
    roles: tuple = ()            # e.g. ("ctx", "method", "url", "body")
    danger_roles: tuple = ()     # e.g. ("url",)
    shell: str = "never"         # always | argv | conditional | never
    program_arg: int = -1        # for shell="argv": which position names the program
    shell_kwarg: str = ""        # for shell="conditional": the flag that turns it into one
                                 # (python's `shell=True`, node's `{shell: true}`)
    # The family this sink's pattern is a claim about: shell | argv | db | code | http.
    # A pattern over a callee name cannot tell `exec` the shell from `exec` the
    # promisified execFile from `exec` the RegExp method. Where this is set,
    # `analysis.binding` resolves what the name refers to and the engine either
    # reclassifies the sink or drops it, saying which definition it read.
    identity: str = ""
    # When set, the sink only fires for these value kinds. A logging call is not a sink for
    # request data - it is a sink for a *secret*, and the question it raises is disclosure,
    # not injection. Without this the log line would match every tainted value in the file.
    value_kinds: tuple = ()

    def danger_positions(self, count: int) -> list:
        """Argument positions worth reporting, given how many were actually passed."""
        if self.roles and self.danger_roles:
            return [i for i, role in enumerate(self.roles)
                    if role in self.danger_roles and i < count]
        if self.args == (-1,):
            return list(range(count))
        return [i for i in self.args if i < count]

    def role_of(self, index: int) -> str:
        if self.roles and index < len(self.roles):
            return self.roles[index]
        return ""


@dataclass
class Sanitizer:
    """Neutralises taint. Matched against the callee text of a call.

    `partial` is the important flag. `strings.ReplaceAll(url, "&", "^&")` removes exactly one
    character and leaves `|`, `>`, `<`, `%` and `"` untouched; calling that "sanitized" is how
    a tool misses the bug it was pointed at. A partial sanitizer does not kill the finding -
    it narrows what the payload can contain, and `removes` is handed to the solver so the
    remaining possibilities are reasoned about rather than assumed away.
    """
    id: str
    pattern: str
    label: str
    kills: tuple = ()            # categories it neutralises; empty = all
    partial: bool = False
    removes: tuple = ()          # the characters or sequences it actually takes out


@dataclass
class Propagator:
    """Calls that pass taint through rather than removing it (str(), .join(), etc)."""
    id: str
    pattern: str


@dataclass
class Guard:
    """A call inside an `if` that constrains a value, in a form the solver understands.

    `kind` picks the encoding:
      regex       - the value must match a pattern literal
      membership  - the value must be one of the elements of a literal list
      prefix      - the value must start with a literal
      suffix      - the value must end with a literal
      contains    - the value must contain a literal
      numeric     - the value is a number
    Positions: -1 means "the receiver of the call".
    """
    id: str
    pattern: str
    kind: str
    value_arg: int = 0
    pattern_arg: int = -1
    literal: str = ""           # the pattern itself, when the call implies one (isalnum())


@dataclass
class ImportRule:
    """How one language spells "pull a name in from another file".

    A regex over comment-stripped source with named groups: `spec` (the module specifier)
    and either `alias` (one bound name) or `names` (a comma list to split). Imports are
    syntactically simple in every language here, and a regex survives partial parse trees.
    """
    id: str
    pattern: str
    kind: str = "import"        # import | relative | package | class


@dataclass
class LangSpec:
    lang: str
    adapter: Adapter
    sources: tuple = ()
    sinks: tuple = ()
    sanitizers: tuple = ()
    propagators: tuple = ()
    handler_params: tuple = ()   # regexes: a param named like this in a handler is tainted
    implicit_sources: tuple = () # globals that are always tainted (PHP superglobals)
    param_sources: tuple = ()    # ParamSource list, matched on the declared type first
    never_params: tuple = ()     # regexes over a parameter's type or name that is never a
                                 # source: context.Context, *slog.Logger, self, testing.T
    barriers: tuple = ()         # Barrier list: calls whose result carries no taint
    handler_registrars: tuple = ()  # regexes over a callee that registers a route handler:
                                 # app.get, router.use, http.HandleFunc, @app.route
    shells: tuple = ()           # programs that interpret their arguments: sh, bash, cmd.exe
    # (callee regex, needle argument, replacement argument) for replace-style calls, so the
    # analyser can read what a filter actually takes out instead of guessing
    replacers: tuple = ()
    guards: tuple = ()           # calls the path-condition encoder understands
    imports: tuple = ()          # ImportRule list, for the cross-file pass
    exports: tuple = ()          # regexes whose group 1 is a name this file hands out
    # Regexes with named groups `name` and `type`: a field or variable that holds an
    # instance of an imported class. Without these, `this.userService.find(x)` resolves to
    # nothing, which is most of a modern dependency-injected codebase.
    bindings: tuple = ()


# -------------------------------------------------------------------- findings

@dataclass
class TraceStep:
    line: int
    code: str
    note: str
    path: str = ""          # set when the hop is in a different file


@dataclass
class Evidence:
    """What is actually known about a flow, kept separate so it can be shown and argued with.

    One overall number hid the difference between "known framework source reaches a shell
    with no guard" and "a parameter called `c` reaches something named `exec`". Both used to
    print 9/10 High. These fields are what decide the verdict, and all of them are reported.
    """
    source: str = "unknown"       # known | inferred | unknown
    value: str = "text"           # text | opaque | id | enum | bool | secret | trigger
    sink: str = "direct"          # direct | argv | indirect | unknown
    role: str = ""                # which argument the taint landed in, when known
    flow: str = "direct"          # direct | assumed (passed through a call we cannot see)
    guard: str = "none"           # none | present | partial | bypass-required
    hops: int = 0
    notes: tuple = ()             # the specific unknowns, in words
    # Injection needs a value that can carry a payload. Disclosure does not - the whole
    # point of `secret -> log` is that the value is a credential, so the payload question
    # does not apply and must not turn the result into a lead.
    payload_required: bool = True
    # Who would do this. Set when the deployment answers that nobody would: the value
    # comes from the command line or the environment of a tool the user starts
    # themselves, so the source is real, the flow is real, and the attacker is the
    # operator. A lead rather than a finding, and the reason is the text itself.
    no_attacker: str = ""

    def verdict(self) -> str:
        """`finding` only when every element is evidence. Otherwise it is a lead."""
        if self.no_attacker:
            return "lead"
        if self.source != "known":
            return "lead"
        if self.payload_required and self.value not in PAYLOAD_VALUES:
            return "lead"
        if self.flow != "direct":
            return "lead"
        if self.sink == "unknown":
            return "lead"
        # A validator whose body is not visible is not "no effective guard". The value may
        # already be checked, and claiming otherwise is the overconfidence this is here to
        # avoid. An *authorization* check is different: it gates who can reach the path, it
        # does not constrain the value, so the bug is real and conditional.
        if self.guard == "validator-opaque":
            return "lead"
        return "finding"

    def confidence(self) -> str:
        verdict = self.verdict()
        if verdict == "finding":
            if self.guard in ("none", ""):
                return "high"
            return "medium"
        if self.source == "unknown" or (self.payload_required
                                        and self.value not in PAYLOAD_VALUES):
            return "low"
        if self.guard not in ("none", ""):
            return "low"
        return "medium"

    def exploitability(self) -> str:
        """Whether a payload could actually be built, as its own axis.

        Separate from "is the flow real": a traced flow into an argv entry of a fixed
        program is a real flow and a limited bug, and collapsing the two into one number
        is what made the ranking unreadable.
        """
        if not self.payload_required:
            return "disclosure"
        if self.value not in PAYLOAD_VALUES:
            return "none"
        if self.sink == "argv":
            return "limited"
        if self.sink == "unknown":
            return "unknown"
        if self.guard in ("validator-opaque", "authorization"):
            return "conditional"
        if self.flow != "direct":
            return "unknown"
        return "direct"

    def unknowns(self) -> tuple:
        """What could not be determined, in plain words.

        Saying "I could not tell where this value comes from, I need the caller" is more
        use than a confident guess in either direction, and it is the thing a reviewer
        should go and settle first.
        """
        out = []
        if self.value == "secret" and not self.payload_required:
            out.append("who can read this sink - a log file, a build log, an error "
                       "response - which is what decides whether the credential is exposed")
        if self.source == "inferred":
            out.append("whether this really is untrusted input: it was matched by name, "
                       "not by a declared type or a framework registration")
        elif self.source == "unknown":
            out.append("where the value comes from - the caller is not visible from here")
        if self.value == "opaque":
            out.append("what kind of value this is, so whether it can carry a payload")
        if self.flow == "assumed":
            out.append("whether the value survives the "
                       + (str(self.hops) + " call(s)" if self.hops else "calls")
                       + " in between: their bodies were not analysed")
        if self.sink == "unknown":
            out.append("whether this call interprets the value, because the program being "
                       "run could not be determined")
        if self.guard == "validator-opaque":
            out.append("what the validator on this path accepts - its body is not visible")
        if self.guard == "authorization":
            out.append("who can reach this path: an authorization check gates it")
        return tuple(out)

    def breakdown(self) -> dict:
        """The axes, named and separate, rather than one number."""
        return {
            "source": {"known": "high", "inferred": "low", "unknown": "unknown"}
                      .get(self.source, "unknown"),
            "sink": {"direct": "high", "argv": "medium", "indirect": "medium",
                     "unknown": "unknown"}.get(self.sink, "unknown"),
            "guard": {"none": "none", "": "none", "present": "present",
                      "partial": "partial", "bypass-required": "bypass-required",
                      "authorization": "authorization",
                      "validator-opaque": "unreadable"}.get(self.guard, self.guard),
            "exploitability": self.exploitability(),
            "overall": self.confidence(),
        }

    def to_dict(self) -> dict:
        return {"source": self.source, "value": self.value, "sink": self.sink,
                "role": self.role, "flow": self.flow, "guard": self.guard,
                "hops": self.hops, "notes": list(self.notes),
                "payload_required": self.payload_required,
                "no_attacker": self.no_attacker,
                "verdict": self.verdict(), "unknowns": list(self.unknowns()),
                "breakdown": self.breakdown()}


@dataclass
class Finding:
    rule: str
    cat: str
    title: str
    why: str
    line: int
    snippet: str
    weight: int
    cwe: str = ""
    confidence: str = "high"      # high | medium | low
    engine: str = "taint"
    source_label: str = ""
    sanitizers: tuple = ()
    trace: list = field(default_factory=list)
    # path sensitivity
    guards: tuple = ()            # human-readable branch conditions on the way in
    witness: str = ""             # a concrete value the solver says still reaches the sink
    proof: str = ""               # witness | guards-opaque | no-solver | unguarded
    # cross-file
    cross: dict = field(default_factory=dict)   # {entry_path, entry_line, entry_source, links}
    # why anyone should believe it
    evidence: Evidence = field(default_factory=Evidence)
    tier: str = "sink"            # sink | context | signal

    def verdict(self) -> str:
        return self.evidence.verdict()

    def to_hit(self) -> dict:
        hit = {
            "rule": self.rule, "cat": self.cat, "title": self.title, "why": self.why,
            "line": self.line, "snippet": self.snippet, "weight": self.weight,
            "cwe": self.cwe, "tier": self.tier, "engine": self.engine,
            "confidence": self.confidence, "source": self.source_label,
            "sanitizers": list(self.sanitizers),
            "evidence": self.evidence.to_dict(),
            # only a claimed vulnerability has a verdict; a signal is an observation and a
            # context note is a property of the file, and labelling either a "lead" made
            # the counts meaningless
            "verdict": self.evidence.verdict() if self.tier == "sink" else self.tier,
            "trace": [{"line": s.line, "code": s.code, "note": s.note, "path": s.path}
                      for s in self.trace],
            "soft": False,
        }
        if self.guards:
            hit["guards"] = list(self.guards)
        if self.witness:
            hit["witness"] = self.witness
        if self.proof:
            hit["proof"] = self.proof
        if self.cross:
            hit["cross"] = self.cross
        return hit


# ------------------------------------------------- interprocedural summaries

@dataclass
class SinkRef:
    """A sink that one formal parameter of a function can reach.

    This is the unit of cross-file reasoning: "pass something dirty as argument 0 of
    `runCmd` and it lands in `exec` at util.js:14". Combined with a call site that passes
    tainted data, it is a complete finding spanning two files.
    """
    sink_id: str
    cat: str
    title: str
    why: str
    weight: int
    line: int
    path: str = ""
    steps: tuple = ()           # TraceStep tuple inside the callee
    hops: int = 0               # how many function boundaries were crossed to get here
    via: tuple = ()             # link strengths used, e.g. ("import", "name")
    guards: tuple = ()
    sanitized: tuple = ()
    killed: tuple = ()


@dataclass
class Summary:
    """What a caller needs to know about a function it cannot see the body of."""
    path: str
    name: str
    line: int
    params: tuple = ()
    param_sinks: dict = field(default_factory=dict)      # index -> [SinkRef]
    param_forwards: dict = field(default_factory=dict)    # index -> [(callee_text, arg_index)]
    param_returns: tuple = ()                             # indexes that flow into the return
    returns_source: str = ""                              # label if it returns untrusted data


@dataclass
class CallSite:
    """A call passing untrusted data into something not defined in this file."""
    path: str
    line: int
    callee: str
    arg: int
    source: str
    kind: str = "request"
    confidence: str = "high"
    steps: tuple = ()
    sanitized: tuple = ()
    killed: tuple = ()
    scope: str = ""


@dataclass
class FileFacts:
    """Everything the repo-level pass needs from one file."""
    path: str = ""
    lang: str = ""
    summaries: dict = field(default_factory=dict)     # name -> Summary
    callsites: list = field(default_factory=list)     # CallSite
    imports: list = field(default_factory=list)       # (kind, spec, {alias: remote_name})
    exports: tuple = ()
    bindings: list = field(default_factory=list)      # (field name, class name)
