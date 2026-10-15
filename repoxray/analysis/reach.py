"""Is this dangerous setting always on, or only when the operator asks for it?

    if o.NoTLSVerify {
        tlsConfig := &tls.Config{
            InsecureSkipVerify: true,
        }
    }

The pattern match sees `InsecureSkipVerify: true` and reports TLS verification disabled at
weight 8. What is actually there is a documented opt-in: the operator writes
`no-tls-verify` in a connection string and gets what they asked for. That is a capability.
The same line outside any condition is a vulnerability, because then every caller gets it
whether they wanted it or not.

The difference is the enclosing branch conditions, which the AST already has. This module
walks up from a line and says what guards it, reusing the tree the dataflow pass parsed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# node types that introduce a condition, across the nine grammars
_BRANCH = {
    "if_statement", "if", "elif_clause", "else_clause", "unless", "unless_modifier",
    "if_modifier", "conditional_expression", "ternary_expression",
    "switch_statement", "expression_switch_statement", "type_switch_statement",
    "match_statement", "case_statement", "when", "switch_section", "select_statement",
    "guard_statement", "for_statement", "while_statement", "range_clause",
}
_LOOP = {"for_statement", "while_statement", "range_clause", "for_in_statement",
         "for_statement_with_clause", "do_statement", "while", "until", "repeat_statement"}
_FUNC = {
    "function_declaration", "function_definition", "method_declaration", "func_literal",
    "method_definition", "function", "arrow_function", "function_expression",
    "constructor_declaration", "lambda", "singleton_method", "block",
    "method", "local_function_statement", "function_item",
}

# A condition that reads one of these is the operator turning something on, not an
# attacker influencing a value.
_OPTION_NAME = re.compile(
    r"\b(?:opt|opts|option|options|cfg|conf|config|configuration|settings?|"
    r"flags?|params?|args?|spec|prefs?|preferences|override|overrides|"
    r"features?|toggle|enabled?|disabled?|allow|skip|insecure|verbose|debug|"
    r"dev|devel|development|local|dry[_\-]?run|force|strict|unsafe)\b", re.I)
_SETTING_FIELD = re.compile(
    r"\b(?:insecure|skip[_\-]?verify|no[_\-]?tls[_\-]?verify|no[_\-]?verify|"
    r"allow[_\-]?insecure|disable[_\-]?(?:tls|ssl|verify|auth|csrf|cors)|"
    r"trust[_\-]?all|self[_\-]?signed|debug|dev[_\-]?mode|test[_\-]?mode|"
    r"unsafe|experimental|enable[_\-]?\w+|is[_\-]?\w*(?:enabled|allowed))\b", re.I)
_ENV_READ = re.compile(
    r"os\.Getenv|os\.environ|getenv|process\.env|ENV\[|System\.getenv|"
    r"Environment\.GetEnvironmentVariable|\$_ENV\[")
_REQUEST_READ = re.compile(
    r"\br\.(?:FormValue|URL|Header|Body|PostForm)|\breq\.(?:body|query|params|headers|"
    r"cookies)|request\.(?:args|form|json|GET|POST|getParameter)|\$_(?:GET|POST|REQUEST)|"
    r"\bparams\[|mux\.Vars|c\.(?:Param|Query)")
_LITERAL_ONLY = re.compile(r"^[\s!()]*(?:true|false|nil|null|None|\d+|\"[^\"]*\"|"
                           r"'[^']*')[\s()]*$")


@dataclass(frozen=True)
class Guard:
    """One enclosing condition."""
    text: str
    kind: str            # option | env | request | constant | loop | unknown
    line: int = 0

    def describe(self) -> str:
        if self.kind == "option":
            return "reached only when the caller sets `" + self.text + "`"
        if self.kind == "env":
            return "reached only when the environment sets `" + self.text + "`"
        if self.kind == "request":
            return "guarded by `" + self.text + "`, which reads request data"
        if self.kind == "constant":
            return "guarded by the constant condition `" + self.text + "`"
        if self.kind == "loop":
            return "inside the loop `" + self.text + "`"
        return "guarded by `" + self.text + "`"


@dataclass(frozen=True)
class Reach:
    """How a line is reached."""
    guards: tuple = ()
    function: str = ""
    exported: bool = True

    @property
    def unconditional(self) -> bool:
        return not any(g.kind in ("option", "env", "request", "unknown")
                       for g in self.guards)

    @property
    def opt_in(self) -> bool:
        """Reached only if someone deliberately turned it on."""
        return any(g.kind in ("option", "env") for g in self.guards) \
            and not any(g.kind == "request" for g in self.guards)

    def describe(self) -> str:
        if not self.guards:
            return ("this line runs every time the enclosing function does, with nothing "
                    "to turn it off")
        return "; ".join(g.describe() for g in self.guards[:3])


def classify_condition(text: str) -> str:
    flat = " ".join(text.split())
    if _REQUEST_READ.search(flat):
        return "request"
    if _ENV_READ.search(flat):
        return "env"
    if _SETTING_FIELD.search(flat):
        return "option"
    if _OPTION_NAME.search(flat):
        return "option"
    if _LITERAL_ONLY.match(flat):
        return "constant"
    return "unknown"


def _txt(node, data: bytes) -> str:
    try:
        return data[node.start_byte:node.end_byte].decode("utf-8", "replace")
    except Exception:                                       # noqa: BLE001
        return ""


def _condition_of(node, data: bytes):
    for field in ("condition", "value", "left"):
        try:
            child = node.child_by_field_name(field)
        except Exception:                                   # noqa: BLE001
            child = None
        if child is not None:
            return child
    # grammars that do not name the field: the first non-keyword child
    for child in node.named_children:
        if child.type not in ("block", "statement_block", "statement_list", "body",
                              "consequence", "alternative", "else_clause", "elif_clause"):
            return child
    return None


def _body_ranges(node):
    """The line ranges the condition actually governs (its body, not the whole statement).

    Without this an `if` claims every line down to its closing brace, including the `else`
    branch, and a setting in the else branch would be reported as opt-in when it is the
    default.
    """
    out = []
    for field in ("consequence", "body", "block"):
        try:
            child = node.child_by_field_name(field)
        except Exception:                                   # noqa: BLE001
            child = None
        if child is not None:
            out.append((child.start_point[0] + 1, child.end_point[0] + 1))
    if not out:
        for child in node.named_children:
            if child.type in ("block", "statement_block", "statement_list", "do_block",
                              "then", "body"):
                out.append((child.start_point[0] + 1, child.end_point[0] + 1))
    if not out:
        out.append((node.start_point[0] + 1, node.end_point[0] + 1))
    return out


MAX_NODES = 200_000


def analyse(root, data: bytes, lines: set) -> dict:
    """{line: Reach} for each line in `lines`.

    One pass over the tree collecting (condition, governed range) and (function, range),
    then a containment test per requested line. Cheaper than walking up from each line and
    it needs no parent pointers.
    """
    if not lines or root is None:
        return {}
    branches: list = []
    funcs: list = []
    seen = 0
    stack = [root]
    while stack:
        node = stack.pop()
        seen += 1
        if seen > MAX_NODES:
            break
        ntype = node.type
        if ntype in _BRANCH:
            if ntype in _LOOP:
                cond = _condition_of(node, data)
                text = _txt(cond, data) if cond is not None else ntype
                for lo, hi in _body_ranges(node):
                    branches.append((lo, hi, Guard(" ".join(text.split())[:160], "loop",
                                                   node.start_point[0] + 1)))
            else:
                cond = _condition_of(node, data)
                if cond is not None:
                    text = " ".join(_txt(cond, data).split())
                    if text:
                        text = text.strip("()").strip()
                        kind = classify_condition(text)
                        for lo, hi in _body_ranges(node):
                            branches.append((lo, hi, Guard(text[:160], kind,
                                                           node.start_point[0] + 1)))
        elif ntype in _FUNC:
            name = ""
            try:
                ident = node.child_by_field_name("name")
                if ident is not None:
                    name = _txt(ident, data)
            except Exception:                               # noqa: BLE001
                name = ""
            funcs.append((node.start_point[0] + 1, node.end_point[0] + 1, name))
        stack.extend(node.children)

    out: dict = {}
    for line in lines:
        guards = [g for lo, hi, g in branches if lo <= line <= hi]
        guards.sort(key=lambda g: g.line)
        inner = [(lo, hi, n) for lo, hi, n in funcs if lo <= line <= hi]
        inner.sort(key=lambda t: t[1] - t[0])
        fname = inner[0][2] if inner else ""
        exported = True
        if fname:
            # Go and Python conventions: an unexported or private helper is not reachable
            # from outside the package, which matters for a library
            exported = not (fname[0] == "_" or (fname[0].islower() and "_" not in fname
                                                and fname.isalpha() is False))
            exported = not fname.startswith("_")
        out[line] = Reach(tuple(guards[:4]), fname, exported)
    return out
