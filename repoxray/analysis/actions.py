"""GitHub Actions workflows, modelled as workflows rather than as text with braces in it.

Treating a workflow as "YAML that sometimes contains user data" produces exactly the wrong
answers. Three distinct things get conflated:

  a trigger          `on: pull_request_target` says *when* the workflow runs and with what
                     privileges. It is not data and nothing flows from it.
  an event field     `github.event.pull_request.title` is attacker-controlled text.
                     `github.event.pull_request.number` is an integer. Only one of them can
                     carry `; whoami`.
  a position         an expression inside `run:` is handed to a shell. The same expression
                     in `concurrency.group:` or `name:` is handed to nothing.

So this module parses the workflow structure, classifies every `${{ }}` expression by what
the referenced field actually *is*, and only reports an expression that reaches somewhere
that interprets it. The privileged-trigger question is answered separately, as an exposure
note with the guards that gate it, because "this workflow runs with write access on pull
requests from forks" is a true and useful statement that is not an injection finding.

Needs PyYAML. Without it the file falls back to the pattern pass and says so.
"""
from __future__ import annotations

import re

try:                                   # pragma: no cover - import probe
    import yaml
except Exception:                      # pragma: no cover
    yaml = None

MAX_BYTES = 400_000
EXPR_RE = re.compile(r"\$\{\{(.+?)\}\}", re.S)
# the identifier chains inside an expression: github.event.pull_request.title, inputs.name
REF_RE = re.compile(r"\b(github|inputs|needs|steps|env|secrets|vars|matrix|runner|job)"
                    r"((?:\.[A-Za-z_][\w-]*|\[[^\]]+\])*)")


def available() -> bool:
    return yaml is not None


def is_workflow(path: str) -> bool:
    low = path.replace("\\", "/").lower()
    return ("/.github/workflows/" in "/" + low) and low.endswith((".yml", ".yaml"))


def is_action_manifest(path: str) -> bool:
    low = path.replace("\\", "/").lower()
    return low.endswith(("action.yml", "action.yaml"))


# --------------------------------------------------------------- field semantics

# Free-form text an attacker can put anything in. This is the list that matters: everything
# else is either not attacker-controlled or not able to carry a payload.
TEXT_FIELDS = (
    r"^github\.event\.(issue|pull_request|discussion)\.(title|body)$",
    r"^github\.event\.(comment|review|review_comment)\.body$",
    r"^github\.event\.(issue|pull_request)\.user\.(name|email)$",
    r"^github\.event\.pull_request\.head\.(ref|label)$",
    r"^github\.event\.pull_request\.head\.repo\.(description|homepage|default_branch)$",
    r"^github\.head_ref$",
    r"^github\.event\.head_commit\.(message|author\.(name|email))$",
    r"^github\.event\.commits(\[[^\]]*\])?\.(message|author\.(name|email))$",
    r"^github\.event\.release\.(body|name|tag_name)$",
    r"^github\.event\.milestone\.(title|description)$",
    r"^github\.event\.label\.(name|description)$",
    r"^github\.event\.(inputs|client_payload)\b",
    r"^inputs\.",
    r"^github\.event\.workflow_run\.(head_branch|display_title)$",
    r"^github\.event\.pages(\[[^\]]*\])?\.page_name$",
    r"^github\.event\.deployment\.(payload|description|ref|environment)$",
    r"^github\.event\.ref$",
    r"^github\.ref$", r"^github\.ref_name$",
)

# Declared in the workflow file itself, so controlled by whoever can change the workflow -
# which is the same person the job already trusts. Classifying these as untrusted produced
# dozens of findings on `matrix.features` and `env.XCODE_VERSION`, values written three
# lines further up in the same file.
AUTHORED_FIELDS = (r"^matrix\.", r"^vars\.", r"^env\.")

# Produced by an earlier step or job. Trustworthy exactly as far as that step is, which
# this pass cannot know in general - so it is reported as something to check, never as a
# finding on its own.
DERIVED_FIELDS = (r"^steps\.", r"^needs\.")

# Attacker-chosen but not free-form: an integer, a hash, a login. None of these can hold a
# shell metacharacter, so none of them is a command-injection source.
ID_FIELDS = (
    r"\.(number|id|node_id|sha)$",
    r"^github\.(sha|run_id|run_number|run_attempt|workflow_sha)$",
    r"^github\.event\.(issue|pull_request)\.(created_at|updated_at|closed_at|merged_at)$",
)
SLUG_FIELDS = (          # GitHub logins and repo names: [A-Za-z0-9._-] only
    r"\.(login|slug)$",
    r"^github\.(actor|triggering_actor)$",
    r"^github\.event\.(sender|pusher)\.(login|name)$",
    r"^github\.event\.pull_request\.head\.repo\.full_name$",
    r"^github\.event\.repository\.(name|full_name)$",
)
ENUM_FIELDS = (
    r"^github\.event_name$", r"^github\.event\.action$", r"^github\.ref_type$",
    r"\.(state|merged|draft|locked|private|fork|author_association)$",
)
TRUSTED_FIELDS = (
    r"^github\.(repository|repository_owner|repository_id|workflow|workflow_ref|job|"
    r"action|action_path|action_repository|workspace|server_url|api_url|graphql_url|"
    r"event_path|path|env|retention_days)$",
    r"^runner\.", r"^job\.",
)


def classify(ref: str, env_kinds: dict | None = None) -> tuple:
    """(value kind, label) for one `${{ }}` reference.

    Order matters: the specific field patterns are checked before the broad prefixes, so
    `github.event.pull_request.number` is an id even though `github.event.pull_request.*`
    is otherwise a text-bearing object.

    `env_kinds` resolves `env.NAME` to whatever the workflow put in it, so an env variable
    that really does hold an event field is followed rather than waved through.
    """
    ref = ref.strip()
    if ref.startswith("secrets."):
        return "secret", "repository secret"
    if ref in ("github.token",):
        return "secret", "workflow token"
    if env_kinds and ref.startswith("env."):
        resolved = env_kinds.get(ref.split(".", 1)[1])
        if resolved:
            return resolved[0], "env " + ref.split(".", 1)[1] + " holding " + resolved[1]
    for pattern in AUTHORED_FIELDS:
        if re.search(pattern, ref):
            return "trusted", "declared in the workflow"
    for pattern in DERIVED_FIELDS:
        if re.search(pattern, ref):
            return "derived", "output of an earlier step"
    for pattern in ID_FIELDS:
        if re.search(pattern, ref):
            return "id", "identifier"
    for pattern in ENUM_FIELDS:
        if re.search(pattern, ref):
            return "enum", "fixed set of values"
    for pattern in SLUG_FIELDS:
        if re.search(pattern, ref):
            return "slug", "login or repository name"
    for pattern in TRUSTED_FIELDS:
        if re.search(pattern, ref):
            return "trusted", "workflow metadata"
    for pattern in TEXT_FIELDS:
        if re.search(pattern, ref):
            return "text", "attacker-controlled text"
    if ref.startswith("github.event."):
        # an event field nobody has classified: assume text, say that it was an assumption
        return "opaque", "event field of unknown type"
    return "trusted", "workflow metadata"


# Triggers that can be fired by someone without write access, where the workflow still runs
# with the repository's own permissions and secrets.
UNTRUSTED_TRIGGERS = {
    "pull_request_target": "a pull request from any fork",
    "issue_comment": "a comment from any user",
    "issues": "an issue from any user",
    "discussion": "a discussion from any user",
    "discussion_comment": "a discussion comment from any user",
    "workflow_run": "the completion of another workflow, including one from a fork",
    "fork": "anyone forking the repository",
    "watch": "anyone starring the repository",
    "pull_request_review_comment": "a review comment from any user",
}
# `pull_request` runs without secrets and with a read-only token for fork PRs, so it is not
# in the list above - but it is worth noting when combined with write permissions.

WRITE_PERMS = ("write", "write-all")

GUARD_PATTERNS = (
    (r"head\.repo\.full_name\s*==\s*github\.repository",
     "restricted to pull requests from the repository itself, not from forks", True),
    (r"head\.repo\.fork\s*==\s*false", "restricted to non-fork pull requests", True),
    (r"\.fork\s*==\s*false", "restricted to non-fork events", True),
    (r"github\.repository\s*==\s*['\"]", "restricted to one repository", True),
    (r"author_association\s*==\s*['\"](OWNER|MEMBER|COLLABORATOR)",
     "restricted to repository members", True),
    (r"github\.actor\s*==\s*['\"]", "restricted to one actor", True),
    (r"contains\(\s*fromJSON", "restricted to an allow-list", True),
    (r"startsWith\(\s*github\.event\.pull_request\.head\.ref",
     "restricted by branch-name prefix", False),
    (r"startsWith\(", "restricted by a prefix check", False),
    (r"github\.event\.pull_request\.draft", "skips draft pull requests", False),
)


def _guards_in(expr: str) -> list:
    """[(description, blocks_fork)] for the checks inside an `if:` expression."""
    out = []
    for pattern, label, blocks in GUARD_PATTERNS:
        if re.search(pattern, expr):
            out.append((label, blocks))
    return out


# -------------------------------------------------------------------- yaml tree

class Y:
    """A YAML value that remembers which line it came from."""
    __slots__ = ("val", "line", "kind", "block")

    def __init__(self, val, line: int, kind: str, block: bool = False):
        self.val = val
        self.line = line
        self.kind = kind
        # A block scalar's node starts on the `run: |` line, but its *content* starts on
        # the next one. Without this, every interpolation in a multi-line script reported
        # the `run: |` line - three identical rows on one line, pointing at the one line
        # of the script that holds no expression.
        self.block = block

    @property
    def body_line(self) -> int:
        """The line the scalar's text actually begins on."""
        return self.line + 1 if self.block else self.line

    def get(self, key, default=None):
        if self.kind != "map":
            return default
        return self.val.get(key, default)

    def keys(self):
        return list(self.val.keys()) if self.kind == "map" else []

    def items(self):
        return list(self.val.items()) if self.kind == "map" else []

    def seq(self) -> list:
        if self.kind == "seq":
            return self.val
        if self.kind == "map":
            return [self]
        return [self] if self.val is not None else []

    def text(self) -> str:
        return self.val if self.kind == "scalar" and isinstance(self.val, str) else ""

    def __repr__(self) -> str:                               # pragma: no cover
        return "Y(%s@%d)" % (self.kind, self.line)


def _convert(node) -> Y:
    line = node.start_mark.line + 1
    if isinstance(node, yaml.MappingNode):
        out = {}
        for key, value in node.value:
            name = key.value if hasattr(key, "value") else str(key)
            if isinstance(name, str):
                out[name] = _convert(value)
        return Y(out, line, "map")
    if isinstance(node, yaml.SequenceNode):
        return Y([_convert(c) for c in node.value], line, "seq")
    return Y(node.value, line, "scalar",
             block=getattr(node, "style", None) in ("|", ">"))


def parse_workflow(text: str):
    if yaml is None:
        return None, "PyYAML is not installed"
    if len(text) > MAX_BYTES:
        return None, "workflow too large"
    try:
        node = yaml.compose(text)
    except Exception as exc:
        return None, "yaml: " + type(exc).__name__ + " " + str(exc)[:90]
    if node is None:
        return None, "empty workflow"
    try:
        return _convert(node), ""
    except Exception as exc:                                 # pragma: no cover
        return None, "yaml walk: " + str(exc)[:90]


# ------------------------------------------------------------------- expressions

def refs_in(expr: str) -> list:
    """The context references inside one `${{ }}` body, normalised to dotted paths."""
    out = []
    for m in REF_RE.finditer(expr):
        ref = (m.group(1) + m.group(2)).replace("['", ".").replace("']", "")
        ref = re.sub(r"\[\s*([\w.]+)\s*\]", r".\1", ref)
        if ref not in out:
            out.append(ref)
    return out


def expressions(value: str) -> list:
    """[(whole expression, [refs], line offset)] for every `${{ }}` in a scalar.

    The offset matters for a block scalar: a `run: |` script is one YAML node, and a
    finding has to point at the line inside it that actually carries the expression.
    """
    out = []
    text = value or ""
    for m in EXPR_RE.finditer(text):
        out.append((m.group(0), refs_in(m.group(1)), text.count("\n", 0, m.start())))
    return out


def worst(refs: list, env_kinds: dict | None = None) -> tuple:
    """The most dangerous classification among a set of references."""
    rank = {"text": 6, "opaque": 5, "derived": 4, "slug": 3, "id": 2, "enum": 1,
            "trusted": 0, "secret": 0}
    best = ("trusted", "workflow metadata", "")
    for ref in refs:
        kind, label = classify(ref, env_kinds)
        if rank.get(kind, 0) > rank.get(best[0], 0):
            best = (kind, label, ref)
    return best


# Which fields anyone can set, as opposed to the ones that need push access. The injection
# is the same shape either way; the question of who can reach it is not, and reporting a
# push-only field at the same weight floods ordinary CI with findings nobody can use.
ANYONE_FIELDS = (
    r"^github\.event\.(issue|pull_request|comment|review|review_comment|discussion)\b",
    r"^github\.head_ref$",
    r"^github\.event\.client_payload\b",
    r"^github\.event\.(sender|pusher)\b",
    r"^github\.event\.workflow_run\.head_branch$",
    r"^github\.event\.fork(ee)?\b",
)


# Event types that only someone with write or triage access can produce. `issues: [opened]`
# fires for anybody; `issues: [labeled]` needs a label applied, which needs permission - so
# the same field is reachable by a different set of people depending on the trigger types.
PRIVILEGED_TYPES = {
    "labeled", "unlabeled", "assigned", "unassigned", "closed", "reopened", "milestoned",
    "demilestoned", "locked", "unlocked", "pinned", "unpinned", "transferred",
    "converted_to_draft", "ready_for_review", "review_requested", "review_request_removed",
    "auto_merge_enabled", "auto_merge_disabled", "dequeued", "enqueued",
}


def reachable_by(ref: str, gated: bool = False) -> str:
    """`anyone` or `writer` - who has to be able to act to control this field."""
    if gated:
        return "writer"
    for pattern in ANYONE_FIELDS:
        if re.search(pattern, ref or ""):
            return "anyone"
    return "writer"


def _types_need_access(on_node) -> bool:
    """True when every configured event type needs repository access to fire."""
    if on_node is None or on_node.kind != "map":
        return False
    found = []
    for _name, value in on_node.items():
        if value is None or value.kind != "map":
            continue
        types = value.get("types")
        if types is None:
            continue
        found += [item.text() for item in types.seq() if item.text()]
    return bool(found) and all(t in PRIVILEGED_TYPES for t in found)


# -------------------------------------------------------------- shell use of env

def env_use(script: str, name: str) -> str:
    """How a `run:` script uses an environment variable: quoted, bare, reinterpreted, none.

    `env: X: ${{ ... }}` plus `run: cmd "$X"` is GitHub's own recommended mitigation, and a
    tool that calls it an injection is telling people to undo the fix.

    The distinction that matters is *command position*. In `$(echo $X | sed ...)` the shell
    runs `echo`, and `$X` is an argument to it - the value is word-split and globbed, which
    can add arguments, and is not executed. In `$($X)`, `eval $X` or `sh -c "$X"` the value
    itself is parsed as a command line. Calling the first one command execution overstates
    it by two severity levels.
    """
    if not script or not name:
        return "none"
    var = r"\$\{?" + re.escape(name) + r"\b\}?"
    if not re.search(r"(?<!\\)" + var, script):
        return "none"
    # the value lands where a command name is expected, so the shell parses it as one
    command_position = (
        r"(?:^|[\n;|&]|\$\(|`|\beval\s+)[ \t]*(?:[\"']\s*)?" + var,
        r"\b(?:sh|bash|zsh|ash|dash)\b[^\n]{0,40}?-c[ \t]+[\"']?" + var,
        r"\bexec[ \t]+[\"']?" + var,
    )
    for pattern in command_position:
        if re.search(pattern, script):
            return "reinterpreted"
    for m in re.finditer(r"(?<!\\)" + var, script):
        line = script[script.rfind("\n", 0, m.start()) + 1:m.start()]
        quotes = line.count('"') - line.count('\\"')
        if quotes % 2 == 1:
            continue                     # inside a double-quoted string: no word splitting
        return "bare"
    return "quoted"


# ------------------------------------------------------------------- the pass

RISKY_ACTION_INPUTS = {
    "actions/github-script": ("script",),
    "docker/build-push-action": ("build-args",),
}


def _triggers(doc) -> list:
    on = doc.get("on")
    if on is None:
        on = doc.get(True)      # YAML 1.1 reads a bare `on:` key as the boolean True
    if on is None:
        return []
    if on.kind == "scalar":
        return [(on.text(), on.line)]
    if on.kind == "seq":
        return [(item.text(), item.line) for item in on.val if item.text()]
    return [(name, value.line if value is not None else on.line)
            for name, value in on.items()]


def _permissions(block) -> tuple:
    """(elevated?, description) for a permissions mapping or scalar."""
    if block is None:
        return True, "no permissions block, so the job gets the repository default"
    if block.kind == "scalar":
        text = str(block.val)
        if text in WRITE_PERMS:
            return True, "permissions: " + text
        return False, "permissions: " + text
    granted = [name for name, value in block.items() if str(value.val) in WRITE_PERMS]
    if granted:
        return True, "write access to " + ", ".join(sorted(granted))
    return False, "read-only permissions"


def analyse_workflow(text: str, path: str) -> dict:
    """Findings, signals and exposure notes for one workflow file."""
    out = {"ok": False, "findings": [], "signals": [], "notes": [], "reason": "",
           "triggers": [], "guards": []}
    doc, reason = parse_workflow(text)
    if doc is None or doc.kind != "map":
        out["reason"] = reason or "not a workflow mapping"
        return out
    out["ok"] = True

    triggers = _triggers(doc)
    out["triggers"] = [name for name, _line in triggers]
    untrusted = [(name, line) for name, line in triggers if name in UNTRUSTED_TRIGGERS]
    on_node = doc.get("on") if doc.get("on") is not None else doc.get(True)
    gated_types = _types_need_access(on_node)
    top_elevated, top_perm = _permissions(doc.get("permissions"))

    jobs = doc.get("jobs")
    guards: list = []
    secrets_used: list = []
    findings = out["findings"]
    signals = out["signals"]
    elevated_anywhere = top_elevated
    # name -> (kind, label) for every env: block in the file, so `env.X` resolves to what
    # the workflow actually put in X instead of being waved through as workflow metadata
    env_kinds: dict = {}

    def learn_env(node) -> None:
        for name, value in (node.items() if node is not None and node.kind == "map" else []):
            exprs = expressions(value.text())
            if not exprs:
                continue
            kind, label, _ref = worst([r for _e, rs, _o in exprs for r in rs], env_kinds)
            if kind not in ("trusted",):
                env_kinds[name] = (kind, label)

    learn_env(doc.get("env"))
    for _jn, _job in (jobs.items() if jobs is not None else []):
        if _job.kind != "map":
            continue
        learn_env(_job.get("env"))
        _steps = _job.get("steps")
        for _step in (_steps.seq() if _steps is not None else []):
            if _step.kind == "map":
                learn_env(_step.get("env"))

    def scalar_expressions(node) -> list:
        """[(expression, refs, line)] for every scalar under a node."""
        if node is None:
            return []
        if node.kind == "scalar":
            return [(expr, refs, node.body_line + off)
                    for expr, refs, off in expressions(node.text())]
        found = []
        if node.kind == "map":
            for _key, value in node.items():
                found += scalar_expressions(value)
        elif node.kind == "seq":
            for value in node.val:
                found += scalar_expressions(value)
        return found

    def note_secrets(node, where: str) -> None:
        for _expr, refs, line in scalar_expressions(node):
            for ref in refs:
                if ref.startswith("secrets.") or ref == "github.token":
                    secrets_used.append((ref, line, where))

    for job_name, job in (jobs.items() if jobs is not None else []):
        if job.kind != "map":
            continue
        job_elevated, job_perm = top_elevated, top_perm
        if job.get("permissions") is not None:
            job_elevated, job_perm = _permissions(job.get("permissions"))
        elevated_anywhere = elevated_anywhere or job_elevated

        job_if = job.get("if")
        if job_if is not None:
            for label, blocks in _guards_in(job_if.text()):
                guards.append({"where": "job " + job_name, "line": job_if.line,
                               "guard": label, "blocks_fork": blocks,
                               "expr": job_if.text().strip()[:200]})
            # An `if:` is evaluated by GitHub's expression engine with the field as a
            # typed value - it is not substituted into a shell and not re-parsed, so
            # untrusted text here is a condition input, not an injection. Reporting it was
            # the same control-flow/data-flow confusion as treating a trigger as data.

        note_secrets(job.get("with"), "job inputs")
        note_secrets(job.get("env"), "job env")
        note_secrets(job.get("secrets"), "reusable workflow secrets")

        steps = job.get("steps")
        for index, step in enumerate(steps.seq() if steps is not None else []):
            if step.kind != "map":
                continue
            step_name = (step.get("name").text() if step.get("name") is not None
                         else "step " + str(index + 1))
            run = step.get("run")
            uses = step.get("uses")
            with_block = step.get("with")
            env_block = step.get("env")
            step_if = step.get("if")
            if step_if is not None:
                for label, blocks in _guards_in(step_if.text()):
                    guards.append({"where": step_name, "line": step_if.line,
                                   "guard": label, "blocks_fork": blocks,
                                   "expr": step_if.text().strip()[:200]})
            note_secrets(env_block, "env of " + step_name)
            note_secrets(with_block, "inputs of " + step_name)

            # an expression inlined straight into a shell script
            if run is not None and run.text():
                script = run.text()
                for expr, refs, off in expressions(script):
                    line = run.body_line + off
                    kind, label, ref = worst(refs, env_kinds)
                    if kind in ("text", "opaque"):
                        who = reachable_by(ref, gated_types)
                        openly = who == "anyone"
                        findings.append({
                            "rule": "gha.run_injection", "cat": "cmd", "line": line,
                            "title": "untrusted text interpolated into a shell script",
                            "why": ("GitHub substitutes " + expr.strip() + " into the script "
                                    "before the shell parses it, so a value containing ; or "
                                    "$(...) runs as a command with this job's token."
                                    + ("" if openly else " Setting " + ref + " needs push "
                                       "access to this repository, so the reach is limited "
                                       "to people who already have it.")),
                            "weight": 9 if openly else 5, "value": kind, "ref": ref,
                            "actor": who,
                            "verdict": ("finding" if (kind == "text" and openly)
                                        else "lead"),
                            "confidence": ("high" if (kind == "text" and openly)
                                           else "medium"),
                            "position": "run", "step": step_name,
                            "fix": ("pass it through env: and reference it as \"$NAME\", "
                                    "which the shell treats as data"),
                        })
                    elif ref:
                        signals.append({
                            "rule": "gha.run_interpolation", "line": line,
                            "title": "expression in a script, but the value cannot carry a "
                                     "payload",
                            "detail": ref + " is " + label + ", so this is not injection.",
                        })
                for name, value in (env_block.items() if env_block is not None else []):
                    exprs = expressions(value.text())
                    if not exprs:
                        continue
                    kind, label, ref = worst([r for _e, rs, _o in exprs for r in rs],
                                             env_kinds)
                    if kind not in ("text", "opaque"):
                        continue
                    usage = env_use(script, name)
                    who = reachable_by(ref, gated_types)
                    openly = who == "anyone"
                    limited = ("" if openly else " Setting " + ref + " needs repository "
                               "access, which limits who can reach it.")
                    if usage == "reinterpreted":
                        findings.append({
                            "rule": "gha.env_reinterpreted", "cat": "cmd",
                            "line": value.line,
                            "title": "untrusted env value re-parsed by the shell",
                            "why": ("$" + name + " holds " + ref + " and the script expands "
                                    "it where a command name is expected, so the shell "
                                    "parses it as a command line." + limited),
                            "weight": 8 if openly else 5, "value": kind, "ref": ref,
                            "actor": who,
                            "verdict": "finding" if openly else "lead",
                            "confidence": "high" if openly else "medium",
                            "position": "env->run", "step": step_name,
                        })
                    elif usage == "bare":
                        findings.append({
                            "rule": "gha.env_unquoted", "cat": "argv", "line": value.line,
                            "title": "untrusted env value expanded without quotes",
                            "why": ("$" + name + " holds " + ref + " and is expanded "
                                    "unquoted, so it is split into words and globbed. It is "
                                    "not run as a command, but it can add arguments to the "
                                    "command that is." + limited),
                            "weight": 5 if openly else 3, "value": kind, "ref": ref,
                            "actor": who, "verdict": "lead",
                            "confidence": "medium" if openly else "low",
                            "position": "env->run", "step": step_name,
                            "fix": "quote the expansion: \"$" + name + "\"",
                        })
                    # quoted or unused: this is the documented mitigation, nothing to report

            if uses is not None and uses.text():
                spec = uses.text().strip()
                action = spec.split("@")[0]
                ref_part = spec.split("@")[1] if "@" in spec else ""
                for key in RISKY_ACTION_INPUTS.get(action, ()):
                    target = with_block.get(key) if with_block is not None else None
                    if target is None:
                        continue
                    for expr, refs, off in expressions(target.text()):
                        line = target.body_line + off
                        kind, label, ref = worst(refs, env_kinds)
                        if kind in ("text", "opaque"):
                            findings.append({
                                "rule": "gha.script_injection", "cat": "code", "line": line,
                                "title": "untrusted text interpolated into " + action,
                                "why": (expr.strip() + " is substituted into JavaScript that "
                                        "runs with this job's token."),
                                "weight": 9, "value": kind, "ref": ref,
                                "verdict": "finding" if kind == "text" else "lead",
                                "confidence": "high" if kind == "text" else "medium",
                                "position": "with." + key, "step": step_name,
                            })
                if action == "actions/checkout" and untrusted and with_block is not None:
                    target = with_block.get("ref")
                    if target is not None:
                        refs = [r for _e, rs, _o in expressions(target.text())
                                for r in rs]
                        if any(("pull_request" in r) or ("head" in r) or ("merge" in r)
                               for r in refs):
                            findings.append({
                                "rule": "gha.untrusted_checkout", "cat": "supply",
                                "line": target.line,
                                "title": "fork code checked out in a privileged workflow",
                                "why": ("The workflow is triggered by " + untrusted[0][0]
                                        + " and checks out the pull request head, so any "
                                        "later step that runs project scripts executes code "
                                        "from the fork with this job's permissions."),
                                "weight": 9, "value": "text",
                                "ref": refs[0] if refs else "",
                                "verdict": "finding", "confidence": "high",
                                "position": "with.ref", "step": step_name,
                            })
                if ref_part and "/" in action and not action.startswith("actions/") \
                        and not re.fullmatch(r"[0-9a-f]{40}", ref_part):
                    signals.append({
                        "rule": "gha.unpinned_action", "line": uses.line,
                        "title": "third-party action pinned to a mutable ref",
                        "detail": (spec + " can be repointed by its owner; a commit SHA "
                                   "cannot."),
                    })

    out["guards"] = guards
    blocking = [g for g in guards if g["blocks_fork"]]
    if untrusted:
        trigger, line = untrusted[0]
        if blocking:
            weight, confidence, verdict = 2, "high", "context"
            closing = ("Gated by: " + "; ".join(sorted({g["guard"] for g in blocking}))
                       + " - the fork case this trigger exposes is already closed.")
        elif elevated_anywhere:
            weight, confidence, verdict = 7, "medium", "lead"
            closing = ("No check restricting this to the repository's own branches was "
                       "found, so what the privileged steps do with event data is worth "
                       "reading.")
        else:
            weight, confidence, verdict = 3, "medium", "context"
            closing = "Permissions are read-only, which limits what a fork could reach."
        out["notes"].append({
            "rule": "gha.privileged_trigger", "cat": "supply", "line": line,
            "title": "workflow runs with repository access on an untrusted event",
            "why": ("on: " + trigger + " is fired by " + UNTRUSTED_TRIGGERS[trigger]
                    + ", and the job runs against the base repository with " + top_perm
                    + ". " + closing),
            "weight": weight, "value": "trigger", "ref": "on." + trigger,
            "verdict": verdict, "confidence": confidence, "position": "on",
            "guards": [g["guard"] for g in guards],
        })
    seen_secret = set()
    for ref, line, where in secrets_used:
        if (ref, line) in seen_secret or len(seen_secret) >= 12:
            continue
        seen_secret.add((ref, line))
        signals.append({
            "rule": "gha.secret_use", "line": line,
            "title": ref + " passed to " + where,
            "detail": (ref + " is exposed to this step. That is a disclosure question - who "
                       "can read the logs, and can a step be influenced to print it - not an "
                       "injection one."),
        })

    # `--title "${{ github.ref_name }}" --body "... ${{ github.ref_name }}" --head
    # "${{ github.ref_name }}"` is one problem on one line, not three. Same rule, same
    # line, same reference means one row; the fix is the same for all of them.
    for key in ("findings", "notes"):
        seen: set = set()
        kept = []
        for item in out[key]:
            ident = (item.get("rule"), item.get("line"), item.get("ref"))
            if ident in seen:
                continue
            seen.add(ident)
            kept.append(item)
        out[key] = kept
    return out
