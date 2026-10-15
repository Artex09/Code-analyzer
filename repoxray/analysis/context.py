"""The context pass: deciding whether a pattern match means anything here.

Every pattern in the rule base is technically correct about what it matched. The gap
between "this matched" and "this is a finding" is security context, and this module is
where it gets applied. Six questions, each one a false positive observed on a real
repository:

1. **Did a reviewer already decide this?** `//nolint:gosec // Explicit no-tls-verify
   override for selected APIs.` - the directive was on the matched line and was ignored.
2. **Is this literal actually a secret?** `bordrless_token =
   "2XoEWp8cF3kRXg74eVwPAyTFhVCAztn3V88komxAvr22"` is a Solana program address: 44 base58
   characters, public by construction, printed in the project's own README.
3. **Is the capability corroborated?** `new RegExp(`^${name}:\\s*(\\S+)`)` was reported as
   ReDoS four times in one CLI. The pattern has no nested quantifier and `name` is a local
   constant.
4. **Is the setting on by default, or opt-in?** `InsecureSkipVerify: true` inside
   `if o.NoTLSVerify {` is a documented operator option, not a shipped weakness.
5. **Can this library do what the CWE claims?** `yaml.Unmarshal` in Go fills a struct. It
   is not CWE-502 and there is no code-execution path to find.
6. **Is there a victim?** SSRF needs an internal network to reach. A command-line tool run
   by its own user has neither a victim nor a remote attacker.
7. **Is this name that function?** `await exec(command, ["--version"])` is command
   injection only if `exec` is `child_process.exec`. In the repository where it was
   reported eight times it is `promisify(execFile)`, exported from a sibling module, and
   there is no shell in that path at all.

Nothing is deleted silently. A dismissed match keeps its line, its rule and the reason it
was dismissed, so the decision can be read back and argued with.
"""
from __future__ import annotations

import re

from . import annot, binding, deployment, semantics

MAX_DISMISSED_KEPT = 12        # per file, in the scan record; the count is always exact

# ----------------------------------------------------------------- small extractors

_ASSIGN = re.compile(
    r"(?P<name>[A-Za-z_$][\w.$\-]*)\s*(?:=|:|=>|:=)\s*"
    r"(?P<q>[\"'`])(?P<val>(?:(?!(?P=q)).)*)(?P=q)")
_REGEX_CALL = re.compile(r"new\s+RegExp\s*\(\s*(?P<body>(?:`[^`]*`|\"[^\"]*\"|'[^']*'|"
                         r"[A-Za-z_$][\w.$]*))")
# Names that mean "this value is a secret", used to corroborate weak randomness.
#
# Matched by splitting the identifier into words rather than with a regex, because a word
# boundary cannot see inside `generateResetToken` or `csrf_token`: `\b` needs a non-word
# character, and camelCase and snake_case have none. Splitting also stops `pin` matching
# `spinner` and `iv` matching `driver`, which is what the boundaries were there for.
_WORD_SPLIT = re.compile(r"[^A-Za-z]+|(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")

# a single one of these names is enough
SECRET_WORDS = frozenset({
    "token", "tokens", "secret", "secrets", "password", "passwords", "passwd", "pwd",
    "nonce", "salt", "csrf", "xsrf", "otp", "pin", "iv", "coupon", "voucher",
    "entropy", "seed", "apikey", "uuid", "guid", "jwt", "cookie", "sessionid",
})
# these mean a secret only together, so `apiKey` counts and `keyboard` does not
SECRET_PAIRS = frozenset({
    frozenset({"api", "key"}), frozenset({"private", "key"}),
    frozenset({"secret", "key"}), frozenset({"signing", "key"}),
    frozenset({"encryption", "key"}), frozenset({"session", "key"}),
    frozenset({"session", "id"}), frozenset({"reset", "code"}),
    frozenset({"auth", "code"}), frozenset({"access", "code"}),
    frozenset({"invite", "code"}), frozenset({"verification", "code"}),
    frozenset({"recovery", "code"}), frozenset({"backup", "code"}),
    frozenset({"reset", "link"}), frozenset({"magic", "link"}),
    frozenset({"confirmation", "code"}), frozenset({"activation", "code"}),
})


def name_words(text: str) -> frozenset:
    """The lowercase words in an identifier, split on case, digits and punctuation."""
    return frozenset(w.lower() for w in _WORD_SPLIT.split(text) if w)


def security_meaning(text: str) -> str:
    """The name that makes this value a secret, or "" if nothing does."""
    words = name_words(text)
    hit = words & SECRET_WORDS
    if hit:
        return sorted(hit)[0]
    for pair in SECRET_PAIRS:
        if pair <= words:
            return " ".join(sorted(pair))
    return ""
_FETCH_URL = re.compile(r"(?:axios|fetch|superagent|needle|undici|got|request)\s*"
                        r"(?:\.\s*\w+)?\s*\(\s*(?P<body>`[^`]*`|[A-Za-z_$][\w.$]*)")
# Directories the system owns under /tmp. `Path("/tmp/.X11-unix")` is the X11 socket
# directory: root-owned, sticky-bit, and already there. Naming it is not a TOCTOU.
_SYSTEM_TMP = re.compile(
    r"/tmp/\.(?:X11|ICE|XIM|font|Test)-unix|/tmp/\.X\d+-lock|"
    r"/tmp/(?:\.esd|\.s\.PGSQL|systemd-private)")
# `subprocess.run([prog, "-f", path], ...)` - a vector, with no shell to parse it. The
# snippet is one line, so the opening bracket is what there is to see; a call written
# across several lines shows `subprocess.run(` followed by nothing, and stays undecided.
_ARGV_LIST = re.compile(r"(?:run|call|check_call|check_output|Popen)\s*\(\s*[\[(]")
_SHELL_TRUE = re.compile(r"shell\s*=\s*True")
# what turns a path into a file
_TMP_CREATES = re.compile(
    r"\b(?:open|mkdir|makedirs|touch|write_text|write_bytes|create|NamedTemporaryFile|"
    r"mkstemp|mkdtemp|copy|copyfile|move|rename|symlink|link|unlink|remove|chmod|"
    r"fdopen|socket|bind)\s*\(|>\s*/tmp/|>>\s*/tmp/")

# the name sitting in the format slot, whichever position that is for this function
_FORMAT_ARG = re.compile(
    r"\b(?:v?printf|v?wprintf)\s*\(\s*(?P<fmt>[A-Za-z_]\w*)|"
    r"\b(?:v?fprintf|v?sprintf|v?fwprintf|syslog|asprintf|dprintf)\s*\([^,()\"\n]{1,80},"
    r"\s*(?P<fmt2>[A-Za-z_]\w*)|"
    r"\b(?:v?snprintf|v?swprintf)\s*\([^,()\"\n]{1,80},[^,()\"\n]{1,40},"
    r"\s*(?P<fmt3>[A-Za-z_]\w*)")


# the vocabulary `sec.assign` fires on; used to pick the right pair out of a line that
# holds several, so a struct literal is classified on `PrivateKey: "..."` and not on the
# `Name: "test"` that happens to come first
_CRED_NAME = re.compile(
    r"api[_\-]?key|apikey|secret|password|passwd|pwd|token|credential|"
    r"private[_\-]?key|access[_\-]?key|auth[_\-]?key|client[_\-]?secret", re.I)


def _literal_of(snippet: str) -> tuple:
    """(name, value) for the credential-shaped assignment on a line, else ("", "").

    A line can hold several assignments. The one to classify is the one the rule matched,
    so the credential-named pair wins over whichever pair comes first.
    """
    pairs = [(m.group("name"), m.group("val")) for m in _ASSIGN.finditer(snippet)]
    if not pairs:
        return "", ""
    for name, value in pairs:
        if _CRED_NAME.search(name):
            return name, value
    return pairs[0]


def _record(analysis: dict, key: str, entry: dict) -> None:
    analysis.setdefault(key, []).append(entry)


def _dismiss(state: dict, hit: dict, why: str, kind: str) -> None:
    """Remove a match from scoring, keeping it visible with its reason."""
    state["dismissed"].append({
        "line": hit["line"], "rule": hit["rule"], "cat": hit["cat"],
        "title": hit["title"], "snippet": hit.get("snippet", ""),
        "why": why, "kind": kind,
    })
    state["drop_lines"].add((hit["line"], hit["rule"]))


def _demote(hit: dict, why: str, cap: int = 3) -> None:
    hit["tier"] = "context"
    hit["weight"] = min(hit["weight"], cap)
    hit["why"] = why
    hit["adjusted"] = True


# =====================================================================  the pass

_IDENTITY_IS = {
    binding.SHELL: "a call that hands a string to a shell",
    binding.ARGV: "a call that starts a process",
    binding.DB: "a database query",
    binding.CODE: "an evaluator",
    binding.HTTP: "an HTTP request",
}

_CALLEE = re.compile(
    r"(?P<callee>/(?:[^/\\\n]|\\.)+/[a-z]*|new\s+RegExp\s*\([^()\n]*\)|"
    r"[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\(")


def _identity_verdict(snippet: str, expect: str, callees: dict):
    """(reason,) when every resolvable call on this line is the wrong kind of function.

    A line can hold several calls. The rule is wrong only if nothing on it is the thing
    the rule is about; one unresolved name is enough to leave the match standing, because
    an unresolved name is not evidence either way.
    """
    reason = ""
    for m in _CALLEE.finditer(snippet):
        got = binding.callee_family(m.group("callee"), callees)
        if got is None or not got.family:
            continue
        if got.family == expect:
            return None
        if not reason:
            reason = ("`" + m.group("callee").strip() + "` here is " + got.detail
                      + (" (" + got.where + ")" if got.where else "") + ".")
    return (reason,) if reason else None


def apply(rec: dict, text: str, code: str, lang: str, hits: list,
          per_rule_contrib: dict, cat_weight: dict, sources: list,
          guards: dict, dep_ctx, analysis: dict, rules_mod, callees=None,
          misidentified=()) -> dict:
    """Adjust `hits` in place. Returns {"dismissed": [...], "notes": [...]}.

    `guards` is {line: reach.Reach} from the AST pass, `dep_ctx` the deployment Context,
    `callees` the {name: binding.Bound} map of what the file's names actually refer to,
    `rules_mod` the rules module (passed in to keep this module free of a circular import).
    """
    callees = callees or {}
    state = {"dismissed": [], "drop_lines": set(), "notes": []}
    lines = text.splitlines()
    # Sinks the dataflow engine declined because the name is a different function. They
    # never became hits, so there is nothing to remove - but they are decisions, and a
    # decision that leaves no trace is indistinguishable from a blind spot.
    for ln, sink_id, why in misidentified:
        state["dismissed"].append({
            "line": ln, "rule": "taint." + sink_id, "cat": "", "title": "sink matched by name",
            "snippet": lines[ln - 1].strip()[:160] if 0 < ln <= len(lines) else "",
            "why": why + ".", "kind": "wrong-function",
        })
    annots = annot.scan(text)
    has_source = bool(sources)
    scale: dict = {}         # rule -> multiplier applied to its score contribution

    file_ctx = deployment.for_file(dep_ctx, rec["path"], code) if dep_ctx else None
    if file_ctx is not None and dep_ctx is not None and file_ctx.kind != dep_ctx.kind:
        state["notes"].append("Treated as " + file_ctx.human + " rather than "
                              + dep_ctx.human + ": " + (file_ctx.evidence[0]
                                                        if file_ctx.evidence else ""))

    for hit in list(hits):
        rule_id = hit["rule"]
        cat = hit["cat"]
        line = hit["line"]
        snippet = hit.get("snippet", "")

        # ---- 1. a reviewer's own decision, recorded in the code -----------------
        ann = annot.covering(annots, line, cat)
        if ann is not None:
            if ann.explained:
                _dismiss(state, hit, ann.describe() + " The decision is recorded in the "
                         "code, so this is not an open finding. It is still worth "
                         "checking that the stated reason still holds.", "reviewed")
                continue
            _demote(hit, "This line matched " + hit["title"] + ", and " + ann.describe()
                    + " A silenced warning with no stated reason is worth a look, but it "
                      "is not evidence of a vulnerability on its own.", cap=3)
            _record(analysis, "annotated", {"line": line, "rule": rule_id,
                                            "tool": ann.tool, "explained": False})
            scale[rule_id] = min(scale.get(rule_id, 1.0), 0.2)
            continue

        # ---- 2. is this literal a credential? -----------------------------------
        if cat == "secret" and rule_id in ("sec.assign", "sec.jwt_literal"):
            name, value = _literal_of(snippet)
            if value:
                declared = annot.meaning_near(lines, line)
                lit = semantics.classify_literal(value, name, declared)
                if lit.kind in ("public", "identifier"):
                    _dismiss(state, hit,
                             "`" + name + "` is assigned a literal, but " + lit.why
                             + ". A name containing \"token\" or \"key\" does not make the "
                               "value a credential; the encoding decides, and this "
                               "encoding is not one a secret comes in.", "not-a-secret")
                    continue
                if lit.kind == "placeholder":
                    _dismiss(state, hit, "`" + name + "` is assigned a literal, but "
                             + lit.why + ".", "placeholder")
                    continue
                if lit.kind == "unknown":
                    _demote(hit, "`" + name + "` is assigned a literal and " + lit.why
                            + ". That is not enough to call it a credential or to clear "
                              "it; read the value and decide.", cap=4)
                    scale[rule_id] = min(scale.get(rule_id, 1.0), 0.4)
                    continue
                hit["why"] = ("`" + name + "` is assigned a literal and " + lit.why + ".")
                hit["confirmed_secret"] = True

        # ---- 2b. is this name the function the rule is about? ------------------
        expect = rules_mod.IDENTITY_RULES.get(rule_id)
        if expect is not None:
            verdict = _identity_verdict(snippet, expect, callees)
            if verdict is not None:
                _dismiss(state, hit, verdict[0] + " The rule looks for "
                         + _IDENTITY_IS.get(expect, expect) + ", and matched the name "
                         "rather than the function. Nothing here reaches "
                         + _IDENTITY_IS.get(expect, expect) + ".", "wrong-function")
                continue

        # ---- 3. capability rules need corroboration ----------------------------
        if rule_id in rules_mod.CAPABILITY_RULES:
            # A call written across several lines shows only `subprocess.run(` on the
            # matched line, so the corroborator gets the continuation too. Four lines is
            # enough for an argument vector and short enough not to pull in the next
            # statement's meaning.
            window = "\n".join(lines[line - 1:line + 4]) if 0 < line <= len(lines) \
                else snippet
            verdict = _corroborate(rule_id, cat, snippet, code, has_source, lang,
                                   guards.get(line), window)
            if verdict is not None:
                keep, why, cap = verdict
                if not keep:
                    _dismiss(state, hit, why, "capability")
                    continue
                _demote(hit, why, cap=cap)
                scale[rule_id] = min(scale.get(rule_id, 1.0), 0.3)

        # ---- 4. a setting: always on, or opt-in? -------------------------------
        if rule_id in rules_mod.SETTING_RULES:
            info = guards.get(line)
            if info is not None:
                if info.opt_in:
                    _dismiss(state, hit,
                             hit["title"] + " is real, and it is " + info.describe()
                             + ". That makes it a documented capability the operator asks "
                               "for, not a weakness every caller gets. It becomes a "
                               "finding if an attacker can set that option - check who "
                               "writes it.", "opt-in")
                    continue
                if any(g.kind == "request" for g in info.guards):
                    hit["weight"] = min(10, hit["weight"] + 1)
                    hit["why"] = (hit["why"] + " This setting sits behind a condition that "
                                  "reads request data (" + info.describe() + "), so a "
                                  "caller may be able to turn it on.")
                elif info.unconditional:
                    hit["why"] = (hit["why"] + " Nothing guards this line: "
                                  + info.describe() + ", so every caller gets it.")
                    hit["unconditional"] = True

        # ---- 5. does the library have the power the CWE claims? ----------------
        power = rules_mod.DESER_POWER.get(rule_id)
        if power is not None:
            kind, why = power
            if kind == "type":
                hit["why"] = ("This decodes untrusted bytes, and " + why + ". The real "
                              "questions are whether the input is size- and depth-limited "
                              "and whether the decoded values are validated.")
                hit["weight"] = min(hit["weight"], 3)
                hit["tier"] = "context"
                hit["adjusted"] = True
                scale[rule_id] = min(scale.get(rule_id, 1.0), 0.5)
            elif kind == "entity":
                hit["why"] = "This parser resolves external entities, so " + why + "."
            else:
                hit["why"] = hit["why"] + " " + why.capitalize() + "."

        # ---- 6. is there a victim in this deployment? -------------------------
        if file_ctx is not None:
            factor, reason = deployment.gate(cat, file_ctx)
            if factor == 0.0:
                _dismiss(state, hit,
                         hit["title"] + " needs someone to attack. This repository is "
                         + file_ctx.human + " and " + reason + ".", "no-victim")
                continue
            if factor < 1.0:
                hit["why"] = hit["why"] + " In " + file_ctx.human + ", " + reason + "."
                hit["gated"] = reason
                scale[rule_id] = min(scale.get(rule_id, 1.0), factor)

    # ---- apply the removals and the score scaling -----------------------------
    if state["drop_lines"]:
        keep = []
        for hit in hits:
            if (hit["line"], hit["rule"]) in state["drop_lines"]:
                continue
            keep.append(hit)
        hits[:] = keep
        # a rule with no surviving hit contributes nothing
        alive = {h["rule"] for h in hits}
        for rule_id in list(per_rule_contrib):
            if rule_id not in alive:
                per_rule_contrib.pop(rule_id, None)
    for rule_id, factor in scale.items():
        if rule_id in per_rule_contrib:
            per_rule_contrib[rule_id] = round(per_rule_contrib[rule_id] * factor, 2)
    # recompute category weights from what survived
    cat_weight.clear()
    for rule_id, contrib in per_rule_contrib.items():
        rule = rules_mod.COMPILED_BY_ID.get(rule_id)
        if rule is None:
            continue
        cat_weight[rule["cat"]] = round(cat_weight.get(rule["cat"], 0) + contrib, 2)

    # Counted before the list is trimmed below, so the totals the report prints are the
    # real ones even where the per-file list is not the whole story.
    analysis["dismissed"] = len(state["dismissed"])
    if state["dismissed"]:
        analysis["dismissed_kinds"] = sorted({d["kind"] for d in state["dismissed"]})
        by_kind: dict = {}
        for item in state["dismissed"]:
            by_kind[item["kind"]] = by_kind.get(item["kind"], 0) + 1
        analysis["dismissed_by"] = by_kind
    # A shell-heavy repository can produce a thousand correctly-quoted `rm "$x"` lines in
    # one file. They are all dismissed for the same reason, so keeping every one of them
    # in the scan record buys nothing and costs megabytes; the count and the reasons stay.
    if len(state["dismissed"]) > MAX_DISMISSED_KEPT:
        extra = len(state["dismissed"]) - MAX_DISMISSED_KEPT
        state["dismissed"] = state["dismissed"][:MAX_DISMISSED_KEPT]
        state["notes"].append(
            str(extra) + " further pattern " + ("match was" if extra == 1 else "matches were")
            + " ruled out for the same reasons and are not listed individually.")
    return state


# -------------------------------------------------------------- corroboration rules

def _corroborate(rule_id: str, cat: str, snippet: str, code: str,
                 has_source: bool, lang: str, info=None, window: str = ""):
    """(keep, why, weight_cap) for a capability rule, or None to leave it alone.

    `info` is the `reach.Reach` for the line when the caller asked for it, which carries
    the enclosing function name - the difference between `random()` inside
    `generateResetToken` and the same call inside `pickBackgroundColour`.
    `window` is the matched line plus the next few, for a call whose arguments are on
    other lines than its name.
    """
    window = window or snippet

    # --- a regex built at runtime is only ReDoS if it can backtrack
    if rule_id == "js.regex_dyn":
        m = _REGEX_CALL.search(snippet)
        body = m.group("body") if m else snippet
        shape = semantics.redos_shape(body.strip("`\"'"))
        if shape.risk == "catastrophic":
            return True, ("A regex is built at runtime and " + shape.why
                          + ". If untrusted input reaches the subject this is a denial of "
                            "service."), 7
        if shape.risk == "benign":
            return False, ("A regex is built at runtime, but " + shape.why
                           + ", so neither ReDoS nor a filter bypass applies here."), 0
        if shape.risk == "injectable":
            if not has_source:
                return True, ("The caller supplies this entire pattern, and " + shape.why
                              + " No untrusted input is read in this file, so the pattern "
                                "comes from its own code - but any caller of this function "
                                "can choose it."), 5
            return True, ("The caller supplies this entire pattern: " + shape.why), 7
        if shape.risk == "polynomial":
            if not has_source:
                return False, ("A regex is built at runtime and " + shape.why
                               + ", but nothing untrusted is read in this file, so there "
                                 "is no long crafted subject to feed it."), 0
            return True, ("A regex is built at runtime and " + shape.why), 5
        # shape.risk == "dynamic"
        if not has_source:
            return False, ("A regex is built at runtime: " + shape.why
                           + ". No untrusted input is read anywhere in this file, so "
                             "nothing attacker-controlled reaches the spliced value, and "
                             "the pattern itself cannot backtrack."), 0
        return True, ("A regex is built at runtime: " + shape.why
                      + ". This file does read untrusted input, so check whether it "
                        "reaches the spliced value - that would be a filter bypass "
                        "rather than a denial of service."), 4

    # --- an outbound request to a computed URL is SSRF only with a victim and a source
    if rule_id in ("js.fetch_var", "go.ssrf", "java.ssrf"):
        if not has_source:
            return False, ("This file makes an outbound request to a URL it builds, and "
                           "reads no untrusted input anywhere, so the target is its own "
                           "configuration. A dynamic URL is how every HTTP client is "
                           "written; it is not SSRF without an attacker-controlled "
                           "host."), 0
        return True, ("This file makes an outbound request to a computed URL and does read "
                      "untrusted input; trace whether the two meet."), 5

    # --- a shell variable is only a splitting risk when it is actually unquoted
    if rule_id == "sh.var_cmd":
        risky, why = semantics.shell_word_split_risk(snippet)
        if not risky:
            return False, ("The rule looks for an unquoted expansion, and " + why
                           + ", so there is nothing here to split or inject."), 0
        return True, ("A command runs with an unquoted expansion: " + why + "."), 5

    # --- weak randomness matters where the value is a secret, not where it is a jitter
    if rule_id in ("py.weak_random", "js.math_random"):
        where = snippet + " " + (info.function if info is not None else "")
        meaning = security_meaning(where)
        if meaning:
            return True, ("A predictable generator produces a value named for a secret "
                          "(\"" + meaning + "\"), which makes it guessable by anyone who "
                          "can see or request one."), 6
        return False, ("A non-cryptographic generator here produces a value with no "
                       "security meaning beside it - a jitter, a sample, a colour, a "
                       "unique-enough filename. It is a weakness when the output is a "
                       "token, a nonce, a password or a key, and nothing here says it "
                       "is."), 0

    # --- a computed file path needs an untrusted component
    if rule_id in ("py.open_var", "js.fs_var", "rb.send_file"):
        if not has_source:
            return False, ("A file path is built at runtime and this file reads no "
                           "untrusted input, so the path comes from its own code or "
                           "configuration."), 0
        return None

    # --- a predictable temp path is a weakness when this program creates the file
    if rule_id == "py.mktemp":
        if _SYSTEM_TMP.search(snippet):
            return False, ("This names one of the sockets directories the system creates "
                           "under /tmp - root-owned with the sticky bit set, and there "
                           "before this program starts. Referring to it is not the "
                           "predictable-temp-file weakness; creating a file at a guessable "
                           "path is."), 0
        if "mktemp" in snippet:
            return True, ("`tempfile.mktemp` returns a name and does not hold it, so "
                          "anything can take the path between the two calls. "
                          "`NamedTemporaryFile` or `mkstemp` return an open handle "
                          "instead."), 6
        if not _TMP_CREATES.search(snippet):
            return False, ("A constant naming a path under /tmp is not yet a file. "
                           "Nothing on this line creates or opens it, so there is no "
                           "window for anything to be substituted - find the line that "
                           "writes to it and judge that one."), 0
        return True, ("A file is created at a fixed path under /tmp, where any local user "
                      "can place a symlink first."), 5

    # --- a format string held in a variable is usually a macro, and needs a source
    if rule_id == "c.format":
        m = _FORMAT_ARG.search(snippet)
        arg = (m.group("fmt") or m.group("fmt2") or m.group("fmt3")) if m else ""
        if arg and arg.isupper():
            return False, ("The format argument is `" + arg + "`, an upper-case name, "
                           "which is how C spells a compile-time constant. A format "
                           "string only becomes a weakness when its *text* comes from "
                           "input."), 0
        if not has_source:
            return False, ("The format string is a variable rather than a literal, which "
                           "is worth knowing, but nothing untrusted is read in this file, "
                           "so there is no input to put %n in it."), 0
        return True, ("The format string is a variable and this file reads untrusted "
                      "input. If the two meet, %n writes to memory and %s reads it."), 6

    # --- C memory operations are what C is
    if rule_id in ("c.mem_ops", "c.alloc_math"):
        if not has_source:
            return False, ("Pointer and length arithmetic is how C is written. Nothing "
                           "untrusted is read in this file, so there is no input to "
                           "overflow it with."), 0
        return None

    if rule_id == "py.subprocess_var":
        if _SHELL_TRUE.search(window):
            return True, ("`shell=True` hands the whole string to a shell, so a variable "
                          "in it is a command, not an argument."), 7
        if _ARGV_LIST.search(window):
            return False, ("The arguments are given as a list, and without `shell=True` "
                           "Python passes that list straight to execvp - no shell parses "
                           "it, so a value holding ; or $( ) arrives at the program as "
                           "one literal argument. What is left is argument injection, "
                           "which depends on what that program does with the value."), 0
        if not has_source:
            return False, ("A command is assembled from variables and this file reads no "
                           "untrusted input, so the arguments come from its own code."), 0

    return None
