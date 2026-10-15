"""The cases from the field reports, each one a false positive seen on a real repository.

Every case names the file it came from. A case that passes here is a mistake the tool has
stopped making; a case that fails is a regression in something a user already complained
about once.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from repoxray import rules, strip                                         # noqa: E402
from repoxray.analysis import (annot, binding, context, deployment,       # noqa: E402
                               reach, semantics)
from repoxray.analysis.langs import javascript, python                    # noqa: E402

FAIL: list = []


def check(name: str, got, want, note: str = "") -> None:
    ok = got == want
    print(("  pass  " if ok else "  FAIL  ") + name
          + ("" if ok else "\n          got  " + repr(got)
             + "\n          want " + repr(want)))
    if note and not ok:
        print("          " + note)
    if not ok:
        FAIL.append(name)


def truthy(name: str, got, note: str = "") -> None:
    check(name, bool(got), True, note)


def _corr(rule_id: str, cat: str, snippet: str, code: str, has_source: bool,
          lang: str = "python", info=None, window: str = ""):
    """(keep, why, cap) from the corroborator, or (None, "", 0) when it has no opinion."""
    got = context._corroborate(rule_id, cat, snippet, code, has_source, lang, info, window)
    return got if got is not None else (None, "", 0)


def falsy(name: str, got, note: str = "") -> None:
    check(name, bool(got), False, note)


# ===================================================== 1. literal value semantics
print("\nliterals - is this string a credential?")

# nebius/BordrlessDex: programs.ts and Anchor.toml, reported as CWE-798 at weight 7
SOLANA = "2XoEWp8cF3kRXg74eVwPAyTFhVCAztn3V88komxAvr22"
lit = semantics.classify_literal(SOLANA, "bordrless_token")
check("solana program address is not a secret", lit.kind, "public",
      "44 base58 chars is a 32-byte public key; the name 'token' must not override that")
check("  ... and it says why", "public key" in lit.why, True)

lit = semantics.classify_literal(SOLANA, "api_key")
check("even assigned to api_key it stays public", lit.kind, "public",
      "the encoding decides, not the identifier")

# the same alphabet, the length that means a private key
lit = semantics.classify_literal("5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3",
                                 "k")
check("base58 WIF private key IS a secret", lit.kind, "secret")

for value, name, want in (
        ("ghp_abcdefghij0123456789ABCDEFGHIJ0123", "t", "secret"),
        ("AKIAIOSFODNN7EXAMPLE", "k", "secret"),
        ("sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaaaaa", "k", "secret"),
        ("-----BEGIN RSA PRIVATE KEY-----", "k", "secret"),
        ("postgres://user:hunter2@db:5432/x", "dsn", "secret"),
        ("your-api-key-here", "api_key", "placeholder"),
        ("changeme123456", "password", "placeholder"),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha", "public"),
        ("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "addr", "public"),
        ("550e8400-e29b-41d4-a716-446655440000", "id", "identifier"),
        ("https://api.example.com/v1", "endpoint", "identifier"),
        ("1.2.3", "version", "identifier"),
        ("8Hk2Lm9Qw4Rt7Yu1Iop3AsdFghJklZxc", "client_secret", "secret"),
):
    check("literal " + repr(value[:28]), semantics.classify_literal(value, name).kind, want)

# morluto/rea: the same stand-in in eight verify-*-client.mjs files, reported as CWE-798
# at medium. Shannon entropy over seventeen characters called it high-entropy; it is three
# English words, and one of them is the answer.
for value, name in (("local-fixture-key", "OPENAI_API_KEY"),
                    ("local-fixture-only", "COMMAND_CODE_API_KEY"),
                    ("local-fixture-key", "apiKey")):
    lit = semantics.classify_literal(value, name)
    check("fixture stand-in " + repr(value), lit.kind, "placeholder",
          "the value names itself; a generated credential has no vocabulary")

# ... but a multi-word value with no such marker is NOT cleared. It is left open, because
# entropy cannot tell a passphrase from a stand-in and neither can this.
lit = semantics.classify_literal("correct-horse-battery-staple", "password")
check("an unmarked passphrase is left open", lit.kind, "unknown",
      "dismissing this would be the same mistake in the other direction")
truthy("  ... and says why", "spells words" in lit.why)
check("a generated key is still a secret",
      semantics.classify_literal("4eC39HqLyjWDarjtT1zdp7dc", "apiKey").kind, "secret",
      "mixed case and digits in one run is a generator, not a typist")

# the comment above the line said so outright, in a negative sentence
FIXTURE_COMMENT = [
    "  // Native print mode checks for an account key even with a keyless BYOK model.",
    "  // This synthetic value is never a real credential; local-only refuses API calls.",
    '  COMMAND_CODE_API_KEY: "local-fixture-only",',
]
check("the comment declares it a stand-in", annot.meaning_near(FIXTURE_COMMENT, 3),
      "placeholder")
check("a negated secret claim is not a secret claim",
      annot.meaning_near(["// this is never a real key", 'K = "x"'], 2), "placeholder",
      "SECRET_MEANING reads 'real key' and would have said secret")
check("an actual secret claim still reads as one",
      annot.meaning_near(["// real key - do not commit", 'K = "x"'], 2), "secret")


# ===================================================== 1b. who is this name?
print("\ncallee identity - is `exec` child_process.exec?")

# morluto/rea: `exec` is `promisify(execFile)` exported from scripts/lib/
# verify-package-core.mjs. Reported as CWE-78 in eight files; there is no shell in that
# path at all. And `const execute = promisify(execFile)` on line 18 of verify-go-binary.mjs
# was reported as SQL injection, because `execute` is also a database method.
CORE = 'import { execFile } from "node:child_process";\n' \
       'import { promisify } from "node:util";\n' \
       'export const exec = promisify(execFile);\n'
CLIENT = 'import { exec } from "./lib/verify-package-core.mjs";\n' \
         'const r = await exec(command, ["--version"], { env });\n'


def _read_core(path: str) -> str:
    return CORE if path == "scripts/lib/verify-package-core.mjs" else ""


bound = binding.resolve(CLIENT, "javascript", "scripts/verify-client.mjs", _read_core)
truthy("the import is followed to the sibling module", "exec" in bound)
check("  ... and `exec` is an argv call, not a shell",
      bound["exec"].family if "exec" in bound else "", binding.ARGV)
check("  ... naming the definition it read",
      bound["exec"].where if "exec" in bound else "",
      "scripts/lib/verify-package-core.mjs:3")

local = binding.resolve('const execute = promisify(execFile);\n'
                        'import { execFile } from "node:child_process";\n',
                        "javascript", "scripts/verify-go-binary.mjs")
check("a local promisify(execFile) resolves whichever order it sits in",
      local["execute"].family if "execute" in local else "", binding.ARGV,
      "the definition is above the import in the real file")

# the identity question answers itself for a regex receiver, with no bindings at all
got = binding.callee_family("/^(-?)([0-9]+)$/u.exec", {})
check("RegExp.prototype.exec is not command execution",
      got.family if got else "", binding.REGEX,
      "QlogCapture.ts scored 44.6 on one `.exec` call against a regex literal")
held = binding.resolve("const NUM = /^(-?)([0-9]+)$/u;\n", "javascript")
check("a regex kept in a const is still a regex one call later",
      (binding.callee_family("NUM.exec", held) or binding.Bound("x")).family,
      binding.REGEX, "the same mistake, one assignment removed")
check("child_process.exec still is",
      (binding.callee_family("cp.exec", binding.resolve(
          'import * as cp from "node:child_process";\n', "javascript")) or
       binding.Bound("x")).family, binding.SHELL)
falsy("an unresolved name gets the benefit of the doubt",
      binding.callee_family("runSomething", {}),
      "no opinion must mean no change, or the resolver becomes a suppression list")

# the sink declarations that make the engine ask at all
check("js.exec claims to be a shell",
      [s for s in javascript.SINKS if s.id == "js.exec"][0].identity, binding.SHELL)
check("js.sql claims to be a database call",
      [s for s in javascript.SINKS if s.id == "js.sql"][0].identity, binding.DB)


# ===================================================== 1c. code or text?
print("\ncode vs text - is this eval in this file?")

# morluto/rea verify-qwen-client.mjs:290 - a command line for a child process, quoted
QUOTED = 'const c = `node -e "eval(Buffer.from(\'${enc}\',\'base64\').toString())"`;\n'
spans = strip.string_spans(QUOTED, "javascript")
truthy("an eval inside a quoted command line is text",
       strip.inside(spans, QUOTED.index("eval(Buffer")))
falsy("a real eval is still code",
      strip.inside(strip.string_spans("x = eval(req.body.q);\n", "javascript"),
                   len("x = ")))
falsy("and so is one inside an interpolation hole",
      strip.inside(strip.string_spans("const h = `a ${eval(y)} b`;\n", "javascript"),
                   len("const h = `a ${")),
      "`${...}` is this file's code, not the template's text")
truthy("js.eval is one of the rules that asks", "js.eval" in rules.CODE_TEXT_RULES)


# ===================================================== 1d. format strings
print("\nformat strings - which argument is the format?")

# morluto/rea native/windows/src/addon.cc:123/129/131/134/137, reported as CWE-787.
# Every format string in that file is a literal; the rule matched `stderr`.
FMT = rules.COMPILED_BY_ID["c.format"]["rx"]
for line in ('std::fprintf(stderr, "cleanup failed (Win32 %lu) path=\\"", code);',
             'std::fprintf(stderr, "\\\\u%04x", static_cast<unsigned>(unit));',
             'std::fprintf(stderr, "cleanup failed: %s\\n", failure.what());',
             'printf("hello %s", name);',
             'snprintf(buf, sizeof(buf), "%d", n);',
             'syslog(LOG_ERR, "bad login from %s", host);'):
    falsy("literal format: " + line[:40], FMT.search(line),
          "fprintf/sprintf/syslog take the format second, snprintf third")
for line in ('printf(user_input);', 'fprintf(stderr, user_format, x);',
             'sprintf(buf, fmt, x);', 'snprintf(buf, sizeof buf, fmt, x);',
             'fprintf(f, cfg->tmpl, x);', 'printf(argv[1]);'):
    truthy("variable format: " + line[:40], FMT.search(line))
check("and it is filed as a format-string bug",
      rules.COMPILED_BY_ID["c.format"]["cwe"], "CWE-134",
      "it was CWE-787, out-of-bounds write, which is a different weakness")


# ===================================================== 1e. phantom param sources
print("\nparameter sources - does the framework exist in this file?")

# morluto/rea bridge/pwndbg/core_context.py: `request` is the parsed JSON of a debugger
# request file. The engine called it a flask request and reported `exec(compile(...))` as
# a web RCE at weight 9, in a repository with no web framework anywhere.
FLASK = [p for p in python.PARAM_SOURCES if p.id == "py.flask_req"][0]
truthy("the flask param source demands flask in the file", FLASK.requires)
falsy("  ... which a gdb bridge does not have",
      re.search(FLASK.requires, 'request = json.loads(path.read_bytes())\n'
                                'entry = request["gdbinit"]\n'))
truthy("  ... but a flask app does",
       re.search(FLASK.requires, "from flask import request, Flask\n"))
check("a declared type still needs no corroboration",
      bool(re.search(FLASK.type_pattern, "flask.Request")), True,
      "a type names the framework itself; only the name is a convention")
for src_id, spec_mod in (("js.express", javascript), ("js.koa", javascript),
                         ("js.lambda", javascript)):
    src = [p for p in spec_mod.PARAM_SOURCES if p.id == src_id][0]
    truthy("every name-based source is gated: " + src_id, src.requires)


# ===================================================== 1f. temp paths and argv vectors
print("\ncapability vs misuse - two more from the same report")

# morluto/rea scripts/hopper-demo-x11.py:39 and :479
check("the X11 socket directory is not a predictable temp file",
      _corr("py.mktemp", "race", 'X11_SOCKET_DIRECTORY = Path("/tmp/.X11-unix")',
            "", True)[0], False,
      "root-owned with the sticky bit, and there before this program starts")
check("a constant naming a path under /tmp creates nothing",
      _corr("py.mktemp", "race", 'LOCK = "/tmp/myapp.lock"', "", True)[0], False)
check("  ... but opening one does",
      _corr("py.mktemp", "race", 'fh = open("/tmp/myapp.lock", "w")', "", True)[0], True)
check("tempfile.mktemp is still the real thing",
      _corr("py.mktemp", "race", "p = tempfile.mktemp()", "", True)[0], True)

check("subprocess with an argument list is not command injection",
      _corr("py.subprocess_var", "cmd", "authorized = subprocess.run(", "", True,
            window='authorized = subprocess.run(\n    [\n        xauth_path,\n'
                   '        "-f",\n        str(authority),')[0], False,
      "no shell parses an argv vector, so `;` arrives as one literal argument")
check("  ... and shell=True still is",
      _corr("py.subprocess_var", "cmd", 'subprocess.run(cmd, shell=True)', "", True)[0],
      True)


# ===================================================== 2. regex shape (ReDoS)
print("\nregex shape - is new RegExp(var) really ReDoS?")

# bordrless.ts:204 and studio.ts:664/782/817, reported four times as CWE-400
for template, want in (
        # bordrless.ts:204 and studio.ts:664/782/817 - a fixed skeleton with a name
        # spliced in. `\s*` beside `(\S+)` is two quantifiers over disjoint classes, so
        # there is nothing to backtrack between: not ReDoS, whatever `name` holds.
        (r"^${name}:\s*(\S+)", "dynamic"),
        (r"\bfn\s+${name}\s*\(", "dynamic"),
        (r"\b${name}\s*::\s*new\s*\(", "dynamic"),
        (r"\bconst\s+${name[1]}\s*:\s*[A-Za-z0-9_:<>]+\s*=([^;]+)", "dynamic"),
        # the pattern IS the variable: whoever calls this chooses the shape
        (r"${pattern}", "injectable"),
        (r"^${userRe}$", "injectable"),
        # genuinely exponential skeletons
        (r"^(a+)+$", "catastrophic"),
        (r"(\w|\d)+@", "catastrophic"),
        (r"^${x}(.*)*$", "catastrophic"),
        # quadratic: two overlapping unbounded classes in a row
        (r"\w+\w+!", "polynomial"),
        (r".*.*=", "polynomial"),
        # constant and safe
        (r"^[a-z]+$", "benign"),
        (r"^\s*(\S+)\s*$", "benign"),
):
    check("regex " + repr(template[:34]), semantics.redos_shape(template).risk, want)


# ===================================================== 3. shell quoting
print("\nshell quoting - is the variable actually unquoted?")

# toolchain.sh / programs.sh: five hits on correctly quoted lines
for line, want in (
        ('rm -f "$file"', []),
        ('rm -rf "$dest"', []),
        ('mv "$tmp/x${member:+/$member}" "$dest"', []),
        ('cp "$key" "$DEPLOY_DIR/$program-keypair.json"', []),
        ('tar --no-same-owner -xjf "$archive" -C "$tmp/x"', []),
        ('rm -f $file', ["file"]),
        ('curl $URL -o out', ["URL"]),
        ("rm -f '$file'", []),
        ('rm -f "$a" $b', ["b"]),
        ('echo "hi" # rm -rf $HOME', []),
        # omarchy: `[[ ]]` is a bash keyword and does not word-split, so the test on the
        # left of the && must not be read as an unquoted command argument
        ('[[ -n $browser ]] && rm -f "$browser"', []),
        ('[[ -n $home && -d $home ]] && rm -rf "$home"', []),
        ('[[ -f $root/icon.txt ]] && cp "$root/icon.txt" "$HOME/x"', []),
        # a quoted array expansion is the correct way to pass a list, not a risk
        ('cp "${files[@]}" /dest', []),
        ('cp ${files[@]} /dest', ["files[@]"]),
        # $( ) is its own quoting context: the inner " does not unquote $snapshot
        ('rm -rf "$(dirname "$snapshot")"', []),
        ('rm -rf $(dirname "$snapshot")', []),
        # `${x:+"$x"}` quotes its alternate word - the standard "only if set" idiom
        ('rm -f ${chunk_file:+"$chunk_file"} "${test_files[@]}"', []),
        ('rm -rf ${stage:-}', ["stage:-"]),
        # `[ ]` is the test builtin and does split, so it is not exempt
        ('[ -n $x ] && rm -f $x', ["x", "x"]),
):
    check("shell " + repr(line[:36]), semantics.unquoted_expansions(line), want)


# ===================================================== 3b. names that mean "secret"
print("\nvalue names - does this random number matter?")

from repoxray.analysis.context import security_meaning                     # noqa: E402

for text, want in (
        # a word boundary cannot see inside either of these, which is why the names are
        # split into words instead of matched with a regex
        ("generateResetToken", True),
        ("csrf_token", True),
        ("rand = random.randint(1, 100)  fname", False),
        ("Math.floor(Math.random() * 70 + 30) quantity", False),
        ("pickBackgroundColour", False),
        ("spinnerDelay", False),          # `pin` must not match inside `spinner`
        ("driverIndex", False),           # `iv` must not match inside `driver`
        ("keyboardShortcut", False),      # `key` alone is not enough
        ("apiKey", True),
        ("privateKeyBytes", True),
        ("sessionId", True),
        ("resetCode", True),
        ("encodeURIComponent", False),    # `code` alone is not enough
        ("sortKey", False),
        ("otp", True),
        ("couponCode", True),
        ("nonceFor", True),
):
    check("name " + repr(text[:34]), bool(security_meaning(text)), want)


# ===================================================== 4. linter directives
print("\nreviewer directives - was this already triaged?")

# nebius/gosdk conn/parse.go:101 - the directive is on the matched line
GO_LINE = ("\t\t\t\tInsecureSkipVerify: true, //nolint:gosec // Explicit no-tls-verify "
           "override for selected APIs.\n")
anns = annot.scan(GO_LINE)
cover = annot.covering(anns, 1, "tls")
truthy("nolint:gosec covers a tls finding on its line", cover)
check("  ... and is recognised as explained", cover.explained if cover else None, True)
check("  ... and names the reason", "no-tls-verify" in (cover.note if cover else ""), True)
truthy("a bare nolint:gosec silences all of gosec, G101 included",
       annot.covering(anns, 1, "secret"),
       "the directive names no code, so its scope is everything the linter can say")
# the guarantee that matters: a directive carrying a code stays in its own lane
anns_coded = annot.scan("tls.Config{InsecureSkipVerify: true} // #nosec G402 -- opt-in\n")
truthy("a coded directive covers its own class", annot.covering(anns_coded, 1, "tls"))
falsy("  ... and nothing else", annot.covering(anns_coded, 1, "secret"),
      "G402 is about TLS; it must not excuse a hardcoded secret on the same line")

anns = annot.scan("x = run(cmd)  # nosec B602 - cmd is a literal\n")
truthy("nosec B602 covers cmd", annot.covering(anns, 1, "cmd"))
falsy("nosec B602 does not cover sqli", annot.covering(anns, 1, "sqli"))

anns = annot.scan("foo = eval(s)  # type: ignore[misc]\n")
falsy("a type-checker directive is not a security review",
      annot.covering(anns, 1, "code"))

anns = annot.scan("// eslint-disable-next-line security/detect-child-process\n"
                  "exec(cmd)\n")
truthy("eslint-disable-next-line reaches the next line",
       annot.covering(anns, 2, "cmd"))
falsy("  ... and not its own line", annot.covering(anns, 1, "cmd"))

anns = annot.scan("tls.Config{InsecureSkipVerify: true} //nolint:gosec\n")
cover = annot.covering(anns, 1, "tls")
truthy("a bare nolint:gosec still covers tls", cover)
check("  ... but is marked unexplained", cover.explained if cover else None, False)

anns = annot.scan("v := x //nolint:govet,lll\n")
falsy("a non-security linter directive covers nothing",
      annot.covering(anns, 1, "tls"))

# comment prose that says what a value is
lines = ["// Program addresses, public on mainnet-beta.",
         "export const PROGRAMS = {",
         "  token: '" + SOLANA + "',"]
check("comments declare the value public", annot.meaning_near(lines, 3), "public")
check("a string containing 'example' is data, not a comment",
      annot.meaning_near(["token = 'example_of_a_value'"], 1), "")


# ===================================================== 5. deployment context
print("\ndeployment - who is the attacker?")

CLI_FILES = {
    "package.json": '{"name":"x","bin":{"bordrless":"./dist/cli.js"},'
                    '"dependencies":{"commander":"^11"}}',
    "src/cli/bordrless.ts": "#!/usr/bin/env node\nimport { Command } from 'commander';\n",
}
ctx = deployment.classify(list(CLI_FILES), CLI_FILES.get)
check("a package with a bin entry is a CLI", ctx.kind, deployment.CLI)

factor, reason = deployment.gate("ssrf", ctx)
check("SSRF is dropped in a CLI", factor, 0.0,
      "a tool the user runs has no internal network to pivot into")
truthy("  ... with a reason", "no remote attacker" in reason)
check("command injection survives in a CLI, discounted",
      deployment.gate("cmd", ctx)[0], 0.6,
      "a CLI can still be fed a hostile archive or repository")
check("a hardcoded secret is unaffected by deployment",
      deployment.gate("secret", ctx)[0], 1.0)

SRV_FILES = {
    "package.json": '{"dependencies":{"express":"^4.18"}}',
    "src/routes/user.js": "app.get('/u/:id', (req,res) => res.send(req.params.id))\n",
}
ctx = deployment.classify(list(SRV_FILES), SRV_FILES.get)
check("an express app is a server", ctx.kind, deployment.SERVER)
check("SSRF is untouched in a server", deployment.gate("ssrf", ctx)[0], 1.0)

LIB_FILES = {
    "go.mod": "module github.com/nebius/gosdk\n\ngo 1.22\n",
    "conn/parse.go": "package conn\n\nfunc ParseOverrides(v string) {}\n",
}
ctx = deployment.classify(list(LIB_FILES), LIB_FILES.get)
check("an SDK module is a library", ctx.kind, deployment.LIBRARY)
truthy("TLS in a library is discounted, not dropped",
       0.0 < deployment.gate("tls", ctx)[0] < 1.0)


# ===================================================== 6. reachability of a setting
print("\nreachability - is the setting on by default?")

GO_SRC = """package conn

func ParseResolverAndDialOptions(value string) (Resolver, error) {
\toverrides, err := ParseOverrides(value)
\tfor _, o := range overrides {
\t\tif o.NoTLSVerify {
\t\t\ttlsConfig := &tls.Config{
\t\t\t\tInsecureSkipVerify: true,
\t\t\t}
\t\t\t_ = tlsConfig
\t\t}
\t}
\treturn nil, err
}

func AlwaysInsecure() *tls.Config {
\treturn &tls.Config{InsecureSkipVerify: true}
}
"""

try:
    from repoxray.analysis.parse import parse
    root, data = parse(GO_SRC, "go")
except Exception:                                           # noqa: BLE001
    root, data = None, b""

if root is None:
    print("  skip  (no Go grammar installed)")
else:
    got = reach.analyse(root, data, {8, 17})
    opt = got.get(8)
    truthy("the guarded InsecureSkipVerify is opt-in", opt and opt.opt_in,
           "it sits inside `if o.NoTLSVerify`, which is an operator option")
    truthy("  ... and says so", opt and "NoTLSVerify" in opt.describe())
    always = got.get(17)
    truthy("the unguarded one is unconditional", always and always.unconditional)
    falsy("  ... and is not opt-in", always and always.opt_in)

check("an option condition is recognised",
      reach.classify_condition("o.NoTLSVerify"), "option")
check("an env condition is recognised",
      reach.classify_condition('os.Getenv("SKIP") == "1"'), "env")
check("a request condition is recognised",
      reach.classify_condition('r.Header.Get("X-Debug") != ""'), "request")
check("a constant condition is recognised", reach.classify_condition("true"), "constant")


# ===================================================== 7. decode power
print("\ndecoder power - can this library actually execute code?")

from repoxray import rules                                   # noqa: E402

check("go yaml/gob is a typed decode", rules.DESER_POWER["go.deser"][0], "type")
check("  ... and its category is not CWE-502",
      rules.COMPILED_BY_ID["go.deser"]["cat"], "decode")
check("  ... with an honest CWE",
      rules.CATEGORIES["decode"]["cwe"], "CWE-409")
check("pickle executes code", rules.DESER_POWER["py.pickle"][0], "code")
check("  ... and stays CWE-502", rules.COMPILED_BY_ID["py.pickle"]["cwe"], "CWE-502")
check("PHP unserialize executes code", rules.DESER_POWER["php.unserialize"][0], "code")
check("js-yaml 4 load is a typed decode", rules.DESER_POWER["js.yaml_load"][0], "type")
check("js-yaml full schema executes code", rules.DESER_POWER["js.yaml_full"][0], "code")


# ===================================================== 8. phantom sources
print("\nsources - does the framework actually exist in this file?")

GQL = [s for s in rules.COMPILED_SOURCES if s["id"] == "src.graphql"][0]
GO_RESOLVER = ("resolvers = append(resolvers, NewBasicResolver(o.ServiceID, o.Address))\n")
falsy("go is not a graphql language for this source", "go" in GQL["langs"],
      "the rule had no language restriction, so `Resolver(` matched a gRPC resolver")
truthy("the source requires a graphql import", GQL["requires"] is not None)
falsy("  ... which a gRPC line does not satisfy",
      GQL["requires"].search(GO_RESOLVER) if GQL["requires"] else None)
truthy("  ... but a real resolver file does",
      GQL["requires"].search("import { gql } from 'graphql-tag'\n"))

WH = [s for s in rules.COMPILED_SOURCES if s["id"] == "src.webhook"][0]
falsy("the bare word 'webhook' is no longer a source",
      WH["rx"].search("// handle the webhook here\n"))
truthy("a signature header still is",
       WH["rx"].search('sig = req.headers["X-Hub-Signature"]\n'))


# ===================================================================== result
print("\n" + "=" * 66)
if FAIL:
    print("FAILED " + str(len(FAIL)) + " case(s):")
    for name in FAIL:
        print("  - " + name)
    sys.exit(1)
print("context corpus: all cases pass")
