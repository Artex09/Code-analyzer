# RepoXray

Paste a GitHub URL, get the source tree organised several ways at once — plain layout, ranked by
how likely each file is to contain a flaw, grouped by weakness class, and by attack surface. Then
the local model reads the top of that ranking and says which of the leads are real.

Built for bug bounty triage: the point is deciding *where to spend the next hour*, not producing a
scanner report.

Under the ranking is a real static analysis, not a grep: tree-sitter ASTs, a per-function CFG,
interprocedural taint that follows a value **across module boundaries**, and Z3 deciding whether
the branch conditions on the way to a sink can hold at all - and whether they still admit a
payload. When they do, the solver hands back the payload.

## Run it

```
cd C:\Users\jmala\repo-xray
python run.py
```

Opens `http://127.0.0.1:7331/` in your browser. `start.bat` does the same by double-click.
A second launch on the same port hands over to the running instance instead of splitting state.

Options: `--port 7331`, `--host 127.0.0.1`, `--no-browser`, `--debug`.

First run: `pip install -r requirements.txt`. The tree-sitter grammars and `z3-solver` are
each optional - a missing grammar drops that language to the pattern pass, a missing solver
drops path conditions - and the capability line in the top right says which are live.

Accepted inputs: `owner/repo`, `https://github.com/owner/repo`, `.../tree/<branch>/<subdir>`
(scopes the scan to that directory), `.../blob/<branch>/<file>`, `git@github.com:owner/repo.git`.

## The seven views

| # | View | What it answers |
|---|------|-----------------|
| 01 | Risk Ranked | Every file ordered by score, bucketed critical → minimal |
| 02 | Standard Layout | The tree as it is on disk, with risk rolled up into each folder |
| 03 | Vulnerability Classes | Files grouped under the weakness type, with the matching lines inline |
| 04 | Attack Surface | Routes, handlers, CLI entries, jobs, files that read untrusted input, config |
| 05 | Directory Heat | Which regions of the tree concentrate risk |
| 06 | AI Verdicts | Model-read files with per-finding reasoning, attack sketch and confirmation steps |
| 07 | Triage Board | What you confirmed, are still reading, or ruled out |

## Two engines

Every file goes through a fast pattern pass. Files in a modelled language also go through a
real static analysis: tree-sitter parses them to an AST, a statement-level CFG is built per
function with every branch edge labelled by the condition that takes it, and a forward
may-taint dataflow follows untrusted values to their sinks - within the file, across files,
and only along paths a solver agrees are possible.

A dataflow finding only fires when the analyser can actually connect a source to a sink, and it
carries the trace it followed, so you can audit the claim instead of trusting it:

```
L34  untrusted input: express request data   const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
L41  through UserModel.findByPk              user = await UserModel.findByPk(loggedInUser.data.id)
L52  username now holds it                   let username = user.username
L60  through username?.substring             const code = username?.substring(2, username.length - 1)
L65  reaches eval on untrusted data (arg 0)  username = eval(code)
```

That is juice-shop's real RCE, eight hops from a cookie to `eval`. **No single-line pattern can
find it**, because the sink line contains nothing suspicious on its own.

It cuts the other way too. `exec("node --version")` has a constant argument, so the analyser
proves there is nothing to report and the pattern hit that fired on `exec(` is **dropped**.
Where dataflow has a verdict, the pattern match for the same line is removed as redundant.

| language | depth | notes |
|---|---|---|
| python, javascript, typescript, php | **full** | framework sources, sanitizers, path conditions, cross-file links |
| java, kotlin, go, ruby, csharp | basic | common web sinks only; silence here means "not yet modelled" |
| c, c++, rust, others | pattern only | no grammar installed, so the regex pass stands alone |

### Path conditions, decided by a solver

A may-analysis reports every sink it *could* reach, because it merges both arms of every
branch. That is where a large share of the remaining false positives live: the code already
checks the value, and the check is invisible to a flow analysis.

Every CFG edge out of a branch therefore carries the test and the polarity that takes it, and
a statement that ends a path (`return`, `throw`, `die()`) gets no successor. The conditions
collected on the way to a sink go to **Z3**, which is asked two questions.

**Can this path be taken at all?** `if (n > 5) { if (n < 2) { readFile(n) } }` is UNSAT, so the
finding is discarded rather than shipped.

**Can a value that survives these checks still be a payload?** The path condition is conjoined
with a danger predicate for the vulnerability class - for command injection, "contains one of
`;` `|` `&` `` ` `` `$(` or a newline". If that is UNSAT, every value that passes the guards is
harmless and the finding is dropped with a reason. If it is SAT, Z3 returns a model: a concrete
string that passes every check and still carries a payload. That **witness** goes on the
finding.

The difference between the two directions is the whole point:

```
if (!/^[a-z0-9.]+$/.test(host)) return 400;   exec("ping " + host)
   -> suppressed: the checks on this path exclude every payload

if (!/^[\w.-]+$/.test(file)) return 400;      open("/data/" + file)
   -> kept, witness: ".."        <- \w allows dots, so traversal survives the check
```

Both look like careful validation. One is. A reviewer reading quickly will accept both.

Guards that the encoder cannot read become unconstrained atoms, which can only make the
solver *more* permissive - so an untranslatable check never silences a true finding, it only
stops the tool claiming the value was validated. Understood guards include regex literals
(translated into Z3's regex theory, anchors and character classes included), literal
allow-lists, `includes` / `in_array` / `in`, prefix and suffix tests, length and numeric
comparisons, `typeof x === "number"`, and the per-language validator helpers.

Install is optional (`pip install z3-solver`). Without it, findings still carry their guards
for you to read, nothing is suppressed on that basis, and the capability line says `solver:
off`.

### Cross-file flow

The per-file pass produces two halves of a vulnerability and never sees them meet:

```
routes/admin.js   app.post("/run", (req, res) => runJob(req.body.name))
lib/jobs.js       exports.runJob = (name) => exec("./scripts/run " + name)
```

Neither file has a finding on its own. So each file also emits a **summary** - "argument 0 of
`runJob` reaches `exec` at line 4" - and a **call site** - "untrusted data, argument 0, into
`runJob`". A repo-level pass resolves `runJob` to `lib/jobs.js` and joins the pair into one
finding whose trace spans both files:

```
src/controllers/apps/auth/user.controllers.js  L466  request object arrives as req
src/controllers/apps/auth/user.controllers.js  L476  through User.findById
src/controllers/apps/auth/user.controllers.js  L476  user now holds it
src/controllers/apps/auth/user.controllers.js  L496  passed to removeLocalFile()
src/utils/helpers.js                           L116  crosses into src/utils/helpers.js as argument 0
src/utils/helpers.js                           L116  reaches filesystem path from untrusted input (arg 0)
```

That is a real finding in hiteshchoudhary/apihub, reached from **four** different controllers.
The finding is attached to the file holding the sink, because that is where the fix goes, and
every calling file gets a pointer back to it so the route still ranks. Clicking an entry in
the viewer follows the flow into the calling file.

Summaries compose, so a flow is followed through as many modules as the links resolve -
`handle` forwarding to `store` in a third file is one finding with the whole chain in the
trace. Recursion is cut at four hops rather than unrolled.

Each link records how it was resolved, and that travels with the finding:

| link | meaning | treated as |
|---|---|---|
| `import` | the specifier resolved to a real file (`./util` → `lib/util.js`) | evidence |
| `same-package` | one Go directory, one PHP `require` graph | evidence |
| `name` | nothing resolved, but exactly one file in the repo defines that name | a guess; confidence drops and the finding says so |

Resolution is per language: relative and index resolution for JS/TS, dotted and relative
modules for Python, literal and constant-prefixed `require`/`include` for PHP (which pulls in
every function the file declares, as PHP actually works), `require_relative` for Ruby,
directory-as-package for Go, and class-name matching for Java and C#. Constructor-injected
services are resolved too: `constructor(private userService: UserService)` followed by
`this.userService.find(x)` is linked through the field's declared type, which is most of a
modern dependency-injected codebase.

Taint flowing the other way - a helper that *returns* untrusted data - is picked up by
re-analysing the callers of such a function once the repo pass knows about it.

Honest limits, because they decide how much to trust a quiet result:

- **May-analysis.** Branches are merged by union, so a value tainted on any path is treated as
  tainted. The solver recovers the common guard cases, not all of them: a guard it cannot
  translate is kept and shown rather than acted on.
- **Propagation is optimistic.** An unknown call with a tainted argument is assumed to pass the
  taint through. That is what lets the trace above survive a database round-trip, and it is also
  the main way a false positive can still get in - which is why the trace is always shown.
- **The witness is generated, not tested.** It satisfies the constraints the analyser extracted.
  Treat it as the first thing to try, not as a proof.
- **Dynamic dispatch is not resolved.** A call through a variable, a registry, a decorator or
  reflection is unresolved and dropped, not guessed at.
- **Context-insensitive.** One summary per function, not one per call site, so a function
  called safely in ten places and dangerously in one is reported once for the dangerous case.
- Sanitizers are category-aware: `path.basename` kills a traversal finding but deliberately
  does **not** kill a command-injection one on the same value.

Both passes are switched on by the **dataflow** and **cross-file** toggles next to the URL
bar. Turning dataflow off turns off everything in this section and leaves the fast pattern pass.

### Measured

| | juice-shop | apihub | nebius/gosdk | terraform-provider-nebius |
|---|---|---|---|---|
| files / lines | 1,300 / 239k | 572 / 233k | 968 / 246k | 371 / 71k |
| scoring wall time | 23.4s | 10.6s | 25.3s | 5.8s |
| files parsed to an AST | 655 | 450 | 948 | 200 |
| AST + taint + CFG | 9.6s | 1.8s | 16.3s | 3.1s |
| solver | 0.5s / 57 queries | 0.0s / 30 queries | 0.0s / 12 queries | 0.0s / 0 queries |
| **findings** (all parts established) | 41 | 2 | 0 | 0 |
| **leads** (a named gap) | 22 | 65 | 2 | 0 |
| pattern matches, no traced flow | 152 | 11 | 0 | 1 |
| matches ruled out by the context pass | 79 | 21 | 2 | 1 |
| annotations (never scored) | 89 | 3 | 15 | 33 |
| cross-file flows kept | 0 | 13 | 0 | 0 |
| findings with a payload witness | 5 | 2 | 0 | 0 |
| highest score in the repo | 74.8 | 77.1 | 19.3 | 10.8 |
| critical / high | 0 / 13 | 1 / 5 | 0 / 0 | 0 / 0 |

Read the zeroes as results. `nebius/terraform-provider-nebius` is a hardened provider and
reports **nothing** across 371 files - every one of them in the minimal band, one pattern
match and 33 annotations; before the source and sink models went in, its one workflow alone
produced four weight-8 "CI uses untrusted event data" findings on a trigger name, a
concurrency group and two integer PR numbers. `nebius/gosdk` reports no findings and two
labelled leads, where a metadata probe used to be a weight-8 high-confidence SSRF because a
parameter was called `ctx`, and `conn/parse.go` used to score 45.9 on a line its own authors
had annotated.

apihub is the other shape: 2 findings and 65 leads. The leads are honest - almost all of them
pass through a Mongoose round-trip, and what comes back out of `User.findById(req.user._id)`
is a database record, not the id the attacker chose. The analyser used to call all of those
high-confidence findings. Same flows, same volume, correct labels.

## What is a source, what is a sink

Most of what a scanner gets wrong, it gets wrong here. These are the rules.

### A source is modelled, not guessed

A taint source has to be identified by **language, framework, type and field semantics** -
not by what a variable is called.

```go
func (p probe) tryToken(ctx context.Context, logger *slog.Logger) {   // neither is a source
func handler(w http.ResponseWriter, r *http.Request) {               // r is, by type
```

Three tiers, and the finding says which one it rests on:

| tier | what matched | treated as |
|---|---|---|
| `known` | the declared type (`*http.Request`, `HttpServletRequest`, `gin.Context`) | evidence |
| `known` | the name, **and** the function is registered as a route handler (`app.get("/x", h)`, `@app.route`, `http.HandleFunc`) | evidence |
| `inferred` | the name alone, **in a file that has the framework in it** | a guess — the result is a lead, never a finding |

A parameter that **has** a declared type which does not match is not a source at all,
whatever it is called. That single rule is what stopped `ctx context.Context` from turning
every function in a Go repository into a request handler.

The third tier carries one further condition, because the name alone was still too much.
A parameter called `request` is a Flask request only where Flask exists: in a gdb bridge
whose `request` is the parsed JSON of a request file, the name made `exec(compile(...))`
read as *"flask request reaches eval"* at weight 9, in a repository with no web framework
anywhere. Each name-based source now declares what must appear in the file for its
convention to mean anything — a declared type does not, because the type names the
framework itself.

There is also an explicit never-list per language: `context.Context`, `*slog.Logger`,
`testing.T`, `http.ResponseWriter`, `error`, `self`, `cls`, `res`, `next`, a `CancellationToken`,
a `DbContext`. These are checked first so no heuristic can override them.

### A value's type decides what it can carry

Being attacker-controlled and being able to carry a payload are different properties.

```yaml
PR_NUMBER: ${{ github.event.pull_request.number }}   # attacker-chosen. An integer.
TITLE:     ${{ github.event.pull_request.title }}    # attacker-chosen. Free-form text.
```

Values are classified `text`, `opaque`, `id`, `enum`, `bool`, `slug`, `secret` or `trigger`,
and **only `text` and `opaque` can satisfy a string-injection sink**. An integer PR number
reaching a shell is not command injection, and reporting it as one is what buries the real
findings. A `secret` is routed to its own question — who can read the logs — rather than
treated as an injection source.

### A sink knows which argument is dangerous

```go
http.NewRequest(method, url, body)                  // the URL is argument 1
http.NewRequestWithContext(ctx, method, url, body)  // the URL is argument 2
```

Sinks name their arguments, so the analyser can say *the taint is in the context, not the
URL* instead of "argument 0 of an SSRF sink". Taint in an argument that is not a danger
role produces nothing.

### Execution semantics, not function names

```go
exec.Command("sh", "-c", userInput)   // command injection, CWE-77, weight 9
exec.Command("open", userInput)       // argument injection, CWE-88, weight 6
exec.Command("open", constURL)        // nothing: the argument is provably constant
```

Each execution sink declares whether it is `always` a shell, an `argv` vector, or
`conditional` on a flag it reads from the call (`subprocess.run(..., shell=True)`,
`spawn(..., {shell: true})`). A tainted entry in an argv vector to a fixed non-shell program
is reported as argument injection with the reason attached — *the program is fixed and is not
a shell, so this matters only if `open` interprets the value* — not as remote code execution.

### Context flow is not data flow

```go
rctx, cancel := context.WithTimeout(ctx, timeout)
req, _ := http.NewRequestWithContext(rctx, http.MethodGet, endpoint, nil)
```

`context.WithTimeout` returns a cancellation scope. It carries none of its argument's taint,
and a trace reading `through context.WithTimeout` on the way to an SSRF was a category
error. Each language declares its **barriers**: lifecycle and context calls, logging, length
and type inspection, error construction, timers.

The same distinction applies to workflows: `on: pull_request_target` is a *trigger*, which
says when the job runs and with what privileges. Nothing flows from it.

### A filter covers what it covers

```go
strings.ReplaceAll(url, "&", "^&")   // & escaped for cmd.exe. | > < " untouched.
filepath.Clean(p)                    // .. removed. An absolute path is still absolute.
```

Sanitizers are marked full or **partial**, and a partial one is read for what it actually
does. The replaced characters are removed from the solver's payload set, so the witness it
produces is one the code can really generate — and when a filter removes every marker a
class needs, that is a proof of safety rather than an assumption.

### Constants are followed

```go
const defaultEndpoint = "http://metadata.internal/v1/token"
tokenEndpoint := defaultEndpoint      // provably constant, to a fixpoint
```

A symbol assigned only from literals or other constants, anywhere in the file, is constant.
A sink taking one produces no finding and drops the pattern hit on that line.

Constness also survives a **pure builder**, which is what a path is usually made of:

```python
implementation = os.path.join(os.path.dirname(__file__), "launch_impl.py")
with open(implementation, "rb") as handle:        # provably this package's own sibling
    exec(compile(handle.read(), implementation, "exec"))
```

`__file__` is not input, and `join`/`dirname` are pure, so the whole expression is constant
two calls deep. Without that the path read as *built at runtime* and the line scored as
code execution. The rule is that **every** argument must be constant, which is why
`path.join(uploadDir, req.body.name)` is not and cannot become so. A const proof also
refutes a capability hit on the same line — "this line builds something at runtime" is a
claim, and the engine has just answered it.

## Findings, leads and signals

Three different claims, kept apart everywhere — the viewer, the report and the verification
prompt:

| | what it means |
|---|---|
| **finding** | source, value type, dangerous argument and an unbroken flow are all established |
| **lead** | one of those is missing, and the row names which |
| **pattern match** | a regex fired and no flow was traced; read it yourself |
| **context** | a property of the file, not a claim about a bug |
| **signal** | somebody's annotation. `#nosec` means a developer looked and moved on. It carries no CWE, scores nothing, and is listed on its own |

Every flow finding ships its evidence itemised, and the unknowns are the part that is
highlighted:

```
source known   value text   sink direct   arg url   flow assumed   hops 2   guard present
  · passes through 2 call(s) whose body was not analysed, so the connection is assumed
  · reachable only if these checks are satisfied or bypassed
```

High confidence requires **all** of: a known source, a payload-capable value, the taint in a
danger argument, an unbroken flow, and no effective guard. If any one is missing the result
is a lead, and the prompt handed to a model says so and tells it to check that gap first.

There is a sixth way to be a lead with nothing missing at all: **nobody would do it**. When
the source is argv or the environment of a command-line tool, every element is established
and the attacker is the person who started the program. `Evidence.no_attacker` records that
in words rather than hiding it in a flag, because it is a claim about the deployment and the
deployment can be wrong.

Severity and certainty stay on separate axes. A weight-9 `eval` the analyser is unsure of
outranks a weight-4 redirect it is certain of, because that is the order worth reading them
in — but it is still labelled a lead.

### Where the pattern pass stands back

When the dataflow engine successfully reads a file, it is authoritative for the classes it
models: it either traced the flow or showed there is none. Any remaining pattern hit in one
of those classes is demoted to context and almost unscored. It was a name-based guess at
weight 6-9 competing with traced evidence for the same ranking slot — on juice-shop, 88 hits
per scan.

## The context pass

Every pattern in the rule base is technically correct about what it matched. The distance
between *this matched* and *this is a finding* is security context, and
`analysis/context.py` is where most of it gets applied. Each of the eight questions below
is a false positive observed on a real repository, named. Two of them — *is this name that
function* and *who supplies the input* — are answered inside the dataflow pass instead,
because they change what the sink **is** rather than what to do with the match.

Nothing is deleted silently. A ruled-out match keeps its line, its rule and the reason it
was set aside; the viewer shows it struck through with the reason underneath, the report
counts it, and the verification prompt lists it under *"so you can disagree"*. A scanner
you cannot argue with is one you cannot trust either.

### Did a reviewer already decide this?

```go
InsecureSkipVerify: true, //nolint:gosec // Explicit no-tls-verify override for selected APIs.
```

The directive was on the matched line and was ignored, so `conn/parse.go` in an SDK scored
45.9. `annot.py` reads `nolint`, `nosec`, `noqa`, `eslint-disable`, `nosemgrep`,
`lgtm[...]`, `NOSONAR` and `@SuppressWarnings`, and three rules keep it from being a
blanket mute:

- **Codes bind to categories.** `#nosec G402` covers TLS and nothing else — it does not
  excuse a hardcoded secret on the same line. A bare `//nolint:gosec` names no code, so it
  covers everything gosec can say.
- **An explanation counts for more than a bare directive.** With a reason, it is a recorded
  decision and the finding is set aside quoting the author's own words. Without one it is
  "make it stop", which is demoted and kept visible.
- **A traced flow beats a comment.** A comment is evidence about intent, never proof of
  safety. A dataflow finding stands whatever directive sits on the line.

`#type: ignore` and `@ts-expect-error` are recognised so they are *not* read as a security
review.

### Is this literal actually a secret?

```toml
bordrless_token = "2XoEWp8cF3kRXg74eVwPAyTFhVCAztn3V88komxAvr22"
```

44 base58 characters is a 32-byte public key — a Solana account, program or mint address,
public by construction and printed in the project's own README. `semantics.py` classifies
the **encoding**, and the name never overrides it:

| shape | verdict |
|---|---|
| `AKIA…`, `ghp_`, `sk-ant-`, `-----BEGIN`, `eyJ….….…` | secret — the format pins it down |
| base58, 51–52 chars, leading `5`/`K`/`L` | **secret** — that is a WIF private key |
| base58, 43–44 chars | public — a 32-byte key |
| base58, 26–35 chars | public — a base58check address |
| 40 or 64 hex, `0x`+40 hex, UUID | public — a digest, a commit sha, a chain address |
| `scheme://user:pass@host` | secret — a password in the userinfo |
| `your-api-key`, `changeme123456`, `local-fixture-key` | placeholder |

Only an unrecognised shape falls through to entropy, and then a name meaning *credential*
is required. A comment within three lines saying *"program addresses, public on
mainnet-beta"* is read and believed, because a human wrote it down.

**Entropy is not a randomness test at seventeen characters.** `OPENAI_API_KEY:
"local-fixture-key"` was reported as a hardcoded credential in nine files of one
repository; the value scores 3.68 bits per character, which is roughly what any English
word scores, and the name did the rest. So before the entropy fallback is trusted, the
value is checked for **words**: two or more segments of nothing but letters means a person
typed it, because a credential generator has no vocabulary. That makes
`correct-horse-battery-staple` **unknown**, not dismissed — a passphrase and a stand-in are
indistinguishable by shape, and claiming otherwise would be the same mistake pointing the
other way. What settles it here is the marker in the value itself (`fixture`, `mock`,
`synthetic`, `local-only`, `not-a-real-key`) and the sentence above the line:

```js
// This synthetic value is never a real credential; local-only refuses hosted API calls.
COMMAND_CODE_API_KEY: "local-fixture-only",
```

That comment reads as a *secret* declaration to a pattern looking for "real credential", so
the comment reader now checks the placeholder vocabulary first and disqualifies a secret
claim with `never`, `not` or `no` in the clause before it.

### Is the capability corroborated?

```js
new RegExp(`^${name}:\\s*(\\S+)`, 'm')     // reported as ReDoS, four times, in one CLI
```

"This file can build a regex / a URL / a command at runtime" is true of a great deal of
correct code. `CAPABILITY_RULES` need something else before they are worth attention:

- **ReDoS** needs a pattern that can actually backtrack. The skeleton is analysed with the
  character classes expanded, because `\s*` beside `(\S+)` is two quantifiers in a row that
  can never be ambiguous — nothing is both whitespace and non-whitespace. Verdicts:
  `catastrophic` (a nested or overlapping-alternation quantifier), `polynomial` (two
  adjacent overlapping classes), `injectable` (the caller supplies the *whole* pattern, so
  they choose the shape), `dynamic` (a fixed skeleton with a value spliced in — not ReDoS),
  `benign`.
- **SSRF** needs an attacker-controlled host. A dynamic URL is how every HTTP client is
  written.
- **An unquoted shell variable** has to really be unquoted. `rm -f "$file"` splits nothing.
  The analysis tracks quote state, treats `$( … )` as its own context so the inner quote in
  `"$(dirname "$snapshot")"` does not unquote anything, exempts `[[ … ]]` (a bash keyword
  that does no word splitting, unlike the `[ … ]` builtin), and accepts `"${arr[@]}"` and
  `${x:+"$x"}` as the correct idioms they are. On Omarchy this took `sh.var_cmd` from 1754
  matches to **1**, and that one is genuinely unquoted.
- **Weak randomness** matters when the output is a secret. The identifier is split into
  words — a word boundary cannot see inside `generateResetToken` or `csrf_token` — so
  `apiKey` counts and `keyboardShortcut`, `spinnerDelay` and `driverIndex` do not.
- **A subprocess call** is command injection when a shell parses it. `subprocess.run([prog,
  "-f", path])` passes a vector straight to `execvp`, so a value holding `;` arrives as one
  literal argument; `shell=True` on the same line escalates it instead. The corroborator
  gets the matched line *plus four*, because a call written across lines shows only
  `subprocess.run(` on the line that matched.
- **A predictable temp path** is a weakness when this program creates the file.
  `Path("/tmp/.X11-unix")` is the X11 socket directory — root-owned, sticky bit, there
  before the program starts — and a `/tmp` literal with nothing on the line that opens or
  creates it is a constant, not a file.
- **A format string in a variable** is usually a macro. An upper-case format argument is how
  C spells a compile-time constant, and without an untrusted source in the file there is no
  input to put `%n` in it.

### Is the setting on by default, or opt-in?

```go
if o.NoTLSVerify {                       // the operator asked for this
    tlsConfig := &tls.Config{InsecureSkipVerify: true}
}
```

For `SETTING_RULES`, `reach.py` walks the tree the dataflow pass already parsed and
collects the enclosing branch conditions, classifying each as `option`, `env`, `request`,
`constant` or `loop`. Reachable only behind an operator option or an environment variable
is a **documented capability**, and it is set aside naming the condition. Unconditional in
a shipped path stays a finding and says *"nothing guards this line, so every caller gets
it"*. Behind a condition that reads request data, the weight goes **up**.

### Can this library do what the CWE claims?

`DESER_POWER` records what each decoder can actually do, because "insecure
deserialization" is a property of the library and not of the word *load*:

| power | libraries | claim |
|---|---|---|
| `code` | pickle, PyYAML non-safe loaders, PHP `unserialize`, Java `readObject`, Jackson polymorphic, Ruby `Marshal`, `BinaryFormatter`, js-yaml full schema | CWE-502, remote code execution |
| `type` | Go `yaml`/`gob`/`xml`, js-yaml 4 `load` | **not** CWE-502 — these fill declared struct fields and have no mechanism to construct a type the program did not name |
| `entity` | XML parsers with DTDs on | CWE-611, XXE — reads files and makes requests, not RCE |

Typed decoders moved to a new `decode` class with an honest CWE-409: the real risk is a
compressed or deeply nested document exhausting memory, and unvalidated decoded values.
`auth/file_cache.go` went from "Insecure Deserialization, CWE-502" at weight 5 to a
weight-3 observation that says what the question actually is.

### Is there a victim in this deployment?

`deployment.py` classifies the repository once — `server`, `cli`, `library`, `mobile`,
`infra` — from manifests (`bin` entries, console scripts, framework dependencies, exposed
ports) and a capped look at the code. Every `package.json` and `go.mod` is read, not just
the root one, because a monorepo keeps the interesting manifest in a workspace: bordrless's
root manifest is `"private": true` with no `bin`, and the command it installs is declared
in `packages/sdk/package.json`.

A file can override the repository: a route handler is a route handler whatever the project
mostly is.

Then categories that need a remote attacker are gated:

| class | in a CLI | in a library |
|---|---|---|
| SSRF, XSS, open redirect, CORS, CSRF, IDOR | dropped — a tool the user starts has no internal network to reach and no victim to be | 0.4–0.5, *"the caller supplies this, and the caller is the operator"* |
| command injection, argument injection, path traversal | 0.6 — *"the attacker has to control what you hand the tool: a file it reads, an archive it unpacks, a repository it clones"* | — |
| TLS disabled | — | 0.5 — a library exposes this as an option for its caller |
| hardcoded secret | unchanged | unchanged |

When the deployment was inferred weakly the factor never reaches zero: a low-confidence
guess discounts a finding, it does not delete one.

### Is this name that function?

`analysis/binding.py`. A rule that fires on a callee name is making a claim about
identity, and in JavaScript the interesting names are all shared:

```js
// scripts/lib/verify-package-core.mjs
import { execFile } from "node:child_process";
export const exec = promisify(execFile);
```

```js
// scripts/verify-commandcode-client.mjs
import { exec } from "./lib/verify-package-core.mjs";
await exec(command, ["--version"], { env: environment });   // reported as CWE-78, ×8 files
```

`execFile` hands an argv vector to `execvp` or `CreateProcess`; there is no shell anywhere
in that path, and a value holding `;` or `$( )` arrives at the program as one literal
argument. The resolver reads the local definitions, follows a relative import to the
module that exports the name, and rewrites `promisify(x)` and arrow wrappers until it
lands on a platform primitive. Three outcomes:

| | |
|---|---|
| the name is what the rule says | nothing changes |
| the name is the *other* execution primitive | the sink is reclassified — `exec = promisify(execFile)` becomes argument injection, and the engine's existing argv reasoning applies |
| the name belongs somewhere else entirely | no sink, with the definition quoted: `execute(compiler, ["version"])` where `execute` is `promisify(execFile)` is not SQL injection, and `/^(-?)([0-9]+)$/u.exec(literal)` is not command execution |

An unresolved name returns no family and nothing changes, because "I could not find the
definition" is not evidence either way. That is the only honest failure mode for a
resolver, and the difference between this and a suppression list.

Two sibling checks come from the same root cause — *the rule matched the name, not the
thing*:

**The format argument is not always the first one.** `c.format` looked for a non-literal
at argument 0 of `printf|fprintf|sprintf|syslog`, so `std::fprintf(stderr, "cleanup
failed (Win32 %lu)", code)` matched on **`stderr`** — the stream. Five literal format
strings in `native/windows/src/addon.cc` were reported as CWE-787, out-of-bounds write.
fprintf, sprintf and syslog take the format second and snprintf takes it third; each
position now has its own alternative, and the rule has its own category with CWE-134.

**A match inside a string literal is text.** For the handful of rules whose claim is *this
file executes code*, `strip.string_spans` excludes string interiors —

```js
command: `node -e "eval(Buffer.from('${encodedScript}','base64').toString('utf8'))"`
```

— was reported as an `eval` in the file that *quotes* it. Interpolation holes stay
visible: `${...}` is this file's code, so a match inside one still counts.

### Who supplies the input, in this deployment?

The dataflow pass already discounted a local source, labelling it *"local input, not
remotely reachable"* — and that was as far as it went, so a verification script reading
`process.argv[2]` still scored in the medium band. In a tool the user starts, the command
line and the environment **are** the operator: the person supplying the value is the
person running the program, and there is no one else to be the attacker. Such a finding
becomes a weight-2 lead that says so, and names what would change the answer — a wrapper,
a service that re-executes this, a setuid bit.

Argv and the environment, and nothing else. A **file** the tool reads is the one thing an
attacker in a CLI genuinely controls — the binary you analyse, the archive you unpack, the
repository you clone — which is why `deployment.gate` keeps command and path findings at
0.6 there in the first place. A file-borne flow keeps the old discount and stays a finding.
Getting this wrong in the first attempt turned 69 findings into 1 across a
reverse-engineering tool whose whole threat model is a hostile input file.

### What it did to the reported files

| | before | after |
|---|---|---|
| `verify-*-client.mjs` ×9 (rea) | 37.5–42.3 medium | **6.0–8.7 minimal** — `exec` is `promisify(execFile)`, the keys are fixtures |
| `native/windows/src/addon.cc` (rea) | 36.7 medium | **0.0** — the format strings are literals; it matched `stderr` |
| `QlogCapture.ts` (rea) | 44.6 medium | **0.0** — `/^(-?)([0-9]+)$/u.exec` is RegExp.prototype.exec |
| `verify-go-binary.mjs` (rea) | 41.1 medium | **0.0** — `execute` is `promisify(execFile)`, not a database call |
| `bridge/pwndbg/core_context.py` (rea) | 37.2 medium | **15.5 low** — `request` is a JSON dict, not a Flask request |
| `scripts/hopper-demo-x11.py` (rea) | 40.1 medium | **20.1 low** — an argv vector, and the X11 socket directory |
| `bridge/pwndbg/launch.py`, `pwntools/*.py` (rea) | 40.1 medium | **23.6 low** — argv is the operator's, and the path is a constant |
| `conn/parse.go` (gosdk) | 45.9 medium | **0.0** — directive quoted back, phantom source gone, path words unscored |
| `auth/file_cache.go` (gosdk) | 37.5 medium | **2.1** — CWE-502 → a weight-3 decode observation |
| `programs.ts` / `Anchor.toml` (bordrless) | 22.1 / 30.9 low | **0.0** — base58 public keys |
| `bordrless.ts`, `studio.ts` (bordrless) | 11.0 / 8.8 | **0.0** — constant-skeleton regexes, CLI with no victim |
| `toolchain.sh`, `programs.sh` | 10.5 / 7.8 | **0.0** — every expansion correctly quoted |

Across the whole of `morluto/rea` — 3,951 files, 3,463 of them parsed to an AST — the
medium band is now **empty**: 35 files in low, 3,916 minimal, top score 34.8, down from 18
files in medium and a top score of 44.7. 646 matches were ruled out with a reason attached,
412 of them because the name was a different function than the rule meant.

Recall held. juice-shop still reports **41 findings** and 22 leads, including the `eval` RCE
at 60.9 and the SSRF in `profileImageUrlUpload.ts` at 61.6; DVWA 23 findings; the
Vulnerable-Flask-App still critical at 92.4; apihub 2 findings and 65 leads. The only
movement in a server repository is downward in the *dismissal* count, because a const proof
now refutes a capability hit before the context pass sees it.

### Phantom sources

```python
("src.graphql", (), r"(?:resolve\s*[:(]|Resolver|@Mutation|@Query)\s*[\(\{]")
```

No language restriction, so `Resolver(` matched `NewBasicResolver(` — and a gRPC connection
parser in a Go SDK was reported as *"reads untrusted input: graphql"*, in a repository with
no GraphQL anywhere. That phantom then multiplied the whole file's score by 1.4.

Framework sources now carry a **corroborating pattern** that must also appear in the file:
`src.graphql` needs an actual GraphQL import, and is restricted to languages that have one.
`src.webhook` no longer fires on the bare word *webhook* in a comment — it wants a signature
header.

The same hole existed one layer down, in the *parameter* sources. A parameter matched by
**type** is a fact: `r *http.Request` is an HTTP request and nothing else. A parameter
matched by **name** is a convention, and a convention is only evidence where its framework
lives:

```python
ParamSource("py.flask_req", "flask request", name_pattern=r"^(request|req)$")
```

In `bridge/pwndbg/core_context.py`, `request` is the parsed JSON of a debugger request
file. The engine seeded it as a Flask request and reported `exec(compile(entry.read_bytes()))`
as **flask request reaches eval, weight 9** — in a repository with no web framework in it.
Every name-based parameter source now carries `requires`, checked against the file: Flask
needs Flask, express needs express or a `res.send`, a servlet needs `javax.servlet` or a
`@RestController`. A declared type still needs no corroboration, because the type names the
framework itself.

This one is a trade, not a free win, and `precision_corpus` pins both halves: a parameter
called `req` in a module that has never heard of express is not a source, and the same
parameter in a file that *does* import express is still a lead.

## GitHub Actions, as workflows

A workflow is not YAML with code in it. The structural model knows the difference between a
trigger, an event field and a position, which the generic patterns did not:

| | before | now |
|---|---|---|
| `on: pull_request_target` | "CI uses untrusted event data", weight 8 | a trigger — an exposure note with the guards that gate it |
| `concurrency.group: ${{ ...number }}` | weight 8 | not a sink |
| `env: PR_NUMBER: ${{ ...number }}` | weight 8 | an integer, and quoted at use — nothing |
| `run: echo ${{ ...title }}` | weight 8, same as the rest | a finding, weight 9, with the fix |

`env: X: ${{ ... }}` plus `run: cmd "$X"` is GitHub's own documented mitigation, so it
reports nothing. The same value expanded unquoted is argument injection; expanded where a
command name is expected (`eval "$X"`, `$($X)`, `sh -c "$X"`) it is command injection again.
`$(echo $X | sed ...)` is word splitting, not execution, and is reported as such.

Reachability is modelled too. `issues: types: [labeled]` needs triage access to fire, so a
field it exposes is reported as reachable by a writer, not by anyone. Guards in `if:` are
recognised and quoted — `head.repo.full_name == github.repository` closes the fork case, and
the exposure note says so instead of raising an alarm it cannot justify.

Measured over the 85 workflows in the local scan cache: **zero** results with a `finding`
verdict and no parse failures. Everything the model reports there is a labelled lead at
weight 3-5 that names who would have to have access.

## How the score works

Comments are blanked before any matching happens (offsets preserved, so line numbers stay real),
because prose is not code: `// cannot use execvp()` and `the numbering system (0..n)` are English,
and matching them as sinks was once the largest single source of false positives. String literals
are kept, since real findings live in them. The two rules that hunt for security TODOs and
suppressed linter warnings still read the raw text, because what they look for *is* a comment.

Three rule families run over every readable file:

- **sink rules** (~154) — dangerous operations per language: `shell=True`, `unserialize`,
  `eval`, `readObject`, string-built SQL, `InsecureSkipVerify`, `dangerouslySetInnerHTML`,
  hardcoded credentials, `pull_request_target`, suppressed security linters, and so on.
- **source rules** — where untrusted input enters: `request.args`, `req.body`, `$_GET`,
  `getParameter`, `r.FormValue`, `params[`, `argv`, lambda events.
- **entrypoint rules** — route decorators, controllers, handlers, RPC services, CLI mains,
  schedulers.

Then:

- rules split into **sinks** (a specific dangerous operation) and **context** (ambient facts like
  "this C file calls memcpy", true of every C file). Context rules are damped to 0.35x in files
  nothing untrusted can reach, and the UI lists them apart from findings
- a file holding **both a source and a sink** is boosted 1.4x — that is the single strongest signal
- an entrypoint plus a sink adds another 1.15x
- the **context pass** runs here: reviewer directives, literal shapes, capability
  corroboration, what guards a setting, what a decoder can do, and whether this deployment
  has a victim at all
- **path names order, they do not score.** `auth/`, `admin/`, `payment/`, `crypto/`,
  `upload/`, `legacy/` are shown as "path words (not scored)" and apply a multiplier capped
  at 1.18x to a file that *already* carries code evidence. They used to be added to the
  score, and that was the single largest source of invented risk: `auth/file_cache.go`
  scored 37.5 with no findings at all, 11.4 of it from the words "auth" and "file" in its
  path against 1.75 from the one thing found in the code. The directory a file sits in
  tells a reviewer where to look first; it says nothing about whether there is a bug there
- vendored (x0.30), test/example (x0.40) and generated/minified (x0.35) paths are damped
- localisation, docs and static-asset directories are damped further
- secret matches that look like placeholders (`changeme`, `your_key`, `${...}`) lose most weight

Scores saturate on a curve, so one file with fifty `Math.random()` calls cannot outrank a real
injection. Bands: **75+ critical, 55 high, 35 medium, 15 low**.

A hit is a lead, never proof. That is what the AI pass is for.

## AI deep dive

Pick an engine in the left rail, set how many files to read, press **read top files**. Each file
goes to the model with its flagged lines, its context signals and the source (trimmed to windows
around the hits for long files), and comes back as structured JSON: probability, confidence,
findings with line numbers, an attack sketch, and what still needs checking elsewhere in the repo.
Results stream into view 06 as each file finishes.

- **ollama (local)** — free, offline, no key. On this machine `qwen2.5:7b` is the better judge,
  `llama3.2:3b` is roughly 2x faster. Expect **~20-150s per file** on 4GB VRAM; the status line
  shows measured seconds-per-file and an ETA once the first file is back.
- **claude api** — much sharper reasoning, needs `ANTHROPIC_API_KEY` in the environment. It appears
  as unavailable in the rail until that key is set.

`a` on an open file sends just that file. Verdicts are stored in the scan record, so they survive
restarts and land in the markdown report.

## Verifying a finding

A pattern match is a lead. To decide whether it is real, open the file and press `v` (or the
**verify** button): that copies a self-contained prompt for any chat model — the evidence, the
context the scanner inferred, the source with real line numbers, and a permalink pinned to the
commit. It asks for a taint trace and a reachability check, then a one-line verdict
(`TRUE POSITIVE` / `FALSE POSITIVE` / `NEED MORE CONTEXT`), a proof of concept, and — when the
model cannot decide — the exact extra files it needs.

The prompt carries whatever the analyser knows: the dataflow trace hop by hop, the path
conditions the solver collected and the witness value it produced, and - when the flow crosses
a file boundary - **an excerpt of the other file too**, around the calling line. A verdict on
"this helper is called with attacker data" cannot be reached from the helper alone, so without
that the only honest answer a model could give is NEED MORE CONTEXT. It is asked to check each
hop rather than redo the trace, to say whether a listed guard actually blocks the value, and to
confirm the cross-file call really resolves where the tool says it does.

Typical size is 2-4k tokens, so it pastes anywhere. Paste it into a *capable* model: a 3B local
model answered the same juice-shop SQL injection both ways on consecutive runs, contradicting its
own taint analysis.

## Triage

The scanner ranks; you decide. On any open file press `t` to cycle **looking → confirmed →
dismissed**, or `x` to dismiss outright. Marks are stored in the scan record, counted in the rail,
filterable from the chips, collected in view 07, and they reorder the markdown report so confirmed
leads come first and dismissed files sink. `y` copies the open file's evidence — hits, line numbers,
snippets and the AI verdict — as markdown ready to paste into a report draft.

## Typography

Four self-hosted variable faces, so the app loads with no CDN call and no webfont request leaving
the machine: **Bodoni Moda** for display, **Martian Mono** for technical labels and numerals,
**Archivo** for prose, **JetBrains Mono** for code. 213KB total under `static/fonts/`. To change
them, edit `FAMILIES` in `tools/fetch_fonts.py` and re-run it; it downloads the woff2 files and
rewrites `fonts.css`.

## Shortcuts

`ctrl+k` jump to any file or command · `/` filter · `j`/`k` move · `enter` open · `esc` close ·
`n`/`p` next / previous hit · `1`-`7` views · `t` cycle triage · `x` dismiss · `y` copy evidence · `v` verification prompt ·
`a` ai-read open file · `r` download report · `?` help

`ctrl+k` fuzzy-matches every path in the repo; prefix with `>` for views and actions. The code
viewer carries a hit minimap on its right edge, the split between list and code is draggable, and
`density` toggles row spacing. View, density, split width, filters and model choice persist in
localStorage.

URLs are shareable: `?view=classes#<scanId>/routes/login.ts` reopens exactly that file.

## Layout

```
repoxray/
  analysis/     the AST + dataflow engine
    parse.py      tree-sitter parser registry (grammars are optional)
    model.py      Adapter / Source / Sink / Sanitizer / Guard / Summary / Finding shapes
    dataflow.py   condition-labelled CFG + forward may-taint worklist, language-agnostic
    pathcond.py   branch conditions -> Z3; regex translation, payload models, witnesses
    resolve.py    import statements -> paths in this repo, per language, with link strength
    binding.py    what a callee name actually refers to, following local defs and imports
    cross.py      repo-level pass: joins a tainted call site to a callee's summary
    actions.py    GitHub Actions workflows: triggers, event-field semantics, positions
    context.py    the context pass: the questions between a match and a finding
    annot.py      linter-suppression directives, and what a comment says a value is
    semantics.py  literal shapes, regex backtracking shape, shell quote state
    reach.py      what guards a line: an operator option, an env var, request data
    deployment.py server | cli | library | mobile | infra, and who the attacker is
    run.py        per-file entry point with size, time and solver-budget guards
    langs/        one module per language: node shapes, sources, sinks, sanitizers, guards
  fetch.py      GitHub URL parsing, shallow clone, zipball fallback, repo metadata
  inventory.py  tree walk, language/kind classification, test|vendored|generated detection
  rules.py      the pattern knowledge base: sinks, sources, entrypoints, path signals
  score.py      two-phase scoring: per file, then across files
  views.py      the seven view builders + the registry
  ai.py         prompt construction, excerpting, JSON recovery, Ollama/Claude backends
  engine.py     scan and deep-dive jobs (threads, progress, ETA)
  store.py      one JSON per scan under data/scans, history index, cache
  app.py        Flask routes, triage + file index endpoints, markdown report
  static/       the console: one stylesheet, one script, self-hosted fonts
data/
  repos/        cloned sources (reused between scans unless you tick re-fetch)
  scans/        scan records
```

## Test corpora

```
python tests/rule_corpus.py        # 47 pattern cases, all languages
python tests/rule_corpus.py js     # one section
python tests/taint_corpus.py       # 36 dataflow cases, 6 languages
python tests/path_corpus.py        # 16 path-condition cases (incl. no-solver fallback)
python tests/cross_corpus.py       # 9 cross-file cases
python tests/workflow_corpus.py    # GitHub Actions semantics + lead/finding reporting
python tests/precision_corpus.py   # 36 cases, reports precision and recall
python tests/context_corpus.py     # 163 cases, one per false positive from the field
python tests/spec_sanity.py        # every pattern in every spec compiles and coheres
python tools/check_control_bytes.py  # no collapsed escape, and every file parses
```

Three small tools help when a change has to be checked against a repository that produced a
bad result, with no network and no job queue:

```
python tools/rescan.py <repo-dir> [path ...]        # re-score from data/repos, show the parts
python tools/audit_dismissed.py <repo-dir> [--rule js.regex_dyn]
python tools/inspect_file.py <repo-dir> <substring>
```

`audit_dismissed.py` is the one that matters: it prints every match the context pass removed,
grouped by rule, next to the findings that survived. A pass that quietly drops real bugs is
worse than the noise it removed, so it has to be easy to look at.

Labelled cases, most lifted verbatim from repositories the scanner was run against: each says
which rules must fire and which must stay silent. Add a case here before changing a regex or a
spec — a rule that gets broader usually gets noisier, and this is what proves it did not. The
false-positive cases matter more than the positive ones.

Each layer is pinned in isolation: `rule_corpus` runs with `deep=False` so a dataflow change
cannot mask a broken pattern, and `taint_corpus` asserts both the rules that must fire and the
ones that must not. `path_corpus` is written the same way in both directions — half the cases
exist to prove that a *weak* validation is still reported, with the witness value that defeats
it. `cross_corpus` builds a small multi-file repository per case, where the point of every case
is that neither file has a finding on its own.

`precision_corpus` is the one to add to when a false positive turns up. Every case states the
rule, the **category** and the **verdict** that is correct, so "it fired" is not good enough -
`exec.Command("open", url)` has to come out as argument injection and not as command
injection. It prints precision and recall, because "found 100 possible vulnerabilities" is
not a result.

`context_corpus` is the record of mistakes already made. Every case is a false positive that
reached a user, and every one names the file it came from — `conn/parse.go`'s ignored
`//nolint:gosec`, `programs.ts`'s base58 program address, `studio.ts`'s four constant-skeleton
regexes, `toolchain.sh`'s correctly quoted `rm -f "$file"`, `verify-commandcode-client.mjs`'s
`exec` that is a promisified `execFile`, `addon.cc`'s five literal format strings reported on
the `stderr` argument. A failure here is not a new bug, it is a regression in something
somebody already complained about once.

`spec_sanity` validates the specs as data: every regex compiles, no pattern matches the empty
string, danger roles exist among the roles, a conditional shell has a flag to read, a partial
sanitizer says what it removes, a signal carries no CWE. It also rejects **literal control
bytes** in a pattern. That check exists because a collapsed `` became 0x08 in five rules -
they compiled, never matched, and nothing noticed for a whole session. `path_corpus` also removes Z3 and re-runs every
suppressed case, because "install it or not, nothing true is lost" is a claim worth testing
rather than asserting. `workflow_corpus` checks that triggers and numeric event fields are not
treated as shell payloads, uncertain event data stays a lead through reporting, and
suppression annotations remain unscored signals.

## Self test

```
python run.py        # one terminal
python selftest.py   # another
```

116 checks, driving the running console in headless Chrome/Edge: loads a scan from history,
switches views, collapses groups, applies band/text/noise filters, opens a file, jumps to a hit
line, expands the tree, drills through a hotspot, renders a dataflow trace and its path
conditions, follows a cross-file flow into the calling file, opens a file the context pass
ruled matches out of and checks the reason reaches both the panel and the verification prompt,
finds a match the name resolver reclassified and checks it quotes the definition it read,
and exercises `esc`/`j`/`enter`. It checks *computed* styles, which is what catches a panel
that is marked hidden but still painted. Run it after adding a view or touching
`renderView()`. The page it drives is `static/_selftest.html`.

A scan saved before a feature existed is reported as such rather than failed — old data on
disk is not a bug in the code, and a selftest that cries wolf about it gets ignored.

It launches the browser with a throwaway profile. That is not fussiness: a cached `app.js` once
made three checks fail against code that was correct on disk, which is the worst kind of test
result.

## Adding a view

One function plus one registry entry — nothing else changes, the frontend renders by declared shape:

```python
# views.py
def view_untested_code(scan):
    items = [brief(r) for r in scan["files"]
             if r["score"] >= 35 and not r["is_test"]]
    return {"shape": "groups",
            "groups": [{"key": "untested", "label": "risky and untested",
                        "count": len(items), "items": items}]}

VIEWS.append({"id": "untested", "name": "Untested Risk", "glyph": "08",
              "tagline": "scoring files with no test coverage nearby",
              "builder": view_untested_code})
```

Shapes available: `groups` (collapsible file lists, optional `evidence` per item), `tree`,
`hotspots`, `ai`. A new shape needs a matching branch in `renderView()` in `static/app.js`.

## Adding a language

One module in `repoxray/analysis/langs/`, one row in its `SPECS`. The `Adapter` is pure data -
which node types are calls, assignments, functions, strings, blocks - and the dataflow engine
never mentions a node type itself, so nothing else changes:

```python
ADAPTER = Adapter(lang="rust", call_nodes=("call_expression",),
                  assign_nodes=("assignment_expression",), block_nodes=("block",), ...)
SPEC = LangSpec(lang="rust", adapter=ADAPTER,
                sources=(Source("rs.req", r"\breq\.(query|body)", "request data"),),
                sinks=(Sink("rs.cmd", r"\bCommand::new$", "cmd", "command from input",
                            "...", args=(0,), weight=9),))
```

Dump the grammar's node names first (`python -c` with `analysis.parse.parse` and a walk) rather
than guessing - field names differ per grammar, and three of the six languages here needed a
per-grammar quirk handled (argument wrappers, missing value fields, statement-list wrappers).

Four optional blocks buy the rest:

- `if_nodes` / `consequence_field` / `else_nodes` / `terminator_nodes` give the CFG its branch
  polarity, which is what path conditions are built from. Without them the analysis still runs,
  just without guards.
- `guards` are the calls the solver can read (`Guard("js.test", r"\.test$", "regex", ...)`).
- `imports` are regexes with a named `spec` group, plus `bindings` for fields that hold an
  imported class; together they are what makes cross-file flow resolvable.
- `transparent_calls` lists *strict* conversions a guard can be read through. Only strict ones:
  JS `parseInt("5;id")` returns 5, so treating a check on it as a check on the original would
  silence a real finding.

Then add cases to `tests/taint_corpus.py`, and to `path_corpus`/`cross_corpus` if you added
guards or imports.

## Adding a rule

One tuple in `rules.py`: `(id, category, title, weight 1-10, languages, regex, case_insensitive, why)`.
The `why` string is shown in the UI and passed to the model, so write it as the reason a reviewer
should care. New categories go in `CATEGORIES` with a CWE and an accent colour.

## Notes and limits

- Unmodelled languages get the pattern pass only, which finds candidate sinks and cannot prove
  reachability. Those hits appear under **pattern matches**, not findings, and say so.
- A value whose provenance cannot be established is reported as a lead with the gap named,
  not resolved in either direction. "I cannot tell where this comes from without the caller"
  is the honest answer and the verification prompt asks for it in those words.
- The solver, the cross-file pass and the context pass all reduce noise by *deleting* things.
  Every deletion is counted in the scan summary (`paths_validated`, `paths_unreachable`,
  `regex_dropped`, `sanitizer_suppressed`, `text_not_code`, `dismissed` with its per-kind
  tally) so a suspiciously quiet scan is visible rather than silent. The counts are exact
  even where the per-file list of dismissals is trimmed: the count is the claim, the list is
  the sample.
- The name resolver reads local definitions and follows a **relative** import one hop. It does
  not resolve through a package in `node_modules`, and it is JavaScript and TypeScript only —
  the languages where `exec`, `execute` and `query` are genuinely ambiguous. An unresolved name
  changes nothing, so the gap costs recall of *suppression*, never recall of findings.
- Files over ~1.5MB are truncated for matching; binaries are inventoried but not scanned.
- Scans cap at 20,000 files.
- GitHub metadata is fetched unauthenticated, so it can be rate-limited — the scan still works.
- Only public GitHub repos over HTTPS. Private repos work if your local git credentials already do.
