"""Who the attacker is, which depends on how the code is deployed.

SSRF means "I made your server reach somewhere I cannot". A command-line tool the user runs
on their own laptop has no internal network to reach and no victim to be; a dynamic URL in
its `fetch` is the user talking to their own endpoint. The same line of code is a finding in
a web service and a non-event in a CLI, and nothing in the line itself says which.

So the repository is classified once, the file can override it, and categories that need a
remote attacker are gated on the result. Every gate records its reason, so a dropped finding
can be audited rather than silently lost.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

SERVER, CLI, LIBRARY, MOBILE, INFRA, UNKNOWN = (
    "server", "cli", "library", "mobile", "infra", "unknown")

HUMAN = {
    SERVER: "a network service",
    CLI: "a command-line tool",
    LIBRARY: "a library or SDK",
    MOBILE: "a mobile or desktop client",
    INFRA: "infrastructure definitions",
    UNKNOWN: "something the classifier could not place",
}


@dataclass(frozen=True)
class Context:
    kind: str = UNKNOWN
    confidence: str = "low"
    evidence: tuple = ()
    scores: tuple = ()

    @property
    def human(self) -> str:
        return HUMAN.get(self.kind, self.kind)

    def describe(self) -> str:
        if not self.evidence:
            return "This repository is " + self.human + "."
        return ("This repository looks like " + self.human + ": "
                + "; ".join(self.evidence[:3]) + ".")


# ------------------------------------------------------------------ repo evidence

_SERVER_CODE = re.compile(
    r"\b(?:app|server|router|http)\.listen\s*\(|"
    r"http\.ListenAndServe|net/http\".*?ListenAndServe|"
    r"uvicorn\.run|gunicorn|waitress\.serve|app\.run\s*\(|"
    r"FastAPI\s*\(|Flask\s*\(\s*__name__|express\s*\(\s*\)|"
    r"NestFactory\.create|createServer\s*\(|"
    r"ActionController|Rails::Application|"
    r"WebApplication\.CreateBuilder|UseEndpoints|MapControllers|"
    r"@(?:RestController|SpringBootApplication)", re.S)

_CLI_CODE = re.compile(
    r"#!/usr/bin/env\s+(?:node|python3?|ruby|bash|sh|deno|bun)\b|"
    r"\b(?:commander|yargs|@oclif|clipanion|cac|meow|sade|minimist)\b|"
    r"\bargparse\b|\bclick\.(?:command|group)\b|\btyper\.Typer\b|"
    r"spf13/cobra|urfave/cli|alecthomas/kingpin|spf13/pflag|"
    r"\bclap::|structopt|"
    r"OptionParser\.new|Thor\b|"
    r"System\.CommandLine")

_MOBILE_CODE = re.compile(
    r"AndroidManifest\.xml|\bUIApplication\b|SwiftUI|Jetpack\s*Compose|"
    r"react-native|flutter|capacitor|cordova|electron|tauri")

_INFRA_EXT = {".tf", ".tfvars", ".hcl"}
_INFRA_HINT = re.compile(r"(?:^|/)(?:terraform|helm|charts?|k8s|kubernetes|manifests|"
                         r"ansible|pulumi|cloudformation)(?:/|$)", re.I)

_ROUTE_HINT = re.compile(
    r"@(?:app|router|api|bp|blueprint)\.(?:get|post|put|patch|delete|route)\s*\(|"
    r"\b(?:app|router)\.(?:get|post|put|patch|delete|all|use)\s*\(\s*[\"'`/]|"
    r"http\.HandleFunc|mux\.(?:HandleFunc|Handle)\b|"
    r"@(?:GetMapping|PostMapping|RequestMapping|RestController)|"
    r"\[Http(?:Get|Post|Put|Delete)\]")

# A manifest telling us what the package is for is worth more than code that could be a
# test fixture, so manifests carry the heavy weights.
_MANIFESTS = ("package.json", "pyproject.toml", "setup.py", "setup.cfg", "go.mod",
              "Cargo.toml", "composer.json", "Gemfile", "pom.xml", "build.gradle",
              "Dockerfile", "docker-compose.yml", "Procfile")


def _read_manifest(path: str, read) -> str:
    try:
        text = read(path)
    except Exception:                                      # noqa: BLE001
        return ""
    return text or ""


def classify(paths: list, read, langs: dict | None = None) -> Context:
    """Classify a repository from its file list and a reader for individual files.

    `paths` is every scanned path, `read(path)` returns text or raises, `langs` is the
    inventory's language histogram. Deliberately cheap: a handful of manifest reads and one
    pass over the path list, because this runs once per scan.
    """
    score = {SERVER: 0.0, CLI: 0.0, LIBRARY: 0.0, MOBILE: 0.0, INFRA: 0.0}
    evidence: list = []
    lower = [p.lower() for p in paths]
    have = set(lower)

    def every(name: str, cap: int = 8) -> list:
        """Every manifest with this name, nearest the root first.

        A monorepo keeps the interesting manifest in a workspace, not at the root:
        bordrless-sdk's root package.json is `"private": true` with no `bin`, and the
        command it installs is declared in `packages/sdk/package.json`. Reading only the
        first one classified a published CLI as "could not place".
        """
        hits = [p for p, low in zip(paths, lower)
                if low == name or low.endswith("/" + name)]
        hits.sort(key=lambda p: (p.count("/"), len(p)))
        return hits[:cap]

    def seen(name: str) -> str:
        found = every(name, 1)
        return found[0] if found else ""

    # ---- manifests
    for pkg_path in every("package.json"):
        body = _read_manifest(pkg_path, read)
        if not body:
            continue
        where = "" if pkg_path.count("/") == 0 else " (" + pkg_path + ")"
        if re.search(r"\"bin\"\s*:", body):
            score[CLI] += 5
            evidence.append("package.json declares a `bin` entry, so it installs a "
                            "command" + where)
        if re.search(r"\"(?:main|module|exports|types)\"\s*:", body) \
                and not re.search(r"\"bin\"\s*:", body):
            score[LIBRARY] += 3
            evidence.append("package.json declares entry points but no `bin`" + where)
        for dep, kind, note in (
                (r"\"express\"", SERVER, "depends on express"),
                (r"\"fastify\"", SERVER, "depends on fastify"),
                (r"\"@nestjs/core\"", SERVER, "depends on NestJS"),
                (r"\"koa\"", SERVER, "depends on koa"),
                (r"\"next\"", SERVER, "depends on Next.js"),
                (r"\"commander\"|\"yargs\"|\"@oclif/core\"", CLI,
                 "depends on a command-line argument parser"),
                (r"\"react-native\"|\"electron\"|\"@tauri-apps/api\"", MOBILE,
                 "depends on a native app shell")):
            if re.search(dep, body):
                score[kind] += 3
                evidence.append(note)

    for name in ("pyproject.toml", "setup.py", "setup.cfg"):
        for path in every(name, 4):
            body = _read_manifest(path, read)
            if not body:
                continue
            if re.search(r"console_scripts|\[project\.scripts\]|entry_points", body):
                score[CLI] += 5
                evidence.append(name + " declares console scripts")
            elif re.search(r"packages\s*=|\[project\]", body):
                score[LIBRARY] += 2
            for dep, kind, note in ((r"fastapi|flask|django|starlette|aiohttp|tornado",
                                     SERVER, "depends on a web framework"),
                                    (r"\bclick\b|\btyper\b|argparse", CLI,
                                     "depends on a CLI framework")):
                if re.search(dep, body, re.I):
                    score[kind] += 3
                    evidence.append(note)

    for name in ("requirements.txt", "requirements-dev.txt", "Pipfile"):
        for path in every(name, 4):
            body = _read_manifest(path, read)
            if not body:
                continue
            if re.search(r"^\s*(?:flask|django|fastapi|starlette|aiohttp|tornado|"
                         r"gunicorn|uvicorn|waitress)\b", body, re.I | re.M):
                score[SERVER] += 4
                evidence.append(name + " pins a web framework or WSGI server")
            if re.search(r"^\s*(?:click|typer)\b", body, re.I | re.M):
                score[CLI] += 2

    for gomod in every("go.mod", 4):
        body = _read_manifest(gomod, read)
        if re.search(r"spf13/cobra|urfave/cli|alecthomas/kingpin", body):
            score[CLI] += 4
            evidence.append("go.mod requires a CLI framework")
        if re.search(r"gin-gonic|labstack/echo|gofiber|gorilla/mux|chi/v\d", body):
            score[SERVER] += 4
            evidence.append("go.mod requires an HTTP router")
        # a Go module whose name is an SDK and which has no main package is a library
        if re.search(r"^module\s+\S*(?:sdk|client|api|lib)\b", body, re.M | re.I):
            score[LIBRARY] += 3
            evidence.append("the Go module name describes an SDK or client library")

    if seen("Dockerfile") or seen("docker-compose.yml"):
        body = _read_manifest(seen("Dockerfile") or seen("docker-compose.yml"), read)
        if re.search(r"^\s*EXPOSE\s+\d+", body, re.M) or re.search(r"ports?\s*:", body):
            score[SERVER] += 3
            evidence.append("a container definition exposes a port")
    if seen("Procfile"):
        score[SERVER] += 3
        evidence.append("a Procfile declares a web process")

    # ---- shape of the tree
    if any(low.startswith("cmd/") for low in lower):
        score[CLI] += 2
        evidence.append("a cmd/ directory, the Go convention for executables")
    if any(re.search(r"(?:^|/)(?:cli|bin|cmd)/", low) for low in lower):
        score[CLI] += 1
    if any(re.search(r"(?:^|/)(?:routes?|controllers?|handlers?|api|views?|endpoints?)/",
                     low) for low in lower):
        score[SERVER] += 2
        evidence.append("directories named for request handling")
    infra_files = sum(1 for low in lower
                      if low.rsplit(".", 1)[-1] in ("tf", "tfvars", "hcl")
                      or _INFRA_HINT.search("/" + low))
    if infra_files and infra_files >= 0.4 * max(1, len(lower)):
        score[INFRA] += 5
        evidence.append("most of the repository is infrastructure definitions")
    if seen("AndroidManifest.xml".lower()) or any("ios/" in low for low in lower):
        score[MOBILE] += 3
        evidence.append("platform directories for a mobile app")

    # ---- a cheap look at the code itself, capped so it cannot outvote a manifest
    looked = 0
    for path, low in zip(paths, lower):
        if looked >= 40:
            break
        if not re.search(r"\.(?:py|js|ts|tsx|go|rb|java|cs|php|rs)$", low):
            continue
        if re.search(r"(?:^|/)(?:test|tests|spec|__tests__|example|examples|docs?)/", low):
            continue
        body = _read_manifest(path, read)
        if not body:
            continue
        looked += 1
        # A declared route or a bound listener is not circumstantial - it is the thing
        # itself - so it weighs as much as a manifest. Without this, a small Flask app
        # with no requirements.txt came out as "could not place".
        if _ROUTE_HINT.search(body) or _SERVER_CODE.search(body):
            score[SERVER] += 1.5
        if _CLI_CODE.search(body):
            score[CLI] += 0.8
        if _MOBILE_CODE.search(body):
            score[MOBILE] += 0.4
        if _ROUTE_HINT.search(body) or _SERVER_CODE.search(body):
            evidence.append("a listener or route declaration in the source")

    # A monorepo has several manifests saying the same thing, and the same note read twice
    # ("the Go module name describes an SDK; the Go module name describes an SDK") reads
    # like a bug. Order is kept because the first note is the strongest.
    seen_notes: set = set()
    evidence = [n for n in evidence
                if not (n in seen_notes or seen_notes.add(n))]

    ranked = sorted(score.items(), key=lambda kv: -kv[1])
    top, top_score = ranked[0]
    second = ranked[1][1]
    if top_score < 2:
        return Context(UNKNOWN, "low", tuple(evidence[:4]), tuple(ranked))
    conf = "high" if top_score >= 5 and top_score >= second * 2 else (
        "medium" if top_score >= 3 else "low")
    return Context(top, conf, tuple(evidence[:4]), tuple(ranked))


# ------------------------------------------------------------------- per-file override

_FILE_SERVER = re.compile(
    r"(?:^|/)(?:routes?|controllers?|handlers?|api|views?|endpoints?|middleware|"
    r"resolvers?|graphql|webhooks?)(?:/|$)", re.I)
_FILE_CLI = re.compile(r"(?:^|/)(?:cli|cmd|bin|console|scripts?)(?:/|$)", re.I)


def for_file(ctx: Context, path: str, text: str = "") -> Context:
    """Refine the repo context for one file.

    A monorepo can hold a service and a CLI; the file wins when its own evidence is
    unambiguous, because a route handler is a route handler whatever the repository mostly
    is. Only ever moves towards the stricter reading, except where a file is plainly the
    CLI of a library.
    """
    if text and (_SERVER_CODE.search(text) or _ROUTE_HINT.search(text)):
        if ctx.kind != SERVER:
            return Context(SERVER, "medium",
                           ("this file declares a route or starts a listener, whatever the "
                            "rest of the repository does",), ctx.scores)
        return ctx
    if _FILE_SERVER.search("/" + path) and ctx.kind in (LIBRARY, UNKNOWN):
        return Context(SERVER, "low",
                       ("this file sits in a request-handling directory",), ctx.scores)
    if ctx.kind in (LIBRARY, UNKNOWN) and _FILE_CLI.search("/" + path) \
            and (not text or _CLI_CODE.search(text)):
        return Context(CLI, "low",
                       ("this file sits in the command-line part of the project",),
                       ctx.scores)
    return ctx


# ------------------------------------------------------------------------- the gate
#
# factor 0.0 drops the finding (recorded, with the reason). Anything below 1.0 keeps it and
# says what is uncertain. Categories not listed are unaffected: a hardcoded secret is a
# hardcoded secret in every deployment.

_NO_REMOTE_ATTACKER = (
    "this runs as a command the user starts themselves, so there is no remote attacker "
    "and no internal network to reach from it")
_OPERATOR_IS_TRUSTED = (
    "in a library the caller supplies this, and the caller is the application operator "
    "rather than an attacker - whether it is reachable from untrusted input depends on the "
    "host application")

GATES: dict = {
    "ssrf": {CLI: (0.0, _NO_REMOTE_ATTACKER),
             LIBRARY: (0.45, _OPERATOR_IS_TRUSTED),
             INFRA: (0.3, "infrastructure definitions describe a deployment rather than "
                          "handle requests")},
    "xss": {CLI: (0.0, _NO_REMOTE_ATTACKER + ", and no browser renders its output"),
            LIBRARY: (0.5, _OPERATOR_IS_TRUSTED),
            INFRA: (0.2, "no browser renders this")},
    "redirect": {CLI: (0.0, _NO_REMOTE_ATTACKER), LIBRARY: (0.4, _OPERATOR_IS_TRUSTED)},
    "cors": {CLI: (0.0, _NO_REMOTE_ATTACKER), LIBRARY: (0.5, _OPERATOR_IS_TRUSTED)},
    "csrf": {CLI: (0.0, _NO_REMOTE_ATTACKER), LIBRARY: (0.5, _OPERATOR_IS_TRUSTED)},
    "authz": {CLI: (0.0, "a local tool has one user, who is already the operator"),
              LIBRARY: (0.5, _OPERATOR_IS_TRUSTED)},
    "authn": {CLI: (0.2, "a local tool authenticates on the user's behalf"),
              LIBRARY: (0.6, _OPERATOR_IS_TRUSTED)},
    "idor": {CLI: (0.0, "a local tool has one user"), LIBRARY: (0.5, _OPERATOR_IS_TRUSTED)},
    # A CLI can still be attacked - through a repository it clones, an archive it unpacks,
    # a config it reads - so these stay, with the precondition stated.
    "cmd": {CLI: (0.6, "the attacker has to control what you hand the tool - a file it "
                       "reads, an archive it unpacks, a repository it clones - rather "
                       "than reaching it over the network")},
    "argv": {CLI: (0.6, "the attacker has to control what you hand the tool")},
    "path": {CLI: (0.6, "the attacker has to control the input the tool is pointed at")},
    "dos": {CLI: (0.25, "a local tool that hangs wastes the operator's own time")},
    "tls": {LIBRARY: (0.5, "a library exposes this as an option for its caller to set; "
                           "whether it is ever set is the application's decision")},
    "config": {LIBRARY: (0.6, _OPERATOR_IS_TRUSTED)},
}


def gate(cat: str, ctx: Context) -> tuple:
    """(factor, reason). factor 1.0 and an empty reason means "no adjustment"."""
    row = GATES.get(cat)
    if not row:
        return 1.0, ""
    entry = row.get(ctx.kind)
    if not entry:
        return 1.0, ""
    factor, reason = entry
    if ctx.confidence == "low" and factor == 0.0:
        # not confident enough to delete a finding outright; keep it, heavily discounted
        return 0.3, reason + " (the deployment type was inferred weakly, so this is kept)"
    return factor, reason
