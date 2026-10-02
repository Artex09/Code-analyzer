"""Resolve a GitHub URL into a local working copy of the source tree."""
from __future__ import annotations

import io
import json
import re
import shutil
import subprocess
import time
import urllib.request
import urllib.error
import zipfile
from dataclasses import dataclass, asdict
from pathlib import Path

UA = "repo-xray/1.0 (local source analysis tool)"


class FetchError(RuntimeError):
    pass


@dataclass
class RepoSpec:
    owner: str
    repo: str
    ref: str | None = None      # branch, tag or commit
    subpath: str = ""           # limit analysis to this directory

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}"

    @property
    def dirname(self) -> str:
        return re.sub(r"[^A-Za-z0-9._-]", "-", f"{self.owner}__{self.repo}__{self.ref or 'default'}")

    def to_dict(self) -> dict:
        return asdict(self)


_HOSTS = ("github.com", "www.github.com", "raw.githubusercontent.com", "codeload.github.com")


def parse_github_url(raw: str) -> RepoSpec:
    """Accept the shapes a human actually pastes.

    github.com/o/r, .../tree/<ref>/<dir>, .../blob/<ref>/<file>, git@github.com:o/r.git,
    a bare o/r, or any of the above with a trailing .git, query or fragment.
    """
    if not raw or not raw.strip():
        raise FetchError("No URL given.")
    s = raw.strip().strip("<>").split("#")[0].split("?")[0]

    m = re.match(r"^git@([^:]+):(.+)$", s)
    if m:
        s = "https://" + m.group(1) + "/" + m.group(2)
    s = re.sub(r"^(git|ssh)\+?https?://", "https://", s)
    if not s.startswith(("http://", "https://")):
        if re.match(r"^[\w.-]+/[\w.-]+$", s):
            s = "https://github.com/" + s
        else:
            s = "https://" + s

    m = re.match(r"^https?://([^/]+)/(.*)$", s)
    if not m:
        raise FetchError("Could not parse " + repr(raw) + " as a repository URL.")
    host, path = m.group(1).lower(), m.group(2)
    if host not in _HOSTS:
        raise FetchError("Only github.com URLs are supported right now (got " + host + ").")

    parts = [p for p in path.split("/") if p]
    if len(parts) < 2:
        raise FetchError("URL needs at least an owner and a repository name.")
    owner, repo = parts[0], re.sub(r"\.git$", "", parts[1])
    ref, subpath = None, ""

    rest = parts[2:]
    if rest:
        kind = rest[0]
        if kind in ("tree", "blob") and len(rest) >= 2:
            ref = rest[1]
            subpath = "/".join(rest[2:])
            if kind == "blob":
                subpath = str(Path(subpath).parent).replace("\\", "/")
                if subpath == ".":
                    subpath = ""
        elif kind == "archive" and len(rest) >= 2:
            ref = re.sub(r"\.(zip|tar\.gz|tgz)$", "", rest[-1]).replace("refs/heads/", "")
    return RepoSpec(owner=owner, repo=repo, ref=ref, subpath=subpath.strip("/"))


def _http_json(url: str, timeout: int = 15):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return None


def repo_metadata(spec: RepoSpec) -> dict:
    """Best-effort public repo facts. Never fatal, the analysis works without it."""
    data = _http_json("https://api.github.com/repos/" + spec.owner + "/" + spec.repo) or {}
    lic = data.get("license") or {}
    return {
        "description": data.get("description") or "",
        "stars": data.get("stargazers_count"),
        "forks": data.get("forks_count"),
        "primary_language": data.get("language"),
        "default_branch": data.get("default_branch"),
        "pushed_at": data.get("pushed_at"),
        "license": lic.get("spdx_id"),
        "archived": data.get("archived"),
        "open_issues": data.get("open_issues_count"),
        "html_url": data.get("html_url") or ("https://github.com/" + spec.owner + "/" + spec.repo),
    }


def _run(cmd: list, cwd: Path | None = None, timeout: int = 600):
    return subprocess.run(
        cmd, cwd=str(cwd) if cwd else None, capture_output=True, text=True,
        timeout=timeout, encoding="utf-8", errors="replace",
    )


def _git_available() -> bool:
    try:
        return _run(["git", "--version"], timeout=20).returncode == 0
    except Exception:
        return False


def _clone(spec: RepoSpec, dest: Path, log) -> dict:
    url = "https://github.com/" + spec.owner + "/" + spec.repo + ".git"
    cmd = ["git", "clone", "--depth", "50", "--single-branch", "--no-tags", "--quiet"]
    if spec.ref:
        cmd += ["--branch", spec.ref]
    cmd += [url, str(dest)]
    log("git clone " + spec.slug + (" @ " + spec.ref if spec.ref else ""))
    proc = _run(cmd)
    if proc.returncode != 0 and spec.ref:
        # A commit sha cannot be used with --branch: clone the default branch, then fetch the sha.
        log("branch clone failed, retrying via default branch")
        shutil.rmtree(dest, ignore_errors=True)
        proc = _run(["git", "clone", "--depth", "50", "--single-branch", "--no-tags", "--quiet", url, str(dest)])
        if proc.returncode == 0:
            if _run(["git", "fetch", "--depth", "1", "origin", spec.ref], cwd=dest).returncode == 0:
                _run(["git", "checkout", "--quiet", "FETCH_HEAD"], cwd=dest)
    if proc.returncode != 0:
        raise FetchError((proc.stderr or proc.stdout or "git clone failed").strip()[:400])

    head = _run(["git", "rev-parse", "HEAD"], cwd=dest)
    branch = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=dest)
    last = _run(["git", "log", "-1", "--format=%cI|%an|%s"], cwd=dest)
    info = {
        "method": "git",
        "commit": (head.stdout or "").strip()[:40],
        "branch": (branch.stdout or "").strip(),
    }
    if last.returncode == 0 and "|" in last.stdout:
        bits = (last.stdout.strip().split("|", 2) + ["", ""])[:3]
        info["last_commit_at"], info["last_commit_author"], info["last_commit_subject"] = bits
    return info


def _zipball(spec: RepoSpec, dest: Path, log) -> dict:
    """Fallback when git is unavailable or the clone is blocked."""
    candidates = ([spec.ref] if spec.ref else []) + ["HEAD", "main", "master"]
    last_err = None
    for ref in [r for r in candidates if r]:
        if ref == "HEAD":
            url = "https://api.github.com/repos/" + spec.owner + "/" + spec.repo + "/zipball"
        else:
            url = "https://codeload.github.com/" + spec.owner + "/" + spec.repo + "/zip/refs/heads/" + ref
        log("downloading archive (" + ref + ")")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=180) as r:
                blob = r.read()
        except Exception as exc:
            last_err = exc
            continue
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            root = zf.namelist()[0].split("/")[0]
            tmp = dest.parent / (dest.name + ".unzip")
            shutil.rmtree(tmp, ignore_errors=True)
            zf.extractall(tmp)
            shutil.rmtree(dest, ignore_errors=True)
            (tmp / root).rename(dest)
            shutil.rmtree(tmp, ignore_errors=True)
        return {"method": "zipball", "branch": ref, "commit": ""}
    raise FetchError("Could not download source archive: " + str(last_err))


def fetch_repo(spec: RepoSpec, repos_dir: Path, log=lambda m: None, refresh: bool = False):
    """Return (source root path, fetch info). Reuses an existing copy unless refresh is set."""
    repos_dir.mkdir(parents=True, exist_ok=True)
    dest = repos_dir / spec.dirname
    info: dict = {}
    if dest.exists() and not refresh:
        log("reusing local copy")
        info = {"method": "cache", "branch": spec.ref or "", "commit": ""}
        head = _run(["git", "rev-parse", "HEAD"], cwd=dest)
        if head.returncode == 0:
            info["commit"] = head.stdout.strip()[:40]
    else:
        shutil.rmtree(dest, ignore_errors=True)
        t0 = time.time()
        if _git_available():
            try:
                info = _clone(spec, dest, log)
            except FetchError as exc:
                log("git failed (" + str(exc)[:80] + "), falling back to archive")
                shutil.rmtree(dest, ignore_errors=True)
                info = _zipball(spec, dest, log)
        else:
            info = _zipball(spec, dest, log)
        info["fetch_seconds"] = round(time.time() - t0, 1)

    root = dest
    if spec.subpath:
        candidate = dest / spec.subpath
        if candidate.is_dir():
            root = candidate
            info["scoped_to"] = spec.subpath
        else:
            log("subpath " + repr(spec.subpath) + " not found, analysing whole repo")
    return root, info
