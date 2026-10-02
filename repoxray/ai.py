"""AI deep-dive: hand the highest-risk files to a model and keep its structured verdict.

Heuristics decide *where* to look; the model decides *whether it is actually a bug* and
writes the reasoning. Backends are swappable - local Ollama by default, Claude if a key
is present, and a null backend so the app works with no model at all.
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request

OLLAMA_HOST = "http://127.0.0.1:11434"

SYSTEM_PROMPT = (
    "You are a senior application security engineer triaging source code for a bug bounty "
    "researcher. You judge exploitability, not style. You never invent code that is not in the "
    "excerpt.\n"
    "Rules you follow without exception:\n"
    "1. A dangerous sink that any external input can reach IS a finding. Report it, with the "
    "tainted value named and the sink line cited.\n"
    "2. safe_notes is only for patterns you can positively rule out, and each note must say why "
    "it cannot be reached or exploited (parameterised query, constant argument, escaped output, "
    "dead code). Never park a real issue there.\n"
    "3. probability must match the findings: at least 80 if you list a critical or high finding, "
    "at least 50 for a medium one, under 20 only when findings is empty.\n"
    "4. Output JSON only. No markdown, no prose outside the JSON object."
)

SCHEMA_HINT = """Answer with a single JSON object using exactly these keys:

  probability      integer 0-100, the chance a real reportable vulnerability exists in THIS file
  confidence       "low", "medium" or "high"
  summary          one or two sentences: what this file does and where the risk sits
  findings         array; one object per issue, each with:
                     title             your own short name for the issue, not the wording of the
                                       static flag above
                     category          command injection | sql injection | xss | path traversal |
                                       ssrf | deserialization | access control | authentication |
                                       crypto | secret | other
                     cwe               "CWE-nn" or ""
                     severity          "critical" | "high" | "medium" | "low"
                     lines             array of line numbers from the left column
                     explanation       why it is exploitable: name the tainted value, trace it to
                                       the sink, state what the attacker controls
                     attack_sketch     a concrete request, payload or input
                     needs_to_confirm  what to check elsewhere in the repo to prove it
  safe_notes       array of strings; flagged patterns you ruled out, each stating why

Report every sink an external input can reach. Return findings: [] only when you can justify
each flagged pattern as unreachable or already neutralised, and explain that in safe_notes."""



# ----------------------------------------------------------------- excerpting

def build_excerpt(text: str, focus_lines: list, max_lines: int = 420, window: int = 14) -> tuple:
    """Return (numbered excerpt, was_trimmed). Keeps a head plus windows around each hit."""
    lines = text.splitlines()
    n = len(lines)
    if n <= max_lines:
        body = "\n".join(str(i + 1).rjust(5) + " | " + ln for i, ln in enumerate(lines))
        return body, False

    keep: set = set(range(0, min(55, n)))          # imports, decorators, class headers
    for ln in focus_lines:
        lo = max(0, ln - 1 - window)
        hi = min(n, ln - 1 + window + 1)
        keep.update(range(lo, hi))
        if len(keep) > max_lines:
            break

    out = []
    prev = -2
    for i in sorted(keep):
        if i != prev + 1 and out:
            out.append("      |  ... " + str(i - prev - 1) + " lines omitted ...")
        out.append(str(i + 1).rjust(5) + " | " + lines[i])
        prev = i
    return "\n".join(out), True


def build_prompt(rec: dict, text: str) -> str:
    focus = rec.get("match_lines") or []
    excerpt, trimmed = build_excerpt(text, focus)

    flags = []
    for h in rec.get("hits", [])[:14]:
        flags.append("  line " + str(h["line"]) + "  [" + h["cat"] + "/" + (h["cwe"] or "-") + "] "
                     + h["title"] + " -> " + h["why"])
    signals = []
    if rec.get("entrypoints"):
        signals.append("entrypoints: " + ", ".join(sorted({e["kind"] for e in rec["entrypoints"]})))
    if rec.get("sources"):
        signals.append("reads untrusted input: " + ", ".join(s["id"] for s in rec["sources"][:6]))
    if rec.get("path_signals"):
        signals.append("path signals: " + ", ".join(s["label"] for s in rec["path_signals"]))
    if rec.get("is_test"):
        signals.append("NOTE: this path looks like tests/examples, weigh reachability accordingly")

    parts = [
        "FILE: " + rec["path"],
        "LANGUAGE: " + str(rec.get("lang")) + "   LINES: " + str(rec.get("lines")),
        "HEURISTIC SCORE: " + str(rec.get("score")) + "/100 (" + str(rec.get("band")) + ")",
        "",
        "STATIC PATTERN FLAGS (may be false positives, judge them):",
        "\n".join(flags) if flags else "  none",
        "",
        ("CONTEXT SIGNALS:\n  " + "\n  ".join(signals)) if signals else "CONTEXT SIGNALS: none",
        "",
        "SOURCE" + (" (trimmed to relevant windows, line numbers preserved)" if trimmed else "") + ":",
        "-" * 68,
        excerpt,
        "-" * 68,
        "",
        "Assess only what this excerpt supports. Cite line numbers from the left column.",
        "Judge each static flag above: exploitable (a finding) or ruled out (a safe note).",
        SCHEMA_HINT,
    ]
    return "\n".join(parts)


# ------------------------------------------------------------- json recovery

def parse_verdict(raw: str) -> dict:
    if not raw:
        return {"error": "empty response from model"}
    s = raw.strip()
    fence = re.search(r"```(?:json)?\s*(.+?)```", s, re.S)
    if fence:
        s = fence.group(1).strip()
    start = s.find("{")
    if start == -1:
        return {"error": "no JSON object in response", "raw": raw[:500]}
    depth, end = 0, None
    in_str, esc = False, False
    for i, ch in enumerate(s[start:], start):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    chunk = s[start:end] if end else s[start:]
    try:
        data = json.loads(chunk)
    except json.JSONDecodeError:
        try:
            data = json.loads(re.sub(r",\s*([}\]])", r"\1", chunk))
        except json.JSONDecodeError as exc:
            return {"error": "unparseable JSON (" + str(exc)[:80] + ")", "raw": raw[:500]}
    return normalise_verdict(data)


def normalise_verdict(data: dict) -> dict:
    if not isinstance(data, dict):
        return {"error": "model returned a non-object"}
    prob = data.get("probability", data.get("likelihood", 0))
    try:
        prob = max(0, min(100, int(round(float(prob)))))
    except (TypeError, ValueError):
        prob = 0
    conf = str(data.get("confidence", "low")).lower()
    if conf not in ("low", "medium", "high"):
        conf = "medium" if conf.startswith("med") else "low"

    findings = []
    for f in (data.get("findings") or [])[:12]:
        if not isinstance(f, dict):
            continue
        lines = f.get("lines") or f.get("line") or []
        if isinstance(lines, (int, float, str)):
            lines = [lines]
        clean_lines = []
        for x in lines[:24]:
            try:
                n = int(str(x).strip())
            except (TypeError, ValueError):
                continue
            if n not in clean_lines:
                clean_lines.append(n)
        # small models like to dump every flagged line into every finding
        clean_lines = sorted(clean_lines)[:6]
        sev = str(f.get("severity", "medium")).lower()
        if sev not in ("critical", "high", "medium", "low", "info"):
            sev = "medium"
        findings.append({
            "title": str(f.get("title", "unnamed finding"))[:160],
            "category": str(f.get("category", ""))[:60],
            "cwe": str(f.get("cwe", ""))[:16],
            "severity": sev,
            "lines": clean_lines,
            "explanation": str(f.get("explanation", ""))[:1600],
            "attack_sketch": str(f.get("attack_sketch", f.get("exploit", "")))[:900],
            "needs_to_confirm": str(f.get("needs_to_confirm", ""))[:600],
        })
    notes = [str(x)[:400] for x in (data.get("safe_notes") or [])[:8] if x]
    return {
        "probability": prob,
        "confidence": conf,
        "summary": str(data.get("summary", ""))[:900],
        "findings": findings,
        "safe_notes": notes,
    }


# ------------------------------------------------------------------- backends

class Backend:
    name = "null"
    model = ""

    def available(self) -> tuple:
        return False, "no backend configured"

    def review(self, rec: dict, text: str) -> dict:
        return {"error": "AI backend not configured", "probability": 0, "confidence": "low",
                "findings": [], "safe_notes": [], "backend": self.name}


class OllamaBackend(Backend):
    name = "ollama"

    def __init__(self, model: str = "qwen2.5:7b", host: str = OLLAMA_HOST,
                 num_ctx: int = 8192, timeout: int = 600):
        self.model = model
        self.host = host.rstrip("/")
        self.num_ctx = num_ctx
        self.timeout = timeout

    def _post(self, path: str, payload: dict, timeout: int | None = None) -> dict:
        req = urllib.request.Request(
            self.host + path,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout or self.timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))

    def available(self) -> tuple:
        try:
            req = urllib.request.Request(self.host + "/api/tags")
            with urllib.request.urlopen(req, timeout=5) as r:
                tags = json.loads(r.read().decode("utf-8", "replace"))
            names = [m.get("name", "") for m in tags.get("models", [])]
            if not names:
                return False, "ollama is running but has no models pulled"
            if self.model not in names:
                return True, "model " + self.model + " not pulled (have: " + ", ".join(names[:4]) + ")"
            return True, "ollama ready (" + self.model + ")"
        except Exception as exc:
            return False, "ollama not reachable at " + self.host + " (" + type(exc).__name__ + ")"

    def review(self, rec: dict, text: str) -> dict:
        prompt = build_prompt(rec, text)
        t0 = time.time()
        try:
            data = self._post("/api/chat", {
                "model": self.model,
                "stream": False,
                "format": "json",
                "keep_alive": "10m",
                "options": {"temperature": 0.1, "top_p": 0.9, "num_ctx": self.num_ctx,
                            "num_predict": 1400},
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
            })
        except urllib.error.URLError as exc:
            return {"error": "ollama request failed: " + str(exc.reason)[:120], "probability": 0,
                    "confidence": "low", "findings": [], "safe_notes": [],
                    "backend": self.name, "model": self.model,
                    "elapsed": round(time.time() - t0, 1)}
        except Exception as exc:
            return {"error": type(exc).__name__ + ": " + str(exc)[:120], "probability": 0,
                    "confidence": "low", "findings": [], "safe_notes": [],
                    "backend": self.name, "model": self.model,
                    "elapsed": round(time.time() - t0, 1)}
        raw = (data.get("message") or {}).get("content", "")
        verdict = parse_verdict(raw)
        verdict.setdefault("probability", 0)
        verdict.setdefault("findings", [])
        verdict.setdefault("safe_notes", [])
        verdict.setdefault("confidence", "low")
        verdict["backend"] = self.name
        verdict["model"] = self.model
        verdict["elapsed"] = round(time.time() - t0, 1)
        verdict["prompt_tokens"] = data.get("prompt_eval_count")
        verdict["output_tokens"] = data.get("eval_count")
        return verdict


class AnthropicBackend(Backend):
    name = "claude"

    def __init__(self, model: str = "claude-sonnet-5", api_key: str | None = None,
                 max_tokens: int = 2000):
        self.model = model
        self.api_key = api_key
        self.max_tokens = max_tokens
        self._client = None

    def _get_client(self):
        if self._client is None:
            import anthropic  # imported lazily so the app runs without the SDK
            self._client = anthropic.Anthropic(api_key=self.api_key) if self.api_key \
                else anthropic.Anthropic()
        return self._client

    def available(self) -> tuple:
        import os
        if not (self.api_key or os.environ.get("ANTHROPIC_API_KEY")):
            return False, "no ANTHROPIC_API_KEY in the environment"
        try:
            import anthropic  # noqa: F401
        except ImportError:
            return False, "anthropic SDK not installed"
        return True, "claude ready (" + self.model + ")"

    def review(self, rec: dict, text: str) -> dict:
        t0 = time.time()
        try:
            client = self._get_client()
            msg = client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": build_prompt(rec, text)}],
            )
            raw = "".join(getattr(b, "text", "") for b in msg.content)
        except Exception as exc:
            return {"error": type(exc).__name__ + ": " + str(exc)[:160], "probability": 0,
                    "confidence": "low", "findings": [], "safe_notes": [],
                    "backend": self.name, "model": self.model,
                    "elapsed": round(time.time() - t0, 1)}
        verdict = parse_verdict(raw)
        verdict["backend"] = self.name
        verdict["model"] = self.model
        verdict["elapsed"] = round(time.time() - t0, 1)
        return verdict


def list_ollama_models(host: str = OLLAMA_HOST) -> list:
    try:
        req = urllib.request.Request(host.rstrip("/") + "/api/tags")
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        out = []
        for m in data.get("models", []):
            out.append({"name": m.get("name"), "size": m.get("size"),
                        "family": (m.get("details") or {}).get("family")})
        return out
    except Exception:
        return []


def make_backend(kind: str, model: str = "", num_ctx: int = 8192) -> Backend:
    kind = (kind or "ollama").lower()
    if kind == "ollama":
        return OllamaBackend(model=model or "qwen2.5:7b", num_ctx=num_ctx)
    if kind in ("claude", "anthropic"):
        return AnthropicBackend(model=model or "claude-sonnet-5")
    return Backend()
