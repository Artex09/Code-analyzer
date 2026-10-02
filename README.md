# RepoXray

Paste a GitHub URL, get the source tree organised several ways at once — plain layout, ranked by
how likely each file is to contain a flaw, grouped by weakness class, and by attack surface. Then
the local model reads the top of that ranking and says which of the leads are real.

Built for bug bounty triage: the point is deciding *where to spend the next hour*, not producing a
scanner report.

## Run it

```
cd C:\Users\jmala\repo-xray
python run.py
```

Opens `http://127.0.0.1:7331/` in your browser. `start.bat` does the same by double-click.
A second launch on the same port hands over to the running instance instead of splitting state.

Options: `--port 7331`, `--host 127.0.0.1`, `--no-browser`, `--debug`.

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

## How the score works

Three rule families run over every readable file:

- **sink rules** (~154) — dangerous operations per language: `shell=True`, `unserialize`,
  `eval`, `readObject`, string-built SQL, `InsecureSkipVerify`, `dangerouslySetInnerHTML`,
  hardcoded credentials, `pull_request_target`, suppressed security linters, and so on.
- **source rules** — where untrusted input enters: `request.args`, `req.body`, `$_GET`,
  `getParameter`, `r.FormValue`, `params[`, `argv`, lambda events.
- **entrypoint rules** — route decorators, controllers, handlers, RPC services, CLI mains,
  schedulers.

Then:

- a file holding **both a source and a sink** is boosted 1.4x — that is the single strongest signal
- an entrypoint plus a sink adds another 1.15x
- **path names carry weight**: `auth/`, `admin/`, `payment/`, `crypto/`, `upload/`, `legacy/`
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
`n`/`p` next / previous hit · `1`-`7` views · `t` cycle triage · `x` dismiss · `y` copy evidence ·
`a` ai-read open file · `r` download report · `?` help

`ctrl+k` fuzzy-matches every path in the repo; prefix with `>` for views and actions. The code
viewer carries a hit minimap on its right edge, the split between list and code is draggable, and
`density` toggles row spacing. View, density, split width, filters and model choice persist in
localStorage.

URLs are shareable: `?view=classes#<scanId>/routes/login.ts` reopens exactly that file.

## Layout

```
repoxray/
  fetch.py      GitHub URL parsing, shallow clone, zipball fallback, repo metadata
  inventory.py  tree walk, language/kind classification, test|vendored|generated detection
  rules.py      the pattern knowledge base: sinks, sources, entrypoints, path signals
  score.py      matching, evidence capture, risk scoring
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

## Rule corpus

```
python tests/rule_corpus.py        # all languages
python tests/rule_corpus.py js     # one section
```

Labelled cases, most lifted verbatim from repositories the scanner was run against: each says which
rules must fire and which must stay silent. Add a case here before changing a regex — a rule that
gets broader usually gets noisier, and this is what proves it did not. The false-positive cases
matter more than the positive ones.

## Self test

```
python run.py        # one terminal
python selftest.py   # another
```

Drives the running console in headless Chrome/Edge: loads a scan from history, switches views,
collapses groups, applies band/text/noise filters, opens a file, jumps to a hit line, expands the
tree, drills through a hotspot, and exercises `esc`/`j`/`enter`. It checks *computed* styles, which
is what catches a panel that is marked hidden but still painted. Run it after adding a view or
touching `renderView()`. The page it drives is `static/_selftest.html`.

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

## Adding a rule

One tuple in `rules.py`: `(id, category, title, weight 1-10, languages, regex, case_insensitive, why)`.
The `why` string is shown in the UI and passed to the model, so write it as the reason a reviewer
should care. New categories go in `CATEGORIES` with a CWE and an accent colour.

## Notes and limits

- Regex matching, not dataflow: it finds candidate sinks, it cannot prove reachability. Cross-file
  taint is exactly what the AI pass and your own reading are for.
- Files over ~1.5MB are truncated for matching; binaries are inventoried but not scanned.
- Scans cap at 20,000 files.
- GitHub metadata is fetched unauthenticated, so it can be rate-limited — the scan still works.
- Only public GitHub repos over HTTPS. Private repos work if your local git credentials already do.
