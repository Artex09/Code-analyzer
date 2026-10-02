"""Drive the running console in a headless browser and report what broke.

Useful after adding a view or a renderer: it clicks through history, view switching, filters,
the code viewer and the keyboard shortcuts, and checks computed styles (which a DOM dump cannot).

    python run.py                # in one terminal
    python selftest.py           # in another
"""
from __future__ import annotations

import html
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

BROWSERS = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
]


def find_browser() -> str | None:
    for path in BROWSERS:
        if Path(path).exists():
            return path
    return None


def main() -> int:
    # the report contains triage glyphs; the Windows console defaults to cp1252
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    port = sys.argv[1] if len(sys.argv) > 1 else "7331"
    base = "http://127.0.0.1:" + port
    try:
        urllib.request.urlopen(base + "/api/bootstrap", timeout=5).read()
    except Exception as exc:
        print("RepoXray is not answering on " + base + " (" + type(exc).__name__ + ").")
        print("Start it first:  python run.py")
        return 2

    browser = find_browser()
    if not browser:
        print("No Chrome or Edge found; cannot run the browser test.")
        return 2

    print("driving " + base + " with " + Path(browser).name + " ...")
    proc = subprocess.run(
        [browser, "--headless=new", "--disable-gpu", "--no-sandbox", "--window-size=1500,950",
         "--dump-dom", "--virtual-time-budget=60000", base + "/static/_selftest.html"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300,
    )
    m = re.search(r'<div id="out">(.*?)</div>', proc.stdout or "", re.S)
    if not m:
        print("the test page produced no result (did it finish loading?)")
        return 1
    report = html.unescape(m.group(1))
    print(report)
    return 1 if "FAIL" in report.split("\n")[0] else 0


if __name__ == "__main__":
    sys.exit(main())
