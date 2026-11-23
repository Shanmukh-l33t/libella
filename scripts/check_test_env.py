"""Fail loudly when the test environment silently loses whole test groups.

A missing Chromium (or an import path that stops resolving a directory) turns
tests into skips instead of failures, so a suite can look greener while covering
less. This check asserts the critical groups are still COLLECTED and that
Playwright can actually launch Chromium, and it prints the total so a drop is
visible in the log.

Usage: python scripts/check_test_env.py [-v]
Exit 1 on any shortfall. Run it in CI after `playwright install chromium`.
"""
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Floors, not targets: raise them when a group grows so a later drop is caught.
GROUPS = {
    "tests/browser": 4,
    "tests/authbrowser": 15,
    "tests/test_egress_enforcement.py": 14,
}
TOTAL_FLOOR = 920


def collected(path: str) -> int | None:
    out = subprocess.run([sys.executable, "-m", "pytest", path, "-q", "--collect-only"],
                         cwd=ROOT, capture_output=True, text=True,
                         env={**os.environ, "PYTHONPATH": str(ROOT / "src")})
    m = re.search(r"(\d+) tests? collected", out.stdout + out.stderr)
    return int(m.group(1)) if m else None


def browser_ok() -> str | None:
    """None when Chromium launches, else the reason."""
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:  # noqa: BLE001 - any import failure means no browser
        return f"playwright not importable: {e}"
    try:
        with sync_playwright() as p:
            b = p.chromium.launch()
            b.close()
        return None
    except Exception as e:  # noqa: BLE001
        return f"chromium will not launch: {str(e).splitlines()[0]} (fix: python -m playwright install chromium)"


def main() -> int:
    bad = []
    for path, floor in GROUPS.items():
        n = collected(path)
        state = "ok" if n is not None and n >= floor else "SHORT"
        print(f"{path:36s} collected {str(n) if n is not None else '?':>4s}  floor {floor:>4d}  {state}")
        if state == "SHORT":
            bad.append(f"{path}: {n} collected, floor {floor}")
    total = collected("tests")
    state = "ok" if total is not None and total >= TOTAL_FLOOR else "SHORT"
    print(f"{'tests':36s} collected {str(total) if total is not None else '?':>4s}  floor {TOTAL_FLOOR:>4d}  {state}")
    if state == "SHORT":
        bad.append(f"tests: {total} collected, floor {TOTAL_FLOOR}")
    reason = browser_ok()
    print(f"{'playwright chromium':36s} {'launches' if reason is None else 'UNAVAILABLE'}")
    if reason:
        bad.append(reason)
    if bad:
        print("\nFAIL: " + "; ".join(bad))
        return 1
    print("\nPASS: critical test groups collected and Chromium launches")
    return 0


if __name__ == "__main__":
    sys.exit(main())
