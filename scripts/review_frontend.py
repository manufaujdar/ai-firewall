"""Deterministic, dependency-free source review for the local console."""

from __future__ import annotations

import sys
from dataclasses import dataclass

from ai_firewall.web_ui import CONSOLE_CSS, CONSOLE_HTML, CONSOLE_JS


@dataclass(frozen=True)
class Check:
    area: str
    description: str
    passed: bool


def review() -> list[Check]:
    checks = [
        Check("accessibility", "document language is declared", '<html lang="en">' in CONSOLE_HTML),
        Check("accessibility", "skip link and main landmark exist", "skip-link" in CONSOLE_HTML and '<main id="workspace">' in CONSOLE_HTML),
        Check("accessibility", "dynamic status is announced", 'aria-live="polite"' in CONSOLE_HTML),
        Check("accessibility", "visible keyboard focus is defined", ":focus-visible" in CONSOLE_CSS),
        Check("responsive", "mobile layout breakpoint exists", "@media(max-width:720px)" in CONSOLE_CSS),
        Check("responsive", "reduced motion is respected", "prefers-reduced-motion" in CONSOLE_CSS),
        Check("clarity", "research limitations are visible", "not a complete DLP product" in CONSOLE_HTML),
        Check("clarity", "unsupported formats are named", "Files, images, audio" in CONSOLE_HTML),
        Check("interaction", "primary action follows payload input", CONSOLE_HTML.index('id="payload"') < CONSOLE_HTML.index('id="scan"')),
        Check("interaction", "advanced settings are collapsible", "<details>" in CONSOLE_HTML),
        Check("privacy", "API key is not stored", "localStorage.setItem('key'" not in CONSOLE_JS and "sessionStorage" not in CONSOLE_JS),
        Check("privacy", "history is explicitly local", "Local history" in CONSOLE_HTML and "localStorage" in CONSOLE_JS),
        Check("security", "dynamic history uses textContent", "title.textContent" in CONSOLE_JS and "innerHTML" not in CONSOLE_JS),
        Check("maintainability", "CSS and JS use separate asset routes", "/assets/console.css" in CONSOLE_HTML and "/assets/console.js" in CONSOLE_HTML),
    ]
    return checks


def main() -> int:
    checks = review()
    for check in checks:
        mark = "PASS" if check.passed else "FAIL"
        print(f"[{mark}] {check.area}: {check.description}")
    failures = [check for check in checks if not check.passed]
    print(f"\n{len(checks) - len(failures)}/{len(checks)} checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
