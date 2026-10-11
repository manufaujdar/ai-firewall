"""Synthetic Chromium regressions; all API traffic is intercepted and local."""

import os
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]


def fixture(browser, assets, blocked_storage=False):
    page = browser.new_page(viewport={"width": 1280, "height": 800}, reduced_motion="reduce")
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    if blocked_storage:
        page.add_init_script(
            "Object.defineProperty(window, 'localStorage', {get(){throw new DOMException('Synthetic denied storage', 'SecurityError')}})"
        )

    def route(request):
        from urllib.parse import urlparse

        url = urlparse(request.request.url)
        if url.hostname != "synthetic.test":
            request.abort()
        elif url.path in assets:
            kind = (
                "text/css"
                if url.path.endswith(".css")
                else "text/javascript"
                if url.path.endswith(".js")
                else "text/html"
            )
            body = assets[url.path] + (
                ";window.__syntheticAppReady=true;" if url.path.endswith(".js") else ""
            )
            request.fulfill(body=body, content_type=kind)
        elif url.path.startswith("/v1/"):
            request.fulfill(json={"execution_mode": "mock", "runtime_credentials_allowed": False})
        else:
            request.abort()

    page.route("**/*", route)
    page.goto("https://synthetic.test/")
    page.wait_for_function("window.__syntheticAppReady === true")
    return page, errors


def run(browser):
    import ast

    tree = ast.parse((ROOT / "src/ai_firewall/web_ui.py").read_text())
    constants = {
        node.targets[0].id: ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign)
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id.startswith("CONSOLE_")
    }
    page, errors = fixture(
        browser,
        {
            "/": constants["CONSOLE_HTML"],
            "/assets/console.css": constants["CONSOLE_CSS"],
            "/assets/console.js": constants["CONSOLE_JS"],
        },
    )
    calls = page.evaluate(
        "()=>{window.motionCalls=[]; HTMLElement.prototype.scrollIntoView=function(options){motionCalls.push(options)};renderResult({requestId:'synthetic',timestamp:'2026-10-11T00:00:00Z',findingCount:0,rules:[],response:{decision:'block',findings:[]}}); return motionCalls}"
    )
    assert calls and calls[-1].get("behavior") != "smooth"
    page.locator("#refresh-history").click()
    assert page.locator("#key").evaluate("el=>el===document.activeElement")
    deletes = []
    page.on(
        "request",
        lambda request: deletes.append(request.method) if request.method == "DELETE" else None,
    )
    page.locator("#key").fill("SYNTHETIC-local-fixture-key-not-a-real-credential")
    page.once("dialog", lambda dialog: dialog.dismiss())
    page.locator("#clear-history").click()
    assert not deletes
    assert page.evaluate("localStorage.length+sessionStorage.length") == 0
    assert not errors, errors
    page.close()


if __name__ == "__main__":
    with sync_playwright() as playwright:
        options = {"headless": True}
        if os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH"):
            options["executable_path"] = os.environ["PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH"]
        browser = playwright.chromium.launch(**options)
        try:
            run(browser)
            print("Synthetic browser regressions passed")
        finally:
            browser.close()
