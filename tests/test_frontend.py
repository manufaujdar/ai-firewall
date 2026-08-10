from fastapi.testclient import TestClient

from ai_firewall.main import app
from ai_firewall.web_ui import CONSOLE_CSS, CONSOLE_HTML, CONSOLE_JS


def test_console_assets_are_served_with_safe_content_types() -> None:
    with TestClient(app) as client:
        css = client.get("/assets/console.css")
        javascript = client.get("/assets/console.js")

    assert css.status_code == 200
    assert css.headers["content-type"].startswith("text/css")
    assert javascript.status_code == 200
    assert javascript.headers["content-type"].startswith("text/javascript")


def test_console_has_restrictive_browser_security_headers() -> None:
    with TestClient(app) as client:
        response = client.get("/")

    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert "camera=()" in response.headers["permissions-policy"]


def test_console_has_accessible_local_research_boundaries() -> None:
    assert '<html lang="en">' in CONSOLE_HTML
    assert 'aria-live="polite"' in CONSOLE_HTML
    assert "not a complete DLP product" in CONSOLE_HTML
    assert ":focus-visible" in CONSOLE_CSS
    assert "prefers-reduced-motion" in CONSOLE_CSS


def test_console_does_not_persist_api_key_or_render_dynamic_html() -> None:
    assert "localStorage.setItem('key'" not in CONSOLE_JS
    assert "sessionStorage" not in CONSOLE_JS
    assert "innerHTML" not in CONSOLE_JS
    assert "textContent" in CONSOLE_JS
