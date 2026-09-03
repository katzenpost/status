"""Tests for the main-page auto-refresh poller injection (status.py).

The poller is a tiny inline script injected into the rich HTML report just
before </body>. It is pure string logic, so it is unit-tested here without
driving a live render.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from katzenpost_status import status  # noqa: E402


def test_poller_not_injected_when_disabled():
    html = "<html><body>hi</body></html>"
    assert status._inject_html_poller(html, "index.meta.json", "t", 0) == html
    assert status._inject_html_poller(html, "index.meta.json", "t", -1) == html


def test_poller_injected_before_body_close():
    html = "<html><body>hi</body></html>"
    out = status._inject_html_poller(html, "index.meta.json", "2026-09-03T00:00:00Z", 60)
    assert out != html
    assert "<script>" in out
    assert "index.meta.json" in out
    assert "2026-09-03T00:00:00Z" in out
    assert "location.reload()" in out
    # Injected before the closing body tag, exactly once.
    assert out.count("</body>") == 1
    assert out.index("<script>") < out.index("</body>")


def test_poller_appended_when_no_body_tag():
    html = "<html>no body tag</html>"
    out = status._inject_html_poller(html, "index.meta.json", "t", 30)
    assert out.startswith(html)
    assert "<script>" in out
