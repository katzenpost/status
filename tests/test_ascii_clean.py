"""Enforce the project's character policy for authored files.

All authored Python, JS, HTML and JSON must be 7-bit ASCII, with the sole
exception of a small whitelist of UI glyphs: the lambda symbol and the two
menu glyphs. Vendored third-party assets are not checked here.
"""

import glob
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

# lambda, hamburger menu, multiplication-x (close).
WHITELIST = {"λ", "☰", "✕"}


def _authored_files():
    pats = [
        "src/katzenpost_status/*.py",
        "src/katzenpost_status/assets/*.html",
        "src/katzenpost_status/assets/*.js",
        "src/katzenpost_status/assets/features/*.js",
        "src/katzenpost_status/data/*.json",
        "src/katzenpost_status/assets/earth/*.json",
        "tests/*.py",
    ]
    out = []
    for pat in pats:
        out.extend(glob.glob(str(ROOT / pat)))
    return out


def test_authored_files_are_ascii_plus_whitelist():
    offenders = {}
    for f in _authored_files():
        text = Path(f).read_text(encoding="utf-8")
        bad = sorted({c for c in text if ord(c) > 127 and c not in WHITELIST})
        if bad:
            offenders[f] = [hex(ord(c)) for c in bad]
    assert not offenders, f"non-ascii (outside whitelist) found: {offenders}"
