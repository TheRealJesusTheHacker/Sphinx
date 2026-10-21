"""The bundled StevenBlack list: the editions must agree on it. The
Android edition parses its asset to exactly 71,491 domains — so must
this one (same file, same parser rules)."""
from pathlib import Path

from sphinx_win.core.blocklist import Blocklist
from sphinx_win.core.validation import parse_and_validate

ASSET = (
    Path(__file__).resolve().parent.parent
    / "src" / "sphinx_win" / "data" / "bundled-blocklist.txt"
)


def test_bundled_list_parses_to_the_audited_count():
    lines = ASSET.read_text(encoding="utf-8", errors="replace").splitlines()
    parsed = Blocklist.from_lines(lines)
    assert parsed.size == 71_491
    validated = parse_and_validate(lines)
    assert validated is not None and validated.size == 71_491


def test_bundled_list_spot_checks():
    lines = ASSET.read_text(encoding="utf-8", errors="replace").splitlines()
    parsed = Blocklist.from_lines(lines)
    # Names any StevenBlack unified list carries.
    assert parsed.is_blocked("doubleclick.net")
    assert parsed.is_blocked("ads.doubleclick.net")
    # And the rails held on real-world data.
    assert not parsed.is_blocked("localhost")
    assert not parsed.is_blocked("com")
