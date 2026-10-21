"""The bundled list: the editions must agree on it.

The canonical asset is the one the Android edition ships
(app/src/main/assets/bundled-blocklist.txt). The Debian edition
never forks a copy into its own tree: its tests read the canonical
asset, and its package build copies that same asset (byte-checked)
into the .deb. These pins are the drift alarm — a deliberate list
update changes the asset and these pins in the same commit.
"""
import hashlib

from conftest import CANONICAL_LIST
from sphinx_deb.core.blocklist import Blocklist
from sphinx_deb.core.validation import parse_and_validate

#: SHA-256 of the canonical asset as shipped at this commit.
CANONICAL_SHA256 = "5fce814e8f675532fe53cbd03848ebd438cf30635a9f581086a3a469f30c086e"


def _lines():
    return CANONICAL_LIST.read_text(encoding="utf-8", errors="replace").splitlines()


def test_canonical_asset_is_the_one_this_edition_expects():
    digest = hashlib.sha256(CANONICAL_LIST.read_bytes()).hexdigest()
    assert digest == CANONICAL_SHA256


def test_bundled_list_parses_to_the_audited_count():
    parsed = Blocklist.from_lines(_lines())
    assert parsed.size == 71_491
    validated = parse_and_validate(_lines())
    assert validated is not None and validated.size == 71_491


def test_bundled_list_spot_checks():
    parsed = Blocklist.from_lines(_lines())
    # Names any StevenBlack unified list carries.
    assert parsed.is_blocked("doubleclick.net")
    assert parsed.is_blocked("ads.doubleclick.net")
    # And the rails held on real-world data.
    assert not parsed.is_blocked("localhost")
    assert not parsed.is_blocked("com")
