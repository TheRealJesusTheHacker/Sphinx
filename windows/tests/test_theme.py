"""The Sphinx palette (app/theme.py): basalt black, sandstone,
bronze-gold — the stone guardian's identity, recorded in
windows/README.md for every other edition and surface to inherit.

Pinned here like the sibling tools pin theirs: every text pairing
at WCAG 4.5:1 or better against the surface it actually sits on,
the fleet-standard danger red, and no purple anywhere (that
exception is Beerus's alone).
"""
import colorsys

from sphinx_win.app import theme


def _luminance(hex_value: str) -> float:
    h = hex_value.lstrip("#")
    channels = [int(h[i : i + 2], 16) / 255 for i in (0, 2, 4)]

    def linear(c: float) -> float:
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = (linear(c) for c in channels)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_ratio(foreground: str, background: str) -> float:
    lf, lb = _luminance(foreground), _luminance(background)
    hi, lo = max(lf, lb), min(lf, lb)
    return (hi + 0.05) / (lo + 0.05)


def test_every_text_pairing_meets_wcag_aa():
    for name, (foreground, background) in theme.TEXT_PAIRINGS.items():
        ratio = contrast_ratio(foreground, background)
        assert ratio >= 4.5, f"{name}: {foreground} on {background} is {ratio:.2f}:1"


def test_danger_is_the_fleet_standard_red():
    assert theme.DANGER == "#e5534b"


def test_no_purple_anywhere_in_the_palette():
    palette = {
        name: getattr(theme, name)
        for name in dir(theme)
        if name.isupper() and isinstance(getattr(theme, name), str)
        and getattr(theme, name).startswith("#")
    }
    assert palette  # the scan found the palette at all
    for name, hex_value in palette.items():
        h = hex_value.lstrip("#")
        r, g, b = (int(h[i : i + 2], 16) / 255 for i in (0, 2, 4))
        hue, _lightness, saturation = colorsys.rgb_to_hls(r, g, b)
        if saturation > 0.12:
            # The violet band (roughly 245°–310°) is out of bounds.
            assert not (0.68 <= hue <= 0.86), f"{name} ({hex_value}) is purple"


def test_stylesheet_carries_the_palette_and_the_fleet_selectors():
    sheet = theme.stylesheet()
    for value in (theme.BG, theme.PANEL, theme.TEXT, theme.BRONZE, theme.DANGER):
        assert value in sheet
    for selector in ("#wordmark", "#tagline", "#statusLine", "#primary", "#attention"):
        assert selector in sheet
