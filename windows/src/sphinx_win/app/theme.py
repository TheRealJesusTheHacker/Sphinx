"""SPHINX — the Windows edition's palette and stylesheet (Phase 3).

Basalt black, sandstone, and bronze-gold — the stone guardian in
the desert. Every Sphinx edition and surface inherits this
identity (it is recorded in windows/README.md for the Android
polish and any Toolkit card to pick up): warm stone darks, pale
sandstone text, one bronze-gold accent. Red exists in exactly the
fleet's standard danger value, used only where something
genuinely needs attention. No purple — that exception belongs to
Beerus alone.

This module is data and stylesheet only — no behavior, no
capability. The window and tray live in ``tray_app.py``; the
palette pairings below are pinned at WCAG 4.5:1 or better by the
test suite, like the sibling tools' themes.
"""

from __future__ import annotations

# ----------------------------------------------------------------------
# Palette (every text pairing verified ≥ 4.5:1 against its surfaces)
# ----------------------------------------------------------------------

BG = "#0f0d0a"            # basalt black — window background
PANEL = "#171310"         # weathered stone — card/panel background
PANEL_RAISED = "#211a12"  # raised card / input / hover surface
HAIRLINE = "#3a2f1e"      # carved edge — borders, separators
TEXT = "#ece0c6"          # sandstone — primary text (on BG: ~14.8:1)
TEXT_FAINT = "#b3a284"    # worn sandstone — secondary text (on BG: ~7.8:1)
BRONZE = "#cf9a3e"        # bronze-gold — the accent (on BG: ~7.7:1)
BRONZE_DEEP = "#6e521f"   # aged bronze — primary button fill (TEXT on it: ~5.6:1)
BRONZE_SOFT = "#eac987"   # polished bronze — bright detail text (on BG: ~12.2:1)
BRONZE_MUTED = "#7d6740"  # dulled bronze — graphics only (tray "off" state)
DANGER = "#e5534b"        # the fleet-standard danger red (on BG: ~5.2:1)

#: The icon's stone face, shared by the drawn tray/window icons.
ICON_FACE = "#16120d"

#: Text/surface pairings the suite holds at ≥ 4.5:1, named so the
#: test reads like the design review it is.
TEXT_PAIRINGS = {
    "body text on window": (TEXT, BG),
    "body text on panel": (TEXT, PANEL),
    "body text on raised surface": (TEXT, PANEL_RAISED),
    "faint text on window": (TEXT_FAINT, BG),
    "faint text on panel": (TEXT_FAINT, PANEL),
    "faint text on raised surface": (TEXT_FAINT, PANEL_RAISED),
    "primary button text on bronze": (TEXT, BRONZE_DEEP),
    "selection text on bronze": (TEXT, BRONZE_DEEP),
    "accent text on window": (BRONZE, BG),
    "accent text on panel": (BRONZE, PANEL),
    "bright detail text on window": (BRONZE_SOFT, BG),
    "danger text on window": (DANGER, BG),
    "danger text on panel": (DANGER, PANEL),
}


def stylesheet() -> str:
    """The application-wide QSS. One stylesheet, every surface —
    consistency is part of the premium feel. Presentation only:
    it restyles the Phase 1–2 window; it changes no behavior."""
    return f"""
QWidget {{
    background: {BG};
    color: {TEXT};
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: 14px;
}}
QLabel#wordmark {{
    font-size: 30px;
    font-weight: 700;
    letter-spacing: 5px;
    color: {TEXT};
}}
QLabel#tagline {{
    color: {BRONZE};
    font-size: 14px;
}}
QLabel#statusLine {{
    color: {TEXT};
    font-size: 15px;
}}
QGroupBox {{
    background: {PANEL};
    border: 1px solid {HAIRLINE};
    border-radius: 10px;
    margin-top: 14px;
    padding: 10px 10px 10px 10px;
    font-weight: 600;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 10px;
    padding: 0 4px;
    color: {BRONZE_SOFT};
    background: {BG};
}}
QGroupBox#attention {{
    border-color: {DANGER};
}}
QGroupBox#attention::title {{
    color: {DANGER};
}}
QPushButton {{
    background: {PANEL_RAISED};
    color: {TEXT};
    border: 1px solid {HAIRLINE};
    border-radius: 8px;
    padding: 8px 16px;
    font-size: 14px;
}}
QPushButton:hover {{
    border-color: {BRONZE};
}}
QPushButton:disabled {{
    color: {TEXT_FAINT};
    border-color: {HAIRLINE};
}}
QPushButton#primary {{
    background: {BRONZE_DEEP};
    border: 1px solid {BRONZE_DEEP};
    font-weight: 600;
}}
QPushButton#primary:hover {{
    border-color: {BRONZE};
}}
QPushButton#primary:disabled {{
    background: {PANEL};
    color: {TEXT_FAINT};
    border-color: {HAIRLINE};
}}
QLineEdit, QPlainTextEdit, QListWidget, QComboBox {{
    background: {PANEL_RAISED};
    color: {TEXT};
    border: 1px solid {HAIRLINE};
    border-radius: 6px;
    padding: 6px;
    selection-background-color: {BRONZE_DEEP};
    selection-color: {TEXT};
}}
QLineEdit:focus, QPlainTextEdit:focus, QListWidget:focus, QComboBox:focus {{
    border-color: {BRONZE};
}}
QListWidget::item {{
    padding: 3px 6px;
    border-radius: 4px;
}}
QListWidget::item:selected {{
    background: {BRONZE_DEEP};
    color: {TEXT};
}}
QComboBox::drop-down {{
    border: none;
    width: 22px;
}}
QComboBox QAbstractItemView {{
    background: {PANEL_RAISED};
    color: {TEXT};
    border: 1px solid {HAIRLINE};
    selection-background-color: {BRONZE_DEEP};
    selection-color: {TEXT};
}}
QCheckBox {{
    color: {TEXT};
    spacing: 8px;
}}
QCheckBox::indicator {{
    width: 16px;
    height: 16px;
    border: 1px solid {HAIRLINE};
    border-radius: 4px;
    background: {PANEL};
}}
QCheckBox::indicator:checked {{
    background: {BRONZE_DEEP};
    border-color: {BRONZE};
}}
QScrollArea {{
    border: none;
    background: {BG};
}}
QScrollBar:vertical {{
    background: {PANEL};
    width: 10px;
    border-radius: 5px;
}}
QScrollBar::handle:vertical {{
    background: {HAIRLINE};
    border-radius: 5px;
    min-height: 30px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}
QMenu {{
    background: {PANEL};
    color: {TEXT};
    border: 1px solid {HAIRLINE};
    padding: 4px;
}}
QMenu::item {{
    padding: 6px 24px 6px 12px;
    border-radius: 4px;
}}
QMenu::item:selected {{
    background: {BRONZE_DEEP};
    color: {TEXT};
}}
QMenu::item:disabled {{
    color: {TEXT_FAINT};
}}
QMenu::separator {{
    height: 1px;
    background: {HAIRLINE};
    margin: 4px 8px;
}}
QToolTip {{
    background: {PANEL_RAISED};
    color: {TEXT};
    border: 1px solid {HAIRLINE};
    padding: 4px 8px;
}}
"""
