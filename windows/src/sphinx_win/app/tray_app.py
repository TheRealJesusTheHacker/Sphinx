"""The Windows UI: the window, and the tray host that keeps
Sphinx running (Phase 2).

Phase 1 was one plain window in the fleet's style — status, on/off,
blocked/allowed counters, list status and manual updates, the
allowlist and custom-entry editors, the list-source editor, and the
on-device query log. Phase 2 keeps that window and adds the host:
a system-tray icon whose process owns the filter, so closing the
window no longer stops protection — the window closes to the tray,
and only the tray's Quit (or the window's own stop, while it is the
only surface) runs the audited stop. Phase 3 restyles the window
and tray in the Sphinx palette (app/theme.py — basalt, sandstone,
bronze-gold; presentation only, no behavior moved) and adds the
Profiles section: named snapshots of the allowlist + custom
entries, with the store's write-through and switch discipline
behind them.

Honesty rules wired in, not just written down:
- The status line reflects the real filter/DNS state, never the
  desired one — in the window and in the tray alike.
- Without administrator rights the Start button is disabled and the
  window says why, in plain language; a "Restart as administrator"
  action is offered instead of a dead end.
- A leftover backup gets its own banner with Restore / Dismiss —
  it is never silently treated as "on".
- Quitting (tray Quit, or closing the window when no tray exists)
  stops the filter cleanly (DNS restored first); if the restore
  fails, the quit is refused and the error shown, so the machine
  is never left pointing at a dead resolver.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction, QColor, QFont, QIcon, QPainter, QPen, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)

from ..core.profiles import is_valid_profile_name
from ..core.updater import ListUpdater
from ..core.validation import ListSource, is_acceptable_url
from ..dnsmgmt.guard import DnsState
from . import theme
from .autostart import AutostartManager
from .controller import SphinxController, StartError
from .host import (
    LaunchOptions,
    StartupAction,
    plan_startup,
    relaunch_args,
    relaunch_elevated,
)


def sphinx_icon(state: str = "off") -> QIcon:
    """The tray/window icon, drawn rather than shipped as a file:
    an S in a stone tablet — one less asset to keep in step. The
    ring and letter take the state's color from the palette
    (app/theme.py): dulled bronze while off, bronze-gold while on,
    the fleet's danger red when the machine needs the user
    ("attention"). The window icon keeps the resting state; the
    tray icon follows the real state."""
    ring = {
        "on": theme.BRONZE,
        "attention": theme.DANGER,
    }.get(state, theme.BRONZE_MUTED)
    pixmap = QPixmap(64, 64)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setBrush(QColor(theme.ICON_FACE))
    painter.setPen(QPen(QColor(ring), 3))
    painter.drawRoundedRect(4, 4, 56, 56, 10, 10)
    painter.setPen(QColor(theme.BRONZE_SOFT if state == "on" else ring))
    font = QFont()
    font.setBold(True)
    font.setPixelSize(36)
    painter.setFont(font)
    painter.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, "S")
    painter.end()
    return QIcon(pixmap)


class MainWindow(QMainWindow):
    def __init__(self, controller: SphinxController, elevated: bool):
        super().__init__()
        self.controller = controller
        self._elevated = elevated
        self._host: Optional["TrayHost"] = None
        self.setWindowTitle("Sphinx — Sentinel Safeguard")
        self.setWindowIcon(sphinx_icon())
        self.resize(600, 820)

        # One scrolling column in the fleet's HUD shape; the
        # stylesheet (app/theme.py) is applied by the entry point.
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(12)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(content)
        self.setCentralWidget(scroll)

        title = QLabel("SPHINX")
        title.setObjectName("wordmark")
        layout.addWidget(title)
        tagline = QLabel("Every request gets questioned.")
        tagline.setObjectName("tagline")
        layout.addWidget(tagline)

        self.status_label = QLabel("")
        self.status_label.setObjectName("statusLine")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        self.leftover_box = QGroupBox("Saved DNS settings found")
        self.leftover_box.setObjectName("attention")
        leftover_layout = QVBoxLayout(self.leftover_box)
        leftover_text = QLabel(
            "Sphinx holds this machine's previous DNS settings, but "
            "DNS is not currently pointing at Sphinx (an earlier run "
            "may have ended unexpectedly, or the settings were changed "
            "by hand). You can put the saved settings back, or dismiss "
            "them if you have checked the current settings yourself."
        )
        leftover_text.setWordWrap(True)
        leftover_layout.addWidget(leftover_text)
        leftover_buttons = QHBoxLayout()
        self.restore_button = QPushButton("Restore saved DNS settings")
        self.restore_button.clicked.connect(self._on_restore_leftover)
        self.dismiss_button = QPushButton("Dismiss")
        self.dismiss_button.clicked.connect(self._on_dismiss_leftover)
        leftover_buttons.addWidget(self.restore_button)
        leftover_buttons.addWidget(self.dismiss_button)
        leftover_layout.addLayout(leftover_buttons)
        layout.addWidget(self.leftover_box)

        controls = QHBoxLayout()
        self.toggle_button = QPushButton("Turn Sphinx on")
        self.toggle_button.setObjectName("primary")
        self.toggle_button.clicked.connect(self._on_toggle)
        controls.addWidget(self.toggle_button)
        self.counter_label = QLabel("Blocked: 0   Allowed: 0")
        controls.addWidget(self.counter_label)
        layout.addLayout(controls)

        if not elevated:
            note = QLabel(
                "Windows requires administrator rights to change DNS "
                "settings. Run Sphinx as administrator to turn the "
                "filter on — until then, nothing can be changed."
            )
            note.setWordWrap(True)
            layout.addWidget(note)
            self.toggle_button.setEnabled(False)

        start_box = QGroupBox("Starting Sphinx")
        start_layout = QVBoxLayout(start_box)
        self.autostart_checkbox = QCheckBox("Start Sphinx when I sign in")
        self.autostart_checkbox.toggled.connect(self._on_autostart_toggled)
        start_layout.addWidget(self.autostart_checkbox)
        start_note = QLabel(
            "With this on, Sphinx starts in the tray when you sign "
            "in. Protection itself resumes only if it was on when "
            "you last left it — and turning it back on needs "
            "administrator rights, so Windows may ask once after "
            "sign-in. Closing this window does not quit Sphinx: it "
            "keeps running in the tray, and the tray's Quit is what "
            "stops it (restoring your DNS settings first)."
        )
        start_note.setWordWrap(True)
        start_layout.addWidget(start_note)
        self.elevate_button = QPushButton("Restart Sphinx as administrator")
        self.elevate_button.clicked.connect(self._on_elevate_clicked)
        self.elevate_button.setVisible(not elevated)
        start_layout.addWidget(self.elevate_button)
        layout.addWidget(start_box)

        lists_box = QGroupBox("Blocklists")
        lists_layout = QVBoxLayout(lists_box)
        self.list_status_label = QLabel("")
        self.list_status_label.setWordWrap(True)
        lists_layout.addWidget(self.list_status_label)
        self.update_button = QPushButton("Update lists now")
        self.update_button.clicked.connect(self._on_update)
        lists_layout.addWidget(self.update_button)
        self.update_result_label = QLabel("")
        self.update_result_label.setWordWrap(True)
        lists_layout.addWidget(self.update_result_label)
        lists_layout.addWidget(QLabel("List sources (one HTTPS address per line):"))
        self.sources_edit = QPlainTextEdit()
        self.sources_edit.setMaximumHeight(64)
        self.sources_edit.setPlainText(
            "\n".join(s.url for s in controller.store.sources())
        )
        lists_layout.addWidget(self.sources_edit)
        save_sources = QPushButton("Save sources")
        save_sources.clicked.connect(self._on_save_sources)
        lists_layout.addWidget(save_sources)
        layout.addWidget(lists_box)

        self.allow_editor = self._entry_editor(
            layout,
            "Allowlist — never blocked (the allowlist always wins)",
            controller.store.allowlist_entries(),
            self._save_allowlist,
        )
        self.custom_editor = self._entry_editor(
            layout,
            "Your own block entries",
            controller.store.custom_block_entries(),
            self._save_custom,
        )

        profiles_box = QGroupBox("Profiles")
        profiles_layout = QVBoxLayout(profiles_box)
        self.profile_status_label = QLabel("")
        self.profile_status_label.setWordWrap(True)
        profiles_layout.addWidget(self.profile_status_label)
        profile_pick = QHBoxLayout()
        self.profile_combo = QComboBox()
        profile_pick.addWidget(self.profile_combo)
        self.profile_switch_button = QPushButton("Use profile")
        self.profile_switch_button.clicked.connect(self._on_switch_profile)
        profile_pick.addWidget(self.profile_switch_button)
        profiles_layout.addLayout(profile_pick)
        profile_actions = QHBoxLayout()
        self.profile_create_button = QPushButton("Save rules as new profile…")
        self.profile_create_button.clicked.connect(self._on_create_profile)
        profile_actions.addWidget(self.profile_create_button)
        self.profile_delete_button = QPushButton("Delete profile")
        self.profile_delete_button.clicked.connect(self._on_delete_profile)
        profile_actions.addWidget(self.profile_delete_button)
        profiles_layout.addLayout(profile_actions)
        profile_note = QLabel(
            "A profile saves your allowlist and your own block "
            "entries under a name. The blocklists themselves are "
            "the same under every profile — switching never changes "
            "which lists are in force. While a profile is active, "
            "edits to the two editors above are saved into it too."
        )
        profile_note.setWordWrap(True)
        profiles_layout.addWidget(profile_note)
        layout.addWidget(profiles_box)
        self._refresh_profiles_ui()

        log_box = QGroupBox("Recent lookups (on this device only, in memory)")
        log_layout = QVBoxLayout(log_box)
        self.log_list = QListWidget()
        log_layout.addWidget(self.log_list)
        log_controls = QHBoxLayout()
        self.log_checkbox = QCheckBox("Record the query log")
        self.log_checkbox.setChecked(controller.store.query_log_enabled())
        self.log_checkbox.toggled.connect(self._on_log_toggled)
        log_controls.addWidget(self.log_checkbox)
        clear_log = QPushButton("Clear log")
        clear_log.clicked.connect(self._on_clear_log)
        log_controls.addWidget(clear_log)
        log_layout.addLayout(log_controls)
        layout.addWidget(log_box)

        self._state_cache = None
        self._state_at = 0.0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(1000)
        self._refresh(force_state=True)
        self._refresh_list_status()

    # --- Entry editors (allowlist / custom entries) -------------------

    def _entry_editor(self, parent_layout, title, entries, on_save):
        box = QGroupBox(title)
        box_layout = QVBoxLayout(box)
        list_widget = QListWidget()
        list_widget.addItems(entries)
        list_widget.setMaximumHeight(96)
        box_layout.addWidget(list_widget)
        row = QHBoxLayout()
        edit = QLineEdit()
        edit.setPlaceholderText("example.com")
        row.addWidget(edit)
        add = QPushButton("Add")
        remove = QPushButton("Remove selected")

        def do_add():
            text = edit.text().strip()
            if not text:
                return
            from ..core.blocklist import normalize_entry

            normalized = normalize_entry(text)
            if normalized is None:
                QMessageBox.warning(
                    self,
                    "Not a usable domain",
                    "That entry can't be used — entries must be domain "
                    "names like ads.example.com (not a single word, not "
                    "an address, not a local name). Nothing was added.",
                )
                return
            items = [list_widget.item(i).text() for i in range(list_widget.count())]
            if normalized not in items:
                list_widget.addItem(normalized)
            edit.clear()
            on_save([list_widget.item(i).text() for i in range(list_widget.count())])

        def do_remove():
            for item in list_widget.selectedItems():
                list_widget.takeItem(list_widget.row(item))
            on_save([list_widget.item(i).text() for i in range(list_widget.count())])

        add.clicked.connect(do_add)
        remove.clicked.connect(do_remove)
        row.addWidget(add)
        row.addWidget(remove)
        box_layout.addLayout(row)
        parent_layout.addWidget(box)
        return list_widget

    def _save_allowlist(self, entries):
        self.controller.store.save_allowlist(entries)
        self.controller.reload_lists()

    def _save_custom(self, entries):
        self.controller.store.save_custom_block_entries(entries)
        self.controller.reload_lists()

    # --- Profiles (Phase 3) ---------------------------------------------
    #
    # The dialog-free helpers (create_profile_named and friends)
    # are the behavior; the _on_* handlers only ask the user and
    # report. A switch writes the snapshot into the live stores
    # (the store's audited sequence) and then applies ALL of it to
    # the running filter through the controller's ordinary reload —
    # never a files-only switch the filter hasn't heard about.

    def _refresh_entry_editors(self):
        """Re-read both entry editors from the live stores (after
        a profile switch changed what "live" is)."""
        for widget, entries in (
            (self.allow_editor, self.controller.store.allowlist_entries()),
            (self.custom_editor, self.controller.store.custom_block_entries()),
        ):
            widget.clear()
            widget.addItems(entries)

    def _refresh_profiles_ui(self, select: Optional[str] = None):
        profile_set = self.controller.store.load_profile_set()
        names = [p.name for p in profile_set.profiles]
        current = select or self.profile_combo.currentText()
        self.profile_combo.blockSignals(True)
        self.profile_combo.clear()
        self.profile_combo.addItems(names)
        if current in names:
            self.profile_combo.setCurrentText(current)
        elif profile_set.active_name in names:
            self.profile_combo.setCurrentText(profile_set.active_name)
        self.profile_combo.blockSignals(False)
        if profile_set.active_name:
            self.profile_status_label.setText(
                f"Active profile: {profile_set.active_name} — edits to "
                "the allowlist and your own block entries are saved "
                "into it."
            )
        elif names:
            self.profile_status_label.setText(
                "No profile is active — the rules above aren't saved "
                "under a name."
            )
        else:
            self.profile_status_label.setText("No profiles yet.")
        has_profiles = bool(names)
        self.profile_combo.setEnabled(has_profiles)
        self.profile_switch_button.setEnabled(has_profiles)
        self.profile_delete_button.setEnabled(has_profiles)

    def create_profile_named(self, name: str) -> bool:
        """Save the live rules as a new profile and make it active.
        False when the name is unusable or already taken."""
        if self.controller.store.create_profile(name) is None:
            return False
        self._refresh_profiles_ui(select=name.strip())
        return True

    def switch_profile_named(self, name: str) -> bool:
        """Switch the live rules to the named profile and apply
        them whole to the running filter. False when no such
        profile exists (nothing changes then)."""
        if not self.controller.store.switch_profile(name):
            return False
        self.controller.reload_lists()
        self._refresh_entry_editors()
        self._refresh_profiles_ui(select=name.strip())
        self._refresh(force_state=True)
        return True

    def delete_profile_named(self, name: str) -> bool:
        """Delete the named profile's snapshot. The live rules are
        untouched; if it was the active profile, they simply stop
        being under a profile."""
        if not self.controller.store.delete_profile(name):
            return False
        self._refresh_profiles_ui()
        return True

    def _on_create_profile(self):
        name, ok = QInputDialog.getText(
            self,
            "New profile",
            "Save the current allowlist and block entries as a "
            "profile named:",
        )
        if not ok:
            return
        if not is_valid_profile_name(name):
            QMessageBox.warning(
                self,
                "That name can't be used",
                "Profile names are 1–40 characters of ordinary text. "
                "Nothing was saved.",
            )
            return
        if not self.create_profile_named(name):
            QMessageBox.warning(
                self,
                "Profile not saved",
                "A profile with that name already exists. Nothing "
                "was changed.",
            )
            return
        self.profile_status_label.setText(
            f"Profile “{name.strip()}” saved and active."
        )

    def _on_switch_profile(self):
        name = self.profile_combo.currentText()
        if not name:
            return
        if self.switch_profile_named(name):
            self.profile_status_label.setText(
                f"Sphinx now uses profile “{name}” — its rules are "
                "in force."
            )
        else:
            QMessageBox.warning(
                self,
                "Profile not switched",
                "That profile no longer exists. Nothing was changed.",
            )
            self._refresh_profiles_ui()

    def _on_delete_profile(self):
        name = self.profile_combo.currentText()
        if not name:
            return
        answer = QMessageBox.question(
            self,
            "Delete profile",
            f"Delete the profile “{name}”? The rules currently in "
            "force stay exactly as they are — only the saved copy "
            "goes.",
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.delete_profile_named(name)

    # --- Filter toggle --------------------------------------------------

    def _on_toggle(self):
        try:
            if self.controller.running:
                message = self.controller.stop()
            else:
                message = self.controller.start()
            self.status_label.setText(message)
        except Exception as e:  # plain-language failure, nothing hidden
            QMessageBox.warning(self, "Sphinx", str(e))
        self._refresh(force_state=True)

    # --- Leftover handling ------------------------------------------------

    def _on_restore_leftover(self):
        try:
            message = self.controller.restore_dns()
            self.status_label.setText(message)
        except Exception as e:
            QMessageBox.warning(self, "Sphinx", str(e))
        self._refresh(force_state=True)

    def _on_dismiss_leftover(self):
        self.controller.dismiss_leftover()
        self._refresh(force_state=True)

    # --- Tray host wiring (Phase 2) --------------------------------------

    def attach_host(self, host: "TrayHost") -> None:
        """Connect the tray host after construction: the checkbox
        takes the autostart state the host actually read from the
        machine (the registry's truth, not a stored hope)."""
        self._host = host
        self.autostart_checkbox.blockSignals(True)
        self.autostart_checkbox.setChecked(host.autostart_state())
        self.autostart_checkbox.blockSignals(False)

    def set_status(self, text: str) -> None:
        self.status_label.setText(text)

    def _on_autostart_toggled(self, checked: bool):
        if self._host is None:
            # No host (tests, unusual shells): record the choice;
            # there is no registry to manage from here.
            self.controller.store.set_autostart_enabled(checked)
            return
        actual = self._host.set_autostart(checked)
        if actual != checked:
            self.autostart_checkbox.blockSignals(True)
            self.autostart_checkbox.setChecked(actual)
            self.autostart_checkbox.blockSignals(False)
            QMessageBox.warning(
                self,
                "Start at sign-in",
                "Sphinx couldn't change the sign-in setting, so it "
                "was left as it was. Nothing else changed.",
            )

    def _on_elevate_clicked(self):
        if self._host is not None:
            self._host.request_elevation()

    # --- List updates -------------------------------------------------------

    def _on_update(self):
        self.update_button.setEnabled(False)
        self.update_result_label.setText("Downloading and checking the lists…")

        def work():
            try:
                result = ListUpdater(self.controller.store).update_all(
                    int(time.time() * 1000)
                )
                if result.success:
                    self.controller.reload_lists()
                    text = (
                        f"Lists updated: {result.total_domains:,} domains "
                        "now questioned."
                    )
                else:
                    text = (
                        "The update didn't pass Sphinx's checks, so "
                        "nothing changed — your current lists are "
                        "still in force."
                    )
            except Exception as e:
                text = f"Update failed ({e}); nothing changed."
            self._pending_update_text = text

        def done():
            self.update_result_label.setText(self._pending_update_text)
            self.update_button.setEnabled(True)
            self._refresh_list_status()

        thread = threading.Thread(target=work, daemon=True)
        thread.start()
        QTimer.singleShot(300, lambda: self._await_update(thread, done))

    def _await_update(self, thread, done):
        if thread.is_alive():
            QTimer.singleShot(300, lambda: self._await_update(thread, done))
        else:
            done()

    def _on_save_sources(self):
        urls = [
            line.strip()
            for line in self.sources_edit.toPlainText().splitlines()
            if line.strip()
        ]
        valid = [u for u in urls if is_acceptable_url(u)]
        if not valid:
            QMessageBox.warning(
                self,
                "No usable sources",
                "Sources must be HTTPS addresses. Nothing was saved.",
            )
            return
        sources = []
        known = {s.url: s for s in self.controller.store.sources()}
        for url in valid:
            existing = known.get(url)
            if existing is not None:
                sources.append(existing)
            else:
                host = urlparse(url).hostname or url
                sources.append(ListSource(host, url))
        self.controller.store.save_sources(sources)
        self.sources_edit.setPlainText("\n".join(s.url for s in sources))
        if len(valid) < len(urls):
            self.update_result_label.setText(
                "Some lines weren't HTTPS addresses and were left out."
            )
        self._refresh_list_status()

    # --- Query log ------------------------------------------------------------

    def _on_log_toggled(self, checked):
        self.controller.set_log_enabled(checked)
        self._refresh()

    def _on_clear_log(self):
        self.controller.engine.query_log.clear()
        self._refresh()

    # --- Refresh ----------------------------------------------------------------

    #: How often the window re-reads the machine's DNS state. Every
    #: read is a set of PowerShell invocations on real Windows —
    #: doing them on the 1-second counter tick would burn a core
    #: forever for a window that mostly sits open. Actions that
    #: change the state force an immediate re-read instead.
    STATE_REFRESH_S = 15.0

    def _refresh(self, force_state=False):
        engine = self.controller.engine
        self.counter_label.setText(
            f"Blocked: {engine.blocked_count:,}   Allowed: {engine.allowed_count:,}"
        )
        now = time.monotonic()
        if (
            force_state
            or self._state_cache is None
            or now - self._state_at >= self.STATE_REFRESH_S
        ):
            try:
                self._state_cache = self.controller.dns_state()
                self._state_at = now
            except Exception as e:
                # Reading the machine's DNS state must never take the
                # window down with it: show that the state is
                # unreadable and leave everything else exactly as is.
                # (The failure is throttled too — no retry storm.)
                self._state_at = now
                self.status_label.setText(
                    f"Sphinx couldn't read this machine's DNS settings ({e}). "
                    "Nothing was changed."
                )
                self.leftover_box.setVisible(False)
                return
        state = self._state_cache
        if self.controller.running:
            if state is DnsState.ENGAGED:
                self.status_label.setText(
                    "Sphinx is ON — DNS points at the filter on this machine."
                )
            else:
                # The status reflects the real state, never the
                # desired one: the filter runs, but DNS no longer
                # points at it (something changed it underneath us).
                self.status_label.setText(
                    "Sphinx is on, but DNS no longer points at the "
                    "filter — turn Sphinx off and on again to restore "
                    "protection."
                )
            self.toggle_button.setText("Turn Sphinx off")
        else:
            self.toggle_button.setText("Turn Sphinx on")
            if state is DnsState.ENGAGED:
                # DNS points at Sphinx but this process isn't serving
                # it — an earlier run (or this machine before a
                # restart) left the engagement in place. Turning
                # Sphinx on resumes against the saved settings.
                self.status_label.setText(
                    "Sphinx is off, but DNS still points at Sphinx on "
                    "this machine. Turn Sphinx on to resume filtering."
                )
            elif state is DnsState.LEFTOVER:
                self.status_label.setText(
                    "Sphinx is off. Saved DNS settings from an earlier "
                    "run are waiting below."
                )
            elif state is DnsState.UNKNOWN:
                self.status_label.setText(
                    "Sphinx is off. DNS currently points at a loopback "
                    "resolver that Sphinx has no record of."
                )
            else:
                self.status_label.setText("Sphinx is off.")
        self.leftover_box.setVisible(
            state is DnsState.LEFTOVER and not self.controller.running
        )
        if self._host is not None:
            # The tray icon's third state: the machine needs the
            # user — a leftover or an unrecorded loopback to decide
            # on, or a filter running while DNS no longer points at
            # it. Presentation only; the status text is unchanged.
            attention = state in (DnsState.LEFTOVER, DnsState.UNKNOWN) or (
                self.controller.running and state is not DnsState.ENGAGED
            )
            self._host.update(
                self.status_label.text(), self.controller.running, attention
            )

        if self.controller.store.query_log_enabled():
            entries = engine.query_log.snapshot()
            wanted = [
                ("BLOCKED  " if e.blocked else "allowed  ")
                + datetime.fromtimestamp(e.timestamp_ms / 1000).strftime("%H:%M:%S")
                + "  "
                + e.name
                for e in entries[:100]
            ]
            current = [self.log_list.item(i).text() for i in range(self.log_list.count())]
            if wanted != current:
                self.log_list.clear()
                self.log_list.addItems(wanted)
        elif self.log_list.count() != 1 or self.log_list.item(0).text() != "Recording is off.":
            self.log_list.clear()
            self.log_list.addItem("Recording is off.")

    def _refresh_list_status(self):
        def work():
            try:
                self._pending_status = self.controller.store.status()
            except Exception:
                self._pending_status = None

        thread = threading.Thread(target=work, daemon=True)
        thread.start()
        QTimer.singleShot(200, lambda: self._await_status(thread))

    def _await_status(self, thread):
        if thread.is_alive():
            QTimer.singleShot(200, lambda: self._await_status(thread))
            return
        status = getattr(self, "_pending_status", None)
        if status is None:
            return
        if status.using_downloaded:
            when = (
                datetime.fromtimestamp(status.last_updated_ms / 1000).strftime(
                    "%Y-%m-%d %H:%M"
                )
                if status.last_updated_ms
                else "unknown"
            )
            self.list_status_label.setText(
                f"Downloaded lists in force: {status.active_domains:,} "
                f"domains. Last updated: {when}."
            )
        else:
            self.list_status_label.setText(
                f"Bundled list in force: {status.active_domains:,} "
                "domains (no downloaded lists yet)."
            )

    # --- Close discipline ---------------------------------------------------------

    def closeEvent(self, event):
        if self._host is not None and self._host.tray_available():
            # The tray host owns the filter now: closing the window
            # is not quitting Sphinx. The window goes to the tray;
            # protection (and the tray's honest status) carries on.
            self.hide()
            event.ignore()
            return
        # No tray to go to (a desktop without one, or a bare test):
        # the window is the app again, with Phase 1's discipline —
        # stop cleanly, and refuse rather than strand the machine.
        if self.controller.running:
            try:
                self.controller.stop()
            except Exception as e:
                QMessageBox.warning(
                    self,
                    "Sphinx is still protecting this machine",
                    "Sphinx couldn't restore your DNS settings, so it "
                    f"stays on rather than leaving the machine pointed "
                    f"at a stopped filter.\n\n{e}",
                )
                event.ignore()
                return
        event.accept()


@dataclass
class StartupOutcome:
    """What the shell should do after the host's startup decision."""

    exit_now: bool = False  # an elevated relaunch took over; just exit
    attention: bool = False  # the user has something to decide: show the window
    summary: str = ""  # one plain line for the tray, when it stays hidden


class TrayHost:
    """The tray-resident host: owns the tray icon and menu, the
    startup decision's execution, and quitting.

    One process owns the window, the tray, and the controller (and
    through it the server and the DNS guard), so the backup/restore
    state the Phase 1 audit proved has exactly one owner — the
    audit's gates never have to cross a process boundary.
    """

    def __init__(
        self,
        window: MainWindow,
        controller: SphinxController,
        *,
        elevated: bool,
        launch: LaunchOptions,
        autostart_manager: Optional[AutostartManager] = None,
        quit_fn=None,
        elevate_fn=None,
        release_instance=None,
    ):
        self.window = window
        self.controller = controller
        self.elevated = elevated
        self.launch = launch
        self.autostart_manager = autostart_manager
        self._quit_fn = quit_fn or (lambda: QApplication.quit())
        self._elevate_fn = elevate_fn or relaunch_elevated
        self._release_instance = release_instance
        self.needs_admin = False

        self.tray_icon: Optional[QSystemTrayIcon] = None
        self._status_action: Optional[QAction] = None
        self._toggle_action: Optional[QAction] = None
        self._elevate_action: Optional[QAction] = None
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray_icon = QSystemTrayIcon(sphinx_icon(), window)
            self.tray_icon.setToolTip("Sphinx — off")
            menu = QMenu()
            self._status_action = QAction("Sphinx is off.", menu)
            self._status_action.setEnabled(False)
            menu.addAction(self._status_action)
            menu.addSeparator()
            open_action = QAction("Open Sphinx", menu)
            open_action.triggered.connect(self._show_window)
            menu.addAction(open_action)
            self._toggle_action = QAction("Turn Sphinx on", menu)
            self._toggle_action.triggered.connect(self.window._on_toggle)
            menu.addAction(self._toggle_action)
            self._elevate_action = QAction("Restart as administrator", menu)
            self._elevate_action.triggered.connect(
                lambda: self.request_elevation()
            )
            self._elevate_action.setVisible(not elevated)
            menu.addAction(self._elevate_action)
            menu.addSeparator()
            quit_action = QAction("Quit Sphinx", menu)
            quit_action.triggered.connect(lambda: self.quit())
            menu.addAction(quit_action)
            menu.aboutToShow.connect(
                lambda: self.window._refresh(force_state=True)
            )
            self.tray_icon.setContextMenu(menu)
            self.tray_icon.activated.connect(self._on_tray_activated)
            self.tray_icon.show()
        window.attach_host(self)

    # --- Tray basics -----------------------------------------------------

    def tray_available(self) -> bool:
        return self.tray_icon is not None

    def _show_window(self):
        self.window.showNormal()
        self.window.raise_()
        self.window.activateWindow()

    def _on_tray_activated(self, reason):
        if reason in (
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.DoubleClick,
        ):
            self._show_window()

    def update(
        self, status_text: str, running: bool, attention: bool = False
    ) -> None:
        """The window's refresh pushes its (real, read) status here,
        so the tray never claims a state the window hasn't read —
        the icon's state color comes from the same read."""
        if self._status_action is not None:
            self._status_action.setText(status_text)
        if self._toggle_action is not None:
            self._toggle_action.setText(
                "Turn Sphinx off" if running else "Turn Sphinx on"
            )
        if self.tray_icon is not None:
            self.tray_icon.setToolTip(
                "Sphinx — on" if running else "Sphinx — off"
            )
            self.tray_icon.setIcon(
                sphinx_icon(
                    "attention" if attention else ("on" if running else "off")
                )
            )

    def notify(self, text: str) -> None:
        if self.tray_icon is not None:
            self.tray_icon.showMessage(
                "Sphinx", text, sphinx_icon(), 5000
            )

    # --- Start-at-sign-in ---------------------------------------------------

    def autostart_state(self) -> bool:
        """The state in force: the registry's actual value when the
        registry can be managed here; otherwise the recorded choice."""
        if self.autostart_manager is not None:
            try:
                return self.autostart_manager.is_enabled()
            except Exception:
                pass
        return self.controller.store.autostart_enabled()

    def set_autostart(self, enabled: bool) -> bool:
        """Apply the user's choice and return the state actually in
        force afterwards (re-read where a registry is involved)."""
        actual = enabled
        if self.autostart_manager is not None:
            try:
                actual = self.autostart_manager.sync(enabled)
            except Exception:
                actual = self.autostart_state()
        self.controller.store.set_autostart_enabled(actual)
        return actual

    # --- Elevation ------------------------------------------------------------

    def request_elevation(self) -> bool:
        """Relaunch this program as administrator and exit this
        instance, so exactly one host owns the machine. False when
        the user declined or the OS refused — this instance then
        stays, saying plainly that rights are needed."""
        if not self._elevate_fn(relaunch_args(self.launch)):
            return False
        if self._release_instance is not None:
            self._release_instance()
        self._quit_fn()
        return True

    # --- Quitting ---------------------------------------------------------------

    def quit(self) -> bool:
        """The audited stop, then exit: restore DNS, verify, and
        only then go. A failed restore refuses the quit — Sphinx
        stays in the tray rather than leave the machine pointed at
        a stopped filter.

        The not-running ENGAGED case (a reboot into NEEDS_ADMIN:
        DNS still points at Sphinx, but this host serves nothing
        and, without administrator rights, cannot restore either)
        must not exit silently through this one unguarded path:
        quitting abandons the engagement, so the user is warned
        and must confirm it explicitly (Sweep #3, W-2)."""
        if self.controller.running:
            try:
                self.controller.stop()
            except Exception as e:
                self._show_window()
                QMessageBox.warning(
                    self.window,
                    "Sphinx is still protecting this machine",
                    "Sphinx couldn't restore your DNS settings, so it "
                    f"stays on rather than leaving the machine pointed "
                    f"at a stopped filter.\n\n{e}",
                )
                return False
        else:
            try:
                state = self.controller.dns_state()
            except Exception:
                state = None  # unreadable state never traps the user
            if state is DnsState.ENGAGED:
                answer = QMessageBox.question(
                    self.window,
                    "DNS still points at Sphinx",
                    "Sphinx is not running, but this machine's DNS "
                    "still points at Sphinx — and nothing is serving "
                    "it. Quitting leaves it pointing there; DNS "
                    "lookups will fail until Sphinx runs again.\n\n"
                    "Restart Sphinx as administrator to resume "
                    "filtering or restore your previous DNS settings, "
                    "or quit anyway and leave DNS as it is.",
                    QMessageBox.StandardButton.Yes
                    | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                if answer != QMessageBox.StandardButton.Yes:
                    return False
        self._quit_fn()
        return True

    # --- Startup ------------------------------------------------------------------

    def run_startup(self) -> StartupOutcome:
        """Execute the startup decision (app/host.py's table). The
        decision itself is pure and tested; this is only its hands."""
        store = self.controller.store
        try:
            state = self.controller.dns_state()
        except Exception as e:
            return StartupOutcome(
                attention=True,
                summary=(
                    f"Sphinx couldn't read this machine's DNS settings "
                    f"({e}). Nothing was changed."
                ),
            )
        plan = plan_startup(
            state,
            intent_on=store.protection_intent(),
            autostart_launch=self.launch.autostart,
            elevated_attempted=self.launch.elevated_attempted,
            elevated=self.elevated,
        )
        if plan.action in (StartupAction.ENGAGE, StartupAction.RESUME):
            try:
                message = self.controller.start()
            except Exception as e:
                return StartupOutcome(attention=True, summary=str(e))
            self.window._refresh(force_state=True)
            return StartupOutcome(summary=message)
        if plan.action is StartupAction.NEEDS_ADMIN:
            self.needs_admin = True
            if plan.may_auto_elevate and self._elevate_fn(
                relaunch_args(self.launch)
            ):
                return StartupOutcome(
                    exit_now=True,
                    summary="Restarting as administrator to resume "
                    "protection.",
                )
            return StartupOutcome(
                attention=not self.launch.autostart,
                summary=plan.reason,
            )
        if plan.action in (
            StartupAction.SURFACE_LEFTOVER,
            StartupAction.SURFACE_UNKNOWN,
        ):
            return StartupOutcome(attention=True, summary=plan.reason)
        return StartupOutcome(summary="")
