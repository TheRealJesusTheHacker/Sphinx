"""The Phase 1 Windows UI: one plain window in the fleet's style.

Status, on/off, blocked/allowed counters, list status and manual
updates, the allowlist and custom-entry editors, the list-source
editor, and the on-device query log. Functional, not pretty — HUD
polish is a later phase, like every other tool in the fleet had.

Honesty rules wired in, not just written down:
- The status line reflects the real filter/DNS state, never the
  desired one.
- Without administrator rights the Start button is disabled and the
  window says why, in plain language.
- A leftover backup gets its own banner with Restore / Dismiss —
  it is never silently treated as "on".
- Closing the window stops the filter cleanly (DNS restored first);
  if the restore fails, the close is refused and the error shown,
  so the machine is never left pointing at a dead resolver.
"""
from __future__ import annotations

import threading
import time
from datetime import datetime
from urllib.parse import urlparse

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (
    QCheckBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ..core.updater import ListUpdater
from ..core.validation import ListSource, is_acceptable_url
from ..dnsmgmt.guard import DnsState
from .controller import SphinxController, StartError


class MainWindow(QMainWindow):
    def __init__(self, controller: SphinxController, elevated: bool):
        super().__init__()
        self.controller = controller
        self.setWindowTitle("Sphinx — Sentinel Safeguard")
        self.resize(560, 760)

        root = QWidget()
        layout = QVBoxLayout(root)
        self.setCentralWidget(root)

        title = QLabel("Sphinx")
        title.setStyleSheet("font-size: 22px; font-weight: bold;")
        layout.addWidget(title)
        tagline = QLabel("Every request gets questioned.")
        layout.addWidget(tagline)

        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        self.status_label.setStyleSheet("font-size: 14px;")
        layout.addWidget(self.status_label)

        self.leftover_box = QGroupBox("Saved DNS settings found")
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

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(1000)
        self._refresh()
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
        self._refresh()

    # --- Leftover handling ------------------------------------------------

    def _on_restore_leftover(self):
        try:
            message = self.controller.restore_dns()
            self.status_label.setText(message)
        except Exception as e:
            QMessageBox.warning(self, "Sphinx", str(e))
        self._refresh()

    def _on_dismiss_leftover(self):
        self.controller.guard.dismiss_leftover()
        self._refresh()

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

    def _refresh(self):
        engine = self.controller.engine
        self.counter_label.setText(
            f"Blocked: {engine.blocked_count:,}   Allowed: {engine.allowed_count:,}"
        )
        try:
            state = self.controller.dns_state()
        except Exception as e:
            # Reading the machine's DNS state must never take the
            # window down with it: show that the state is unreadable
            # and leave everything else exactly as it is.
            self.status_label.setText(
                f"Sphinx couldn't read this machine's DNS settings ({e}). "
                "Nothing was changed."
            )
            self.leftover_box.setVisible(False)
            return
        if self.controller.running:
            self.status_label.setText(
                "Sphinx is ON — DNS points at the filter on this machine."
            )
            self.toggle_button.setText("Turn Sphinx off")
        else:
            self.toggle_button.setText("Turn Sphinx on")
            if state is DnsState.LEFTOVER:
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
