"""Sphinx for Windows — entry point.

Run from source:  python -m sphinx_win.app.main
Frozen (PyInstaller one-file): Sphinx.exe

Launch shapes:
  Sphinx.exe                     the tray host + window (Phase 2's host:
                                 one process owns the filter, the tray,
                                 and the window — see tray_app.TrayHost)
  Sphinx.exe --autostart         the same host, launched by sign-in
                                 (the Run value writes exactly this)
  Sphinx.exe --restore-dns       headless: put back the DNS settings
                                 Sphinx holds, if any, and exit with a
                                 code — the installer's uninstall hook
                                 (0 = restored or nothing to restore,
                                 3 = restore failed or impossible)

A second launch of the host does not start a rival: it asks the
running host to show its window and exits (QLocalServer, one per
user).

Data lives in one directory:
  - SPHINX_DATA_DIR, when set;
  - next to the exe (a "data" folder) when a portable.txt marker sits
    beside a frozen exe — the portable edition;
  - otherwise %LOCALAPPDATA%\\Sphinx (falling back to ~/Sphinx).
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

# Absolute imports throughout this module, deliberately: PyInstaller
# executes the entry script outside the package, where relative
# imports fail. The rest of the package uses relative imports and is
# imported *through* this module (or as sphinx_win.app.main via -m),
# so both launch shapes work.
from sphinx_win.core.store import Store
from sphinx_win.core.tunnelstore import TunnelStore
from sphinx_win.dnsmgmt.base import AdapterDns, NotElevatedError
from sphinx_win.dnsmgmt.guard import DnsGuard
from sphinx_win.dnsmgmt.windows_impl import WindowsDnsManager, is_user_admin
from sphinx_win.app.controller import SphinxController
from sphinx_win.app.host import instance_name, parse_launch_args


def default_data_dir() -> Path:
    override = os.environ.get("SPHINX_DATA_DIR")
    if override:
        return Path(override)
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).resolve().parent
        if (exe_dir / "portable.txt").exists():
            return exe_dir / "data"
        base = os.environ.get("LOCALAPPDATA")
        return (Path(base) if base else Path.home()) / "Sphinx"
    return Path.home() / ".sphinx"


def build_controller(data_dir: Path) -> SphinxController:
    store = Store(data_dir)
    manager = WindowsDnsManager()
    from sphinx_win.tunnelmgmt.openvpn_windows_impl import (
        WindowsOpenVpnManager,
    )
    from sphinx_win.tunnelmgmt.windows_impl import WindowsTunnelManager

    return SphinxController(
        store,
        manager,
        data_dir,
        tunnel_manager=WindowsTunnelManager(),
        openvpn_manager=WindowsOpenVpnManager(work_dir=Path(data_dir)),
    )


def restore_dns_main(data_dir=None, manager_factory=None, out=print) -> int:
    """The headless restore: if Sphinx holds saved DNS settings,
    put them back (the guard verifies each one and retires the
    record only on a verified restore, and records protection
    intent off, like every successful stop); if it holds none,
    there is nothing to do and that is success. Exit code 3 means the
    restore could not be completed — the record is kept, and the
    message says why. Used by the installer's uninstaller, which
    aborts rather than strand a machine when this fails."""
    data_dir = Path(data_dir) if data_dir is not None else default_data_dir()
    try:
        manager = (manager_factory or WindowsDnsManager)()
        guard = DnsGuard(manager, data_dir)
        if guard.load_backup() is None:
            out("Sphinx holds no saved DNS settings; nothing to restore.")
            return 0
        result = guard.disengage()
        if result.ok:
            # A verified restore is a successful stop transition:
            # record protection intent off on the same data dir,
            # exactly as controller.restore_dns() does. Without
            # this, a later --autostart launch would see DISENGAGED
            # + intent on and re-engage DNS the user explicitly
            # restored here (Sweep #3, W-1).
            Store(data_dir).set_protection_intent(False)
    except NotElevatedError as e:
        out(str(e))
        return 3
    except Exception as e:
        out(f"Sphinx could not restore the saved DNS settings ({e}).")
        return 3
    out(result.message)
    return 0 if result.ok else 3


def restore_vpn_main(data_dir=None, tunnel_manager_factory=None,
                     dns_manager_factory=None, out=print,
                     openvpn_manager_factory=None) -> int:
    """The headless VPN teardown: if Sphinx holds a tunnel state
    record, take the tunnel down and restore exactly what the
    record holds (a VPN-only session's DNS originals), verifying
    each restore, and retire the record only when everything
    verifies. Exit code 3 means the teardown could not be
    verified — the record is kept, and the message says why. The
    installer's uninstaller runs this BEFORE the DNS restore and
    before any file is removed, and aborts on a nonzero code:
    Sphinx never strands a machine with a tunnel (or tunnel DNS)
    pointed at an edition that no longer exists. Exactly the DNS
    uninstall discipline, one record over.

    Note what this can and cannot do: the tunnel adapter belongs
    to the tray process that created it (WireGuardNT's sockets
    are owned by the creating process). Run while that host is
    still up, the host's own quit path is the teardown (the
    installer closes applications first — CloseApplications —
    and a running host's quit disconnects the VPN before it
    exits). This headless path owns the record-level restore:
    it asks the manager to take down any adapter THIS process
    holds (a fresh headless process holds none), and restores
    the record's DNS, verified — the part an uninstall must not
    leave behind even when the host is already gone. For an
    OpenVPN session (Phase 2) the same shape holds one step
    further: the record names the supervised openvpn.exe child's
    pid, and this path terminates exactly that recorded pid after
    asking the OpenVPN manager to stop its own child."""
    data_dir = Path(data_dir) if data_dir is not None else default_data_dir()
    try:
        tunnel_store = TunnelStore(data_dir)
        state = tunnel_store.load_state()
        if state is None:
            out("Sphinx holds no tunnel record; nothing to tear down.")
            return 0
        if tunnel_manager_factory is not None:
            manager = tunnel_manager_factory()
        else:
            from sphinx_win.tunnelmgmt.windows_impl import WindowsTunnelManager

            manager = WindowsTunnelManager()
        try:
            manager.down()
        except Exception:
            pass  # the record-level restore below is the verified part
        if getattr(state, "protocol", "wireguard") == "openvpn":
            # An OpenVPN session is torn down too: the supervised
            # child belongs to the tray host (whose quit path
            # disconnects first), but the record holds the child's
            # pid, so this headless path can end a Sphinx-started
            # openvpn.exe even when the host is already gone —
            # never a stranger's process: only the recorded pid.
            try:
                if openvpn_manager_factory is not None:
                    ovpn = openvpn_manager_factory()
                else:
                    from sphinx_win.tunnelmgmt.openvpn_windows_impl import (
                        WindowsOpenVpnManager,
                    )

                    ovpn = WindowsOpenVpnManager()
                try:
                    ovpn.down()
                except Exception:
                    pass
                pid = getattr(state, "openvpn_pid", None)
                if pid and hasattr(ovpn, "terminate_pid"):
                    ovpn.terminate_pid(pid)
            except Exception:
                pass  # the record-level restore below is the verified part
        if state.dns_originals:
            dns_manager = (dns_manager_factory or WindowsDnsManager)()
            failed = []
            for raw in state.dns_originals:
                adapter = AdapterDns.from_dict(raw)
                try:
                    dns_manager.set_dns(
                        adapter.interface_alias,
                        adapter.family,
                        list(adapter.servers),
                    )
                    if dns_manager.get_dns(
                        adapter.interface_alias, adapter.family
                    ) != list(adapter.servers):
                        failed.append(adapter)
                except Exception:
                    failed.append(adapter)
            if failed:
                names = ", ".join(
                    f"{a.interface_alias} ({a.family})" for a in failed
                )
                out(
                    "Sphinx could not put back the DNS settings its "
                    f"VPN session saved (unverified on: {names}), "
                    "so the tunnel record was kept."
                )
                return 3
        tunnel_store.clear_state()
    except Exception as e:
        out(f"Sphinx could not tear down its VPN session record ({e}).")
        return 3
    out("The VPN session is torn down and its settings are restored.")
    return 0


def try_claim_server(make_server, remove_server, probe_connect, name):
    """One claim attempt on the single-instance channel.

    ``make_server()`` builds a fresh (unlistened) local server,
    ``remove_server(name)`` clears a channel name, and
    ``probe_connect()`` asks a running host to show its window.

    Clearing the name is GATED (Sweep #3, W-7): the name is
    removed only after this attempt's own listen has failed AND a
    second probe has also failed. The old shape removed the name
    unconditionally before every claim; on platforms where
    removal is not a no-op, a live host whose probe merely timed
    out under load could have its channel cleared from under it
    by a second launch, which would then claim the name and run
    as a rival host. With the gate, a failed listen followed by a
    host answering the re-probe returns None here, and
    acquire_instance's loop turns this launch into a "show"; only
    a name nobody answers for — a crashed host's leftover — is
    cleared, and the claim is retried once with a fresh server.
    """
    candidate = make_server()
    if candidate.listen(name):
        return candidate
    if probe_connect():
        return None
    remove_server(name)
    candidate = make_server()
    return candidate if candidate.listen(name) else None


def acquire_instance(probe_connect, try_listen, *, attempts=3,
                     pause_s=0.2, sleep=time.sleep):
    """Decide this launch's role in the one-host-per-user rule.

    ``probe_connect()`` asks the running host (if any) to show its
    window and returns True when one answered; ``try_listen()``
    claims the channel and returns the server, or None when the
    claim failed. Returns ("show", None) when a host already owns
    the machine, ("host", server) when this launch claimed the
    channel, and ("solo", None) when the channel could not be
    claimed or held — the caller then proceeds without the
    single-instance net, best effort as before.

    Probing and claiming are two steps, so two launches in the
    same instant can both probe before either claims — and the
    loser of the claim would run on as a rival host, a second
    owner of the machine's DNS state. A failed claim is therefore
    followed by fresh probes before the net is given up: by then
    the winner is listening, the probe reaches it, and this
    launch becomes a "show" instead of a rival (Windows Phase 2
    audit).
    """
    for _ in range(attempts):
        if probe_connect():
            return "show", None
        server = try_listen()
        if server is not None:
            return "host", server
        sleep(pause_s)
    if probe_connect():
        return "show", None
    return "solo", None


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    launch = parse_launch_args(argv)
    if launch.restore_vpn:
        return restore_vpn_main()
    if launch.restore_dns:
        return restore_dns_main()

    from PySide6.QtNetwork import QLocalServer, QLocalSocket
    from PySide6.QtWidgets import QApplication

    from sphinx_win.app.autostart import AutostartManager, WindowsRunRegistry
    from sphinx_win.app.theme import stylesheet
    from sphinx_win.app.tray_app import MainWindow, TrayHost

    app = QApplication(sys.argv)
    app.setApplicationName("Sphinx")
    app.setOrganizationName("Sentinel Safeguard")
    # The Sphinx palette (basalt, sandstone, bronze-gold) — one
    # application-wide stylesheet, Phase 3. Presentation only.
    app.setStyleSheet(stylesheet())
    # The tray is the app's home now: closing every window must not
    # quit the host (the window's close goes to the tray instead).
    app.setQuitOnLastWindowClosed(False)

    # Single instance per user: a second launch shows the running
    # host's window and exits — two hosts would fight over one DNS
    # state, and the state has exactly one owner by design.
    name = instance_name()

    def probe_connect() -> bool:
        probe = QLocalSocket()
        probe.connectToServer(name)
        if not probe.waitForConnected(500):
            return False
        probe.write(b"show")
        probe.flush()
        probe.waitForBytesWritten(500)
        probe.disconnectFromServer()
        return True

    def try_listen():
        # The claim is gated (see try_claim_server): a crashed
        # host's leftover is cleared only after a failed listen
        # and a failed second probe — never unconditionally.
        return try_claim_server(
            QLocalServer, QLocalServer.removeServer, probe_connect, name
        )

    role, server = acquire_instance(probe_connect, try_listen)
    if role == "show":
        return 0

    def release_instance():
        if server is not None:
            server.close()
            QLocalServer.removeServer(name)

    controller = build_controller(default_data_dir())
    elevated = is_user_admin()
    try:
        autostart_manager = AutostartManager(WindowsRunRegistry())
    except RuntimeError:
        autostart_manager = None  # not Windows: nothing to manage
    window = MainWindow(controller, elevated=elevated)
    host = TrayHost(
        window,
        controller,
        elevated=elevated,
        launch=launch,
        autostart_manager=autostart_manager,
        release_instance=release_instance,
    )
    if server is not None:

        def _on_new_connection():
            pending = server.nextPendingConnection()
            if pending is not None:
                pending.readAll()
                pending.disconnectFromServer()
            window.showNormal()
            window.raise_()
            window.activateWindow()

        server.newConnection.connect(_on_new_connection)

    outcome = host.run_startup()
    if outcome.exit_now:
        release_instance()
        return 0
    if not launch.autostart or outcome.attention:
        window.show()
    elif outcome.summary:
        host.notify(outcome.summary)
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
