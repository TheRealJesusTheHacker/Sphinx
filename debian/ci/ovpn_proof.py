#!/usr/bin/env python3
"""CI PROOF (Phase 2): a real OpenVPN tunnel, client side =
Sphinx's shipped path only (profile -> sanitizer -> TunnelGuard
-> system openvpn invoked at arm's length).

Stands up an OpenVPN server inside a network namespace on the
runner (certificates generated IN-JOB with openssl, clearly
test-only, discarded with the job), plus an HTTP token server
that exists ONLY at the tunnel address inside that namespace.
Then, through the shipped code:

  (a) engages an OpenVPN Sphinx profile whose config carries
      dangerous directives (an ``up`` script that would create a
      marker file) and asserts the tunnel proves up;
  (b) asserts the marker was NEVER created — the sanitizer
      stripped the script directives before anything ran;
  (c) asserts real traffic crosses: the HTTP token is fetched
      through the tunnel address;
  (d) asserts DNS honesty: the server pushes a DNS server, the
      client's pull-filter rejects it, and /etc/resolv.conf is
      byte-identical before and after;
  (e) disconnects through the guard and asserts the interface
      and process are gone.

Any failure exits non-zero. Run as root: sudo python3 debian/ci/ovpn_proof.py
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sphinx_deb.core.tunnel import parse_config  # noqa: E402
from sphinx_deb.core.tunnelstore import TunnelStore  # noqa: E402
from sphinx_deb.tunnel.guard import RealTunnelRunner, TunnelGuard  # noqa: E402

TOKEN = "sphinx-ci-ovpn-token-9c1e"
NS = "ovpnsrv"
TUNNEL_SERVER_IP = "10.98.0.1"
ENDPOINT_IP = "10.201.0.2"
MARKER = Path("/tmp/sphinx-ci-ovpn-EVIL-MARKER")

NS_HTTP = r'''
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
TOKEN = "sphinx-ci-ovpn-token-9c1e"
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/token":
            body = TOKEN.encode()
            self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404); self.end_headers()
    def log_message(self, *args): pass
HTTPServer(("10.98.0.1", 18080), Handler).serve_forever()
'''


def run(argv, check=True, **kw):
    print("+", " ".join(str(a) for a in argv), flush=True)
    proc = subprocess.run(argv, capture_output=True, text=True, **kw)
    if check and proc.returncode != 0:
        raise SystemExit(f"FAILED: {argv}\n{proc.stdout}\n{proc.stderr}")
    return proc


def ns_exec(*argv, **kw):
    return run(["ip", "netns", "exec", NS, *argv], **kw)


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("ovpn_proof must run as root (sudo)")
    if MARKER.exists():
        MARKER.unlink()
    work = Path(tempfile.mkdtemp(prefix="sphinx-ovpn-proof-"))
    guard = None
    server_proc = None
    http_proc = None
    try:
        run(["modprobe", "tun"], check=False)
        if not Path("/dev/net/tun").exists():
            run(["mkdir", "-p", "/dev/net"], check=False)
            run(["mknod", "/dev/net/tun", "c", "10", "200"], check=False)
        # --- test-only certificates, generated in-job -----------
        def openssl(*args):
            return run(["openssl", *args])
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(work / "ca.key"), "-out", str(work / "ca.crt"),
                "-days", "1", "-subj", "/CN=Sphinx CI Test CA (test only)")
        for name in ("server", "client"):
            openssl("req", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(work / f"{name}.key"), "-out", str(work / f"{name}.csr"),
                    "-subj", f"/CN={name} (test only)")
            openssl("x509", "-req", "-in", str(work / f"{name}.csr"),
                    "-CA", str(work / "ca.crt"), "-CAkey", str(work / "ca.key"),
                    "-CAcreateserial", "-out", str(work / f"{name}.crt"), "-days", "1")
        ca = (work / "ca.crt").read_text()
        client_crt = (work / "client.crt").read_text()
        client_key = (work / "client.key").read_text()

        # --- underlay + server namespace -------------------------
        run(["ip", "netns", "add", NS])
        run(["ip", "link", "add", "veth-oh", "type", "veth", "peer", "name", "veth-os"])
        run(["ip", "link", "set", "veth-os", "netns", NS])
        run(["ip", "addr", "add", "10.201.0.1/24", "dev", "veth-oh"])
        run(["ip", "link", "set", "veth-oh", "up"])
        ns_exec("ip", "addr", "add", f"{ENDPOINT_IP}/24", "dev", "veth-os")
        ns_exec("ip", "link", "set", "veth-os", "up")
        ns_exec("ip", "link", "set", "lo", "up")

        server_conf = work / "server.conf"
        server_conf.write_text(
            "port 1194\nproto udp\ndev tun\n"
            f"ca {work}/ca.crt\ncert {work}/server.crt\nkey {work}/server.key\n"
            "dh none\nserver 10.98.0.0 255.255.255.0\n"
            'push "dhcp-option DNS 10.98.0.1"\n'
            "keepalive 10 60\ncipher AES-256-GCM\ndata-ciphers AES-256-GCM\n"
        )
        server_proc = subprocess.Popen(
            ["ip", "netns", "exec", NS, "openvpn", "--config", str(server_conf)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        helper = work / "ns_http.py"
        helper.write_text(NS_HTTP)
        # HTTP starts after the server tun exists; retry-bind loop inside Popen wrapper:
        http_proc = subprocess.Popen(
            ["ip", "netns", "exec", NS, "python3", "-c",
             "import time,sys\n"
             "for _ in range(50):\n"
             "    try:\n"
             f"        exec(open({str(helper)!r}).read()); break\n"
             "    except OSError:\n"
             "        time.sleep(0.5)\n"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2.0)

        # --- the client profile, through Sphinx's store ----------
        client_text = (
            "client\ndev tun\nproto udp\n"
            f"remote {ENDPOINT_IP} 1194\n"
            "resolv-retry infinite\nnobind\npersist-key\npersist-tun\n"
            "cipher AES-256-GCM\ndata-ciphers AES-256-GCM\n"
            # Dangerous lines the sanitizer MUST strip (would run as root):
            f"up /bin/sh -c 'touch {MARKER}'\n"
            "script-security 2\n"
            "plugin /tmp/evil.so\n"
            f"<ca>\n{ca}</ca>\n<cert>\n{client_crt}</cert>\n<key>\n{client_key}</key>\n"
        )
        store = TunnelStore(work / "state")
        profile = parse_config(client_text)
        profile.name = "CI-Proof"
        store.save(profile)

        resolv_before = hashlib.sha256(Path("/etc/resolv.conf").read_bytes()).hexdigest()

        guard = TunnelGuard(RealTunnelRunner(), store, work / "run")
        result = guard.engage(store.get("CI-Proof").profile, mode="vpn")
        print("engage:", result.message)
        assert result.ok, f"engage refused: {result.message}"
        print("PROOF (a): OpenVPN tunnel proven up through Sphinx's shipped path")

        assert not MARKER.exists(), "the config's up script RAN — sanitizer failed"
        print("PROOF (b): dangerous directives stripped; the up script never ran")

        import http.client
        body = None
        for _ in range(20):
            try:
                conn = http.client.HTTPConnection(TUNNEL_SERVER_IP, 18080, timeout=5)
                conn.request("GET", "/token")
                body = conn.getresponse().read().decode()
                break
            except OSError:
                time.sleep(1.0)
        print(f"PROOF (c): fetched through the tunnel: {body!r}")
        assert body == TOKEN, "the token did not cross the tunnel"

        resolv_after = hashlib.sha256(Path("/etc/resolv.conf").read_bytes()).hexdigest()
        assert resolv_before == resolv_after, "pushed DNS changed the resolver — pull-filter failed"
        print("PROOF (d): server-pushed DNS rejected; /etc/resolv.conf byte-identical")

        down = guard.disengage()
        print("disconnect:", down.message)
        assert down.ok
        assert not RealTunnelRunner().interface_exists("sphinxovpn")
        print("PROOF (e): tunnel down, interface gone")
        print("OPENVPN PROOF: ALL ASSERTIONS PASSED")
        return 0
    finally:
        if guard is not None:
            try:
                guard.disengage()
            except Exception:
                pass
        for proc in (http_proc, server_proc):
            if proc is not None:
                proc.terminate()
        run(["ip", "netns", "del", NS], check=False)
        run(["ip", "link", "del", "veth-oh"], check=False)
        if MARKER.exists():
            MARKER.unlink()


if __name__ == "__main__":
    raise SystemExit(main())
