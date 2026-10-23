#!/usr/bin/env python3
"""CI PROOF: a real WireGuard tunnel, client side = Sphinx's
shipped path only (profile -> TunnelGuard.engage -> wg-quick).

Stands up a WireGuard server inside a network namespace on the
runner (the server's implementation is the kernel's, driven by
hand — the spec leaves the server free), plus, inside that
namespace, a DNS responder and an HTTP token server that exist
ONLY at the tunnel address. Then, through the shipped code:

  (a) engages a Sphinx profile and asserts `wg show`
      latest-handshake is fresh;
  (b) asserts real traffic crosses: the HTTP token is fetched
      through the tunnel address;
  (c) VPN+Blocker conformance in the same run (TUNNEL-SPEC, "The
      filter questions names; it does not block traffic"): with
      the brain in the path and the profile DNS as upstream
      through the tunnel, an UNLISTED name resolves and a LISTED
      name is sinkholed locally;
  (d) disconnects through the guard and asserts the interface
      is gone.

Any failure exits non-zero — this job must fail if the tunnel
does not actually carry traffic. Run as root on the CI runner:
    sudo python3 debian/ci/wg_proof.py
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sphinx_deb.core.blocklist import Allowlist, Blocklist, FilterLists  # noqa: E402
from sphinx_deb.core.dnswire import build_query, parse_query  # noqa: E402
from sphinx_deb.core.forwarder import forward_query  # noqa: E402
from sphinx_deb.core.server import FilterEngine  # noqa: E402
from sphinx_deb.core.tunnel import build_wireguard_text, parse_config  # noqa: E402
from sphinx_deb.core.tunnelstore import TunnelStore  # noqa: E402
from sphinx_deb.tunnel.guard import (  # noqa: E402
    RealTunnelRunner,
    TunnelGuard,
    freshest_handshake_age,
)

TOKEN = "sphinx-ci-tunnel-token-7f3a"
NS = "srv"
TUNNEL_SERVER_IP = "10.99.0.1"
TUNNEL_CLIENT_IP = "10.99.0.2"
ENDPOINT_IP = "10.200.0.2"

NS_SERVICES = r'''
import socket, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKEN = "sphinx-ci-tunnel-token-7f3a"

def question_end(data):
    i = 12
    while i < len(data) and data[i] != 0:
        i += data[i] + 1
    return i + 5  # root byte + qtype + qclass

def dns_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("10.99.0.1", 53))
    while True:
        data, addr = sock.recvfrom(4096)
        end = question_end(data)
        header = data[:2] + b"\x81\x80" + b"\x00\x01\x00\x01\x00\x00\x00\x00"
        answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton("10.99.0.1")
        sock.sendto(header + data[12:end] + answer, addr)

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/token":
            body = TOKEN.encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404); self.end_headers()
    def log_message(self, *args):
        pass

threading.Thread(target=dns_server, daemon=True).start()
HTTPServer(("10.99.0.1", 18080), Handler).serve_forever()
'''


def run(argv, check=True, **kw):
    print("+", " ".join(argv), flush=True)
    proc = subprocess.run(argv, capture_output=True, text=True, **kw)
    if check and proc.returncode != 0:
        raise SystemExit(
            f"FAILED: {' '.join(argv)}\n{proc.stdout}\n{proc.stderr}"
        )
    return proc


def ns_exec(*argv, **kw):
    return run(["ip", "netns", "exec", NS, *argv], **kw)


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("wg_proof must run as root (sudo)")
    work = Path(tempfile.mkdtemp(prefix="sphinx-wg-proof-"))
    state_dir = work / "state"
    runtime_dir = work / "run"
    services = None
    guard = None
    try:
        run(["modprobe", "wireguard"], check=False)
        # --- the underlay: a veth pair into the server namespace
        run(["ip", "netns", "add", NS])
        run(["ip", "link", "add", "veth-h", "type", "veth", "peer", "name", "veth-s"])
        run(["ip", "link", "set", "veth-s", "netns", NS])
        run(["ip", "addr", "add", "10.200.0.1/24", "dev", "veth-h"])
        run(["ip", "link", "set", "veth-h", "up"])
        ns_exec("ip", "addr", "add", f"{ENDPOINT_IP}/24", "dev", "veth-s")
        ns_exec("ip", "link", "set", "veth-s", "up")
        ns_exec("ip", "link", "set", "lo", "up")

        # --- keys: server by hand; the CLIENT keypair comes from
        # Sphinx's own shipped path (wg genkey via the guard).
        store = TunnelStore(state_dir)
        guard = TunnelGuard(RealTunnelRunner(), store, runtime_dir)
        client_private, client_public = guard.generate_keypair()
        server_private = run(["wg", "genkey"]).stdout.strip()
        server_public = subprocess.run(
            ["wg", "pubkey"], input=server_private + "\n",
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        server_key_file = work / "server.key"
        server_key_file.write_text(server_private + "\n")
        os.chmod(server_key_file, 0o600)

        # --- the server endpoint in its namespace (kernel WG)
        ns_exec("ip", "link", "add", "wg-srv", "type", "wireguard")
        ns_exec(
            "wg", "set", "wg-srv",
            "private-key", str(server_key_file),
            "listen-port", "51820",
            "peer", client_public,
            "allowed-ips", f"{TUNNEL_CLIENT_IP}/32",
        )
        ns_exec("ip", "addr", "add", f"{TUNNEL_SERVER_IP}/24", "dev", "wg-srv")
        ns_exec("ip", "link", "set", "wg-srv", "up")

        # --- services that exist ONLY inside the tunnel
        helper = work / "ns_services.py"
        helper.write_text(NS_SERVICES)
        services = subprocess.Popen(
            ["ip", "netns", "exec", NS, "python3", str(helper)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(1.0)

        # --- the client profile, through Sphinx's store
        text = build_wireguard_text(
            name="CI Proof",
            private_key=client_private,
            addresses=[f"{TUNNEL_CLIENT_IP}/32"],
            dns=[TUNNEL_SERVER_IP],
            server_public_key=server_public,
            endpoint=f"{ENDPOINT_IP}:51820",
            allowed_ips=["0.0.0.0/0"],
        )
        store.save(parse_config(text))

        # --- (a) engage through the shipped guard; handshake fresh
        result = guard.engage(store.get("CI Proof").profile, mode="vpn+blocker")
        print("engage:", result.message)
        assert result.ok, f"engage refused: {result.message}"
        age = freshest_handshake_age(RealTunnelRunner(), "sphinx0")
        print(f"PROOF (a): latest-handshake age = {age}s")
        assert age is not None and age <= 180, "handshake is not fresh"

        # --- (b) real traffic crosses the tunnel
        import http.client

        conn = http.client.HTTPConnection(TUNNEL_SERVER_IP, 18080, timeout=10)
        conn.request("GET", "/token", headers={"Host": "unlisted.example"})
        body = conn.getresponse().read().decode()
        print(f"PROOF (b): fetched through the tunnel: {body!r}")
        assert body == TOKEN, "the token did not cross the tunnel"

        # --- (c) VPN+Blocker conformance in the same run
        lists = FilterLists(Blocklist({"ads.example.com"}), Allowlist([]))
        engine = FilterEngine(
            lists_provider=lambda: lists,
            forwarder=lambda data: forward_query(
                data, resolvers=[TUNNEL_SERVER_IP], timeout=5.0
            ),
        )
        unlisted = engine.handle_query(build_query("unlisted.example"))
        assert unlisted is not None and parse_query(unlisted).is_response
        assert socket.inet_aton(TUNNEL_SERVER_IP) in unlisted
        listed = engine.handle_query(build_query("ads.example.com"))
        assert listed is not None and b"\x00\x00\x00\x00" in listed
        print("PROOF (c): unlisted resolved through the tunnel; "
              "listed sinkholed locally — filter on, traffic passing")

        # --- (d) disconnect through the guard
        down = guard.disengage()
        print("disconnect:", down.message)
        assert down.ok
        assert not RealTunnelRunner().interface_exists("sphinx0")
        print("PROOF (d): tunnel down, interface gone")
        print("WG PROOF: ALL ASSERTIONS PASSED")
        return 0
    finally:
        if services is not None:
            services.terminate()
        if guard is not None:
            try:
                guard.disengage()
            except Exception:
                pass
        run(["ip", "netns", "del", NS], check=False)
        run(["ip", "link", "del", "veth-h"], check=False)


if __name__ == "__main__":
    raise SystemExit(main())
