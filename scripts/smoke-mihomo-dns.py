#!/usr/bin/env python3
"""Exercise Routa's ordinary-port DNS configuration against the pinned Linux core.

Usage: python3 scripts/smoke-mihomo-dns.py /path/to/mihomo
Needs Linux user/mount/network namespaces (unshare) and OpenSSL. No network
access, root on the host, external DNS, or modification to host resolv.conf.
Pass --fixture-dir DIR to use the exact YAML exported by Routa's Rust test.
Without fixtures, independently checks the corresponding pinned core behavior.
"""

import argparse
import base64
import contextlib
import fcntl
import http.server
import json
import os
import pathlib
import re
import shutil
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

IP = "127.0.0.1"
SYSTEM_IP = "127.0.0.2"
ALIAS = "__routa_dns__"
PIN = (pathlib.Path(__file__).resolve().parent.parent / "src-tauri/binaries/MIHOMO_VERSION").read_text().strip()


def parse_dns(packet):
    offset = 12
    labels = []
    while packet[offset]:
        size = packet[offset]
        offset += 1
        assert size < 64
        labels.append(packet[offset:offset + size].decode("ascii").lower())
        offset += size
    kind, klass = struct.unpack_from("!HH", packet, offset + 1)
    assert klass == 1
    return ".".join(labels), kind, packet[12:offset + 5]


def response(packet, address):
    _, kind, question = parse_dns(packet)
    count = 1 if kind == 1 and address is not None else 0
    rcode = 0 if address is not None else 3
    header = packet[:2] + struct.pack("!5H", 0x8180 | rcode, 1, count, 0, 0)
    answer = struct.pack("!HHHIH4s", 0xC00C, 1, 1, 30, 4, socket.inet_aton(address)) if count else b""
    return header + question + answer


class DnsUdp(socketserver.BaseRequestHandler):
    def handle(self):
        packet, server_socket = self.request
        name, kind, _ = parse_dns(packet)
        self.server.events.append((name, kind))
        server_socket.sendto(response(packet, self.server.answer(name)), self.client_address)


class DnsTcp(socketserver.StreamRequestHandler):
    def handle(self):
        framing = self.rfile.read(2)
        if len(framing) != 2:
            return
        packet = self.rfile.read(int.from_bytes(framing, "big"))
        name, kind, _ = parse_dns(packet)
        self.server.events.append((name, kind))
        result = response(packet, self.server.answer(name))
        self.wfile.write(len(result).to_bytes(2, "big") + result)


class Http(http.server.BaseHTTPRequestHandler):
    def ok(self, data, content_type):
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Type", content_type)
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_):
        pass


class Doh(Http):
    def do_GET(self):
        params = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        packet = base64.urlsafe_b64decode(params["dns"][0] + "===")
        name, kind, _ = parse_dns(packet)
        self.server.events.append((name, kind))
        self.ok(response(packet, IP), "application/dns-message")


class Target(Http):
    def do_GET(self):
        self.server.events.append(self.headers["Host"])
        self.ok(b"target", "text/plain")


class Hop(Http):
    def do_CONNECT(self):
        self.server.events.append(self.path)
        if not self.server.available or self.path not in self.server.routes:
            self.connection.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            return
        with socket.create_connection((IP, self.server.routes[self.path]), timeout=4) as upstream:
            self.send_response(200)
            self.end_headers()

            def copy(source, destination):
                try:
                    while data := source.recv(65536):
                        destination.sendall(data)
                    destination.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

            forward = threading.Thread(target=copy, args=(self.connection, upstream), daemon=True)
            forward.start()
            copy(upstream, self.connection)
            forward.join(timeout=4)


class Tcp(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class Udp(socketserver.ThreadingUDPServer):
    daemon_threads = True
    allow_reuse_address = True


def spawn(stack, handler, host=IP, port=0, protocol=Tcp, tls=None, **attrs):
    server = stack.enter_context(protocol((host, port), handler))
    if tls:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
    for key, value in attrs.items():
        setattr(server, key, value)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    stack.callback(server.shutdown)
    return server.server_address[1]


def configure_ns(root):
    # This runs only after unshare; keep the host's exact resolv.conf untouched.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        request = bytearray(struct.pack("16sh22x", b"lo", 0))
        fcntl.ioctl(sock, 0x8913, request, True)   # SIOCGIFFLAGS
        flags = struct.unpack_from("h", request, 16)[0]
        struct.pack_into("h", request, 16, flags | 1)
        fcntl.ioctl(sock, 0x8914, request, True)   # SIOCSIFFLAGS, IFF_UP
    resolv = root / "resolv.conf"
    resolv.write_text(f"nameserver {SYSTEM_IP}\n")
    subprocess.run(["mount", "--bind", str(resolv), "/etc/resolv.conf"], check=True)


def tls_server(root):
    cert = root / "cert.pem"
    key = root / "key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=Routa test DoH", "-addext", f"subjectAltName=IP:{IP}",
         "-keyout", str(key), "-out", str(cert)],
        check=True, capture_output=True,
    )
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(cert, key)
    return server, cert


def free_ports(count):
    with contextlib.ExitStack() as stack:
        ports = []
        for _ in range(count):
            sock = stack.enter_context(socket.socket())
            sock.bind((IP, 0))
            ports.append(sock.getsockname()[1])
    return ports


def config(exit_port, entry_port, doh_port, direct_dns, bootstrap, controller, direct, routed, *, alias="精选 # &, 出口", chain=False, system_control=False):
    exits = [{"name": "精选 # &, 出口", "type": "http", "server": "node.entry.test", "port": exit_port}]
    if chain:
        exits = [
            {"name": "__test_entry", "type": "http", "server": "node.entry.test", "port": entry_port},
            {"name": "精选 # &, 出口", "type": "http", "server": IP, "port": exit_port,
             "dialer-proxy": "__test_entry", "udp": False},
        ]
    return {
        "mode": "rule",
        "log-level": "debug",
        "external-controller": f"{IP}:{controller}",
        "proxies": exits,
        "proxy-groups": [{"name": ALIAS, "type": "select", "proxies": [alias]}],
        "rules": ["MATCH,REJECT"],
        "sub-rules": {"ip-only": [f"IP-CIDR,{IP}/32,DIRECT", "MATCH,REJECT"]},
        "listeners": [
            {"name": "fixed-direct", "type": "mixed", "listen": IP, "port": direct, "proxy": "DIRECT"},
            {"name": "ip-routed", "type": "mixed", "listen": IP, "port": routed, "rule": "ip-only"},
        ],
        "dns": {
            "enable": True,
            "enhanced-mode": "redir-host",
            "use-system-hosts": False,
            "ipv6": False,
            "respect-rules": False,
            "prefer-h3": False,
            "default-nameserver": [f"{IP}:{bootstrap}"],
            "proxy-server-nameserver": [f"{IP}:{bootstrap}"],
            "nameserver": ["system://" if system_control else f"https://{IP}:{doh_port}/dns-query#{ALIAS}"],
            "nameserver-policy": {"+.local.test": f"{IP}:{direct_dns}"},
        },
    }


@contextlib.contextmanager
def running(core, root, cfg, controller, cert):
    path = root / "config.yaml"
    path.write_text(json.dumps(cfg) if isinstance(cfg, dict) else cfg)
    output = root / "core.log"
    env = os.environ.copy()
    if cert:
        env["SSL_CERT_FILE"] = str(cert)
    else:
        env.pop("SSL_CERT_FILE", None)
    with output.open("w") as log:
        with subprocess.Popen([str(core), "-d", str(root), "-f", str(path)], stdout=log, stderr=log, env=env) as proc:
            try:
                deadline = time.monotonic() + 5
                while True:
                    try:
                        with socket.create_connection((IP, controller), timeout=0.2):
                            break
                    except OSError:
                        if proc.poll() is not None or time.monotonic() >= deadline:
                            raise RuntimeError("pinned core did not start")
                        time.sleep(0.05)
                yield output
            except BaseException:
                print(output.read_text(), file=sys.stderr)
                raise
            finally:
                proc.terminate()
                proc.wait(timeout=5)


def query(ctrl, name):
    url = f"http://{IP}:{ctrl}/dns/query?" + urllib.parse.urlencode({"name": name})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(urllib.request.Request(url, headers={"Authorization": "Bearer test"}), timeout=8) as reply:
            result = json.load(reply)
    except urllib.error.HTTPError as err:
        assert err.code == 500, err
        return None
    answer = result.get("Answer")
    return answer[0]["data"] if result["Status"] == 0 and answer else None


def visit(listener, name, target):
    with socket.create_connection((IP, listener), timeout=7) as sock:
        sock.sendall(f"GET http://{name}:{target}/ HTTP/1.1\r\nHost: {name}:{target}\r\nConnection: close\r\n\r\n".encode("ascii"))
        with sock.makefile("rb") as reply:
            return reply.readline()


def fixture_config(fixtures, name, ports):
    text = (fixtures / f"{name}.yaml").read_text()
    for key in ("31001", "31002", "31003", "31004", "31006", "31007", "31008"):
        assert re.search(rf"\b{key}\b", text), f"{name} fixture missing placeholder port {key}"
    if name == "chain":
        assert re.search(r"\b31005\b", text), "chain fixture missing entry placeholder"
    # Rewrite only ephemeral ports and increase logging for negative assertions.
    replacements = {str(31001 + index): str(port) for index, port in enumerate(ports)}
    text = re.sub(r"\b3100[1-8]\b", lambda m: replacements[m.group()], text)
    text, count = re.subn(r"(?m)^log-level: warning$", "log-level: debug", text)
    assert count == 1, "generated config must contain its default log-level"
    return text


def prime_geosite(root):
    # Minimal v1.19.33 protobuf GeoSiteList (CN -> Domain suffix fixture-cn.test).
    # Keeps this smoke deterministic and entirely offline.
    def field(number, data):
        assert len(data) < 128
        return bytes([number << 3 | 2, len(data)]) + data

    domain = b"\x08\x02" + field(2, b"fixture-cn.test")
    (root / "GeoSite.dat").write_bytes(field(1, field(1, b"CN") + field(2, domain)))


def exercise(core, root, fixtures):
    configure_ns(root)
    prime_geosite(root)
    tls, cert = tls_server(root)
    plaintext, bootstrap_queries, system_queries, doh_queries = [], [], [], []
    entry_calls, exit_calls, target_calls = [], [], []
    bootstrap_ready = True
    with contextlib.ExitStack() as stack:
        spawn(stack, DnsUdp, host=SYSTEM_IP, port=53, protocol=Udp, answer=lambda _: IP, events=system_queries)
        spawn(stack, DnsTcp, host=SYSTEM_IP, port=53, answer=lambda _: IP, events=system_queries)
        direct_dns = spawn(stack, DnsUdp, protocol=Udp, answer=lambda _: IP, events=plaintext)
        bootstrap = spawn(
            stack, DnsUdp, protocol=Udp,
            answer=lambda name: IP if bootstrap_ready and name == "node.entry.test" else None,
            events=bootstrap_queries,
        )
        target = spawn(stack, Target, events=target_calls)
        doh = spawn(stack, Doh, tls=tls, events=doh_queries)
        tls_bootstrap_queries = []
        https_bootstrap = spawn(stack, Doh, tls=tls, events=tls_bootstrap_queries)
        # Record each CONNECT and reject any route not explicitly configured.
        with Tcp((IP, 0), Hop) as exit_hop, Tcp((IP, 0), Hop) as entry_hop:
            exit_port = exit_hop.server_address[1]
            entry = entry_hop.server_address[1]
            exit_hop.routes = {f"{IP}:{doh}": doh}
            entry_hop.routes = {f"{IP}:{exit_port}": exit_port}
            exit_hop.available = entry_hop.available = True
            entry_hop.events, exit_hop.events = entry_calls, exit_calls
            for hop in [exit_hop, entry_hop]:
                threading.Thread(target=hop.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
                stack.callback(hop.shutdown)
            ctrl, direct, routed = free_ports(3)
            base = (exit_port, entry, doh, direct_dns, bootstrap, ctrl, direct, routed)
            def choose(name, **kwargs):
                if fixtures:
                    return fixture_config(fixtures, name, (ctrl, direct, routed, exit_port, entry, doh, direct_dns, bootstrap))
                cfg = config(*base, **kwargs)
                if name == "geosite":
                    cfg["dns"]["nameserver-policy"]["geosite:cn"] = f"{IP}:{direct_dns}"
                return cfg

            # A deliberately unprotected positive control is never a generated config.
            with running(core, root, config(*base, system_control=True), ctrl, cert):
                assert query(ctrl, "positive-control.external.test") == IP
                assert ("positive-control.external.test", 1) in system_queries, system_queries
            system_queries.clear()
            with running(core, root, choose("single"), ctrl, cert) as log:
                assert query(ctrl, "protected.external.test") == IP
                assert ("protected.external.test", 1) in doh_queries, doh_queries
                assert exit_calls == [f"{IP}:{doh}"], exit_calls
                assert ("node.entry.test", 1) in bootstrap_queries, bootstrap_queries

                assert query(ctrl, "allowed.local.test") == IP
                assert ("allowed.local.test", 1) in plaintext, plaintext
                assert b" 200 " in visit(direct, "fixed.external.test", target)
                assert b" 200 " in visit(routed, "ip-rule.external.test", target)
                assert {"fixed.external.test", "ip-rule.external.test"} <= {name for name, _ in doh_queries}
                assert len(target_calls) == 2, target_calls

                before = len(doh_queries)
                attempts = len(exit_calls)
                exit_hop.available = False
                assert query(ctrl, "egress-failed.external.test") is None
                assert len(exit_calls) > attempts, exit_calls
                assert len(doh_queries) == before, doh_queries
                assert b" 200 " not in visit(direct, "direct-failed.external.test", target)
                assert b" 200 " not in visit(routed, "ip-rule-failed.external.test", target)
                assert len(target_calls) == 2, target_calls
                assert query(ctrl, "failure-survival.local.test") == IP
                assert "[DNS] system dns update" not in log.read_text()
                exit_hop.available = True
            # Also exercise the shipping bootstrap *transport*: IP-literal
            # validated HTTPS, directly reachable, independent of target DoH.
            # Adapt only the two bootstrap fields of the same fixture.
            endpoint = f"https://{IP}:{https_bootstrap}/dns-query"
            secure = choose("single")
            if isinstance(secure, str):
                old = f"{IP}:{bootstrap}"
                assert secure.count(old) == 2
                secure = secure.replace(old, endpoint)
            else:
                for key in ("default-nameserver", "proxy-server-nameserver"):
                    secure["dns"][key] = [endpoint]
            with running(core, root, secure, ctrl, cert):
                before = len(exit_calls)
                assert query(ctrl, "secure-bootstrap.external.test") == IP
                assert ("secure-bootstrap.external.test", 1) in doh_queries
                assert {name for name, _ in tls_bootstrap_queries} == {"node.entry.test"}
                assert exit_calls[before:] == [f"{IP}:{doh}"]
            with running(core, root, choose("unavailable", alias="REJECT"), ctrl, cert) as log:
                before, attempts = len(doh_queries), len(exit_calls)
                assert query(ctrl, "missing-egress.external.test") is None
                assert len(doh_queries) == before and len(exit_calls) == attempts
                assert "[DNS] system dns update" not in log.read_text()
            with running(core, root, choose("single"), ctrl, cert) as log:
                bootstrap_ready = False
                before, attempts, queries = len(doh_queries), len(exit_calls), len(bootstrap_queries)
                assert query(ctrl, "bootstrap-failed.external.test") is None
                assert len(bootstrap_queries) > queries, bootstrap_queries
                assert len(doh_queries) == before and len(exit_calls) == attempts
                assert "[DNS] system dns update" not in log.read_text()
                bootstrap_ready = True
            with running(core, root, choose("single"), ctrl, None) as log:
                before, attempts = len(doh_queries), len(exit_calls)
                assert query(ctrl, "tls-failed.external.test") is None
                assert len(doh_queries) == before and len(exit_calls) > attempts
                assert "certificate" in log.read_text()
            with running(core, root, choose("chain", chain=True), ctrl, cert) as log:
                before, last = len(entry_calls), len(exit_calls)
                assert query(ctrl, "two-hop.external.test") == IP
                assert entry_calls[before:] == [f"{IP}:{exit_port}"], entry_calls
                assert exit_calls[last:] == [f"{IP}:{doh}"], exit_calls
                entry_hop.available = False
                before, last = len(doh_queries), len(exit_calls)
                assert query(ctrl, "two-hop-failed.external.test") is None
                assert len(doh_queries) == before and len(exit_calls) == last, (doh_queries, exit_calls)
                assert "[DNS] system dns update" not in log.read_text()
            with running(core, root, choose("geosite"), ctrl, cert) as log:
                assert query(ctrl, "sub.fixture-cn.test") == IP
                assert ("sub.fixture-cn.test", 1) in plaintext, plaintext
                assert query(ctrl, "unlisted.cn") == IP
                assert ("unlisted.cn", 1) in doh_queries, doh_queries
                assert "[DNS] system dns update" not in log.read_text()
            assert not system_queries, system_queries
            assert {name for name, _ in bootstrap_queries} == {"node.entry.test"}, bootstrap_queries
            assert {name for name, _ in plaintext} == {"allowed.local.test", "failure-survival.local.test", "sub.fixture-cn.test"}, plaintext
    source = "Routa-exported YAML" if fixtures else "independent core config"
    print(f"{PIN} ({source}): named DoH, explicit suffix and GEOSITE policy, bootstrap, "
          "direct/IP rules, two-hop, TLS failure and fail-closed passed; no system or plaintext fallback observed.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("core", type=pathlib.Path)
    parser.add_argument("--fixture-dir", type=pathlib.Path)
    args = parser.parse_args()
    core = args.core.resolve(strict=True)
    if os.environ.get("_ROUTA_DNS_PARENT_NET") is None:
        for binary in ("unshare", "mount", "openssl"):
            if not shutil.which(binary):
                parser.error(f"{binary} is required")
        version = subprocess.check_output([str(core), "-v"], text=True)
        if not re.search(r"\b" + re.escape(PIN) + r"\b", version):
            parser.error(f"expected mihomo {PIN}, got: {version.strip()}")
        for ns in ("net", "mnt"):
            os.environ[f"_ROUTA_DNS_PARENT_{ns.upper()}"] = os.readlink(f"/proc/self/ns/{ns}")
        os.execvp("unshare", ["unshare", "-Urmn", "--", sys.executable, __file__, *sys.argv[1:]])
    if any(os.environ.get(f"_ROUTA_DNS_PARENT_{ns.upper()}") in (None, os.readlink(f"/proc/self/ns/{ns}"))
           for ns in ("net", "mnt")):
        parser.error("refusing to rewrite resolv.conf outside a private namespace")
    with tempfile.TemporaryDirectory(prefix="routa-dns-smoke-") as dirname:
        exercise(core, pathlib.Path(dirname), args.fixture_dir)


if __name__ == "__main__":
    main()
