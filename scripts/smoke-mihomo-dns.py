#!/usr/bin/env python3
"""Exercise Routa's DNS diversion and opt-in TUN Fake-IP against the pinned core.

Usage: python3 scripts/smoke-mihomo-dns.py /path/to/mihomo
Needs Linux user/mount/network namespaces (unshare) and OpenSSL. No network
access, root on the host, external DNS, or modification to host resolv.conf.
Pass --fixture-dir DIR to use the exact YAML exported by Routa's Rust test.
Without fixtures, independently checks the corresponding pinned core behavior.
For the Fake-IP test only, expose the same enhanced resolver on private
loopback instead of creating an OS TUN adapter in the test namespace.
"""

import argparse
import base64
import contextlib
import fcntl
import http.server
import ipaddress
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
DIRECT_IPV6 = "2001:db8::2"
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
    data = b""
    if address is not None:
        ip = ipaddress.ip_address(address)
        if kind == (1 if ip.version == 4 else 28):
            data = ip.packed
    rcode = 0 if address is not None else 3
    header = packet[:2] + struct.pack("!5H", 0x8180 | rcode, 1, bool(data), 0, 0)
    answer = struct.pack("!HHHIH", 0xC00C, kind, 1, 30, len(data)) + data if data else b""
    return header + question + answer


class DnsUdp(socketserver.BaseRequestHandler):
    def handle(self):
        packet, server_socket = self.request
        name, kind, _ = parse_dns(packet)
        self.server.events.append((name, kind))
        server_socket.sendto(response(packet, self.server.answer(name, kind)), self.client_address)


class DnsTcp(socketserver.StreamRequestHandler):
    def handle(self):
        framing = self.rfile.read(2)
        if len(framing) != 2:
            return
        packet = self.rfile.read(int.from_bytes(framing, "big"))
        name, kind, _ = parse_dns(packet)
        self.server.events.append((name, kind))
        result = response(packet, self.server.answer(name, kind))
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
def running(core, root, cfg, controller, cert, *, ready_proxy, dns_port=None):
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
                ports = (controller, ready_proxy) + ((dns_port,) if dns_port is not None else ())
                for port in ports:
                    while True:
                        try:
                            with socket.create_connection((IP, port), timeout=0.2):
                                break
                        except OSError:
                            if proc.poll() is not None or time.monotonic() >= deadline:
                                raise RuntimeError(f"pinned core did not start on port {port}")
                            time.sleep(0.05)
                # TCP and UDP listeners are started by separate goroutines.
                if dns_port is not None:
                    started = f"DNS server(UDP) listening at: {IP}:{dns_port}"
                    while started not in output.read_text():
                        if proc.poll() is not None or time.monotonic() >= deadline:
                            raise RuntimeError(f"pinned core did not bind UDP port {dns_port}")
                        time.sleep(0.05)
                # Mihomo starts listening before finishing provider setup and
                # releasing the tunnel from suspended/inner-only operation.
                # Check actual routing with a literal loopback IP (no DNS).
                while True:
                    try:
                        status = visit(ready_proxy, IP, controller, path="/version",
                                       extra_header="Authorization: Bearer test\r\n", timeout=0.25)
                    except OSError:
                        status = b""
                    if b" 200 " in status:
                        break
                    if proc.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError("pinned core is not forwarding on the fixture's fixed direct port")
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


def visit(listener, name, target, *, path="/", extra_header="", timeout=7):
    with socket.create_connection((IP, listener), timeout=timeout) as sock:
        sock.sendall(f"GET http://{name}:{target}{path} HTTP/1.1\r\nHost: {name}:{target}\r\n"
                     f"{extra_header}Connection: close\r\n\r\n".encode("ascii"))
        with sock.makefile("rb") as reply:
            return reply.readline()


def dns_wire(port, name, kind=1, *, tcp=False):
    # /dns/query bypasses the enhanced DNS middleware. Send a wire query to
    # the same DNS service as TUN's hijack instead, over UDP or framed TCP.
    qname = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\0"
    question = qname + struct.pack("!HH", kind, 1)
    header = struct.pack("!6H", 0x9629, 0x0100, 1, 0, 0, 0)
    packet = header + question
    if tcp:
        with socket.create_connection((IP, port), timeout=8) as sock:
            sock.sendall(len(packet).to_bytes(2, "big") + packet)
            with sock.makefile("rb") as reply:
                length = int.from_bytes(reply.read(2), "big")
                packet = reply.read(length)
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(8)
            sock.connect((IP, port))
            sock.sendall(packet)
            packet = sock.recv(4096)
    ident, flags, questions, answers, _, _ = struct.unpack_from("!6H", packet)
    assert ident == 0x9629 and flags & 0x8000 and not flags & 0x0200 and questions == 1
    assert packet[12:12 + len(question)] == question, (name, packet)
    rcode = flags & 15
    if not answers:
        return rcode, None
    assert answers == 1 and rcode == 0 and kind in (1, 28), (name, kind, packet)
    offset = 12 + len(question)
    assert packet[offset:offset + 2] == b"\xc0\x0c", (name, packet)
    answer_kind, klass, _, length = struct.unpack_from("!HHIH", packet, offset + 2)
    assert answer_kind == kind and klass == 1
    family = socket.AF_INET if kind == 1 else socket.AF_INET6
    return rcode, socket.inet_ntop(family, packet[offset + 12:offset + 12 + length])


def visit_socks_fake(listener, fake_address, target):
    # Supply only the synthetic address in the SOCKS CONNECT, with a numeric
    # Host header. Mihomo must recover the name from its Fake-IP pool.
    with socket.create_connection((IP, listener), timeout=8) as sock:
        with sock.makefile("rb") as reply:
            sock.sendall(b"\x05\x01\x00")
            assert reply.read(2) == b"\x05\x00"
            sock.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(fake_address) + target.to_bytes(2, "big"))
            assert reply.read(10)[:4] == b"\x05\x00\x00\x01"
            sock.sendall(f"GET / HTTP/1.1\r\nHost: {IP}:{target}\r\nConnection: close\r\n\r\n".encode("ascii"))
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


def fakeip_wire_config(cfg, listen_port, direct_dns):
    address = f"{IP}:{listen_port}"
    if isinstance(cfg, str):
        # Do not change production DNS policy, transport routing, or pools.
        # A test DNS port invokes the enhancer without touching the host's
        # TUN interfaces or DNS settings.
        dns = re.search(r"(?m)^dns:\n((?: .+\n)*)", cfg)
        assert dns and not re.search(r"(?m)^  listen:", dns[1]), "unexpected production DNS listen"
        cfg, count = re.subn(r"(?m)^tun:\n  enable: true$", "tun:\n  enable: false", cfg)
        assert count == 1, "expected exported TUN profile"
        cfg, count = re.subn(r"(?m)^dns:$", f"dns:\n  listen: {address}", cfg)
        assert count == 1
        return cfg
    # Standalone pinned-core check when no Routa fixture directory was passed.
    available = cfg["proxy-groups"][0]["proxies"] != ["REJECT"]
    real_suffixes = ["localhost", "local", "lan", "internal", "home.arpa", "local.test"]
    cfg["hosts"] = {"+.localhost": [IP, "::1"]}
    cfg["dns"].update({
        "listen": address,
        "enhanced-mode": "fake-ip",
        "ipv6": True,
        "fake-ip-range": "198.18.0.1/16",
        "fake-ip-filter-mode": "blacklist" if available else "whitelist",
        "fake-ip-filter": (
            ["+." + name for name in real_suffixes] + ["*", "geosite:cn", "www.msftconnecttest.com", "node.entry.test"]
            if available else []
        ),
        "use-hosts": True,
    })
    cfg["dns"]["nameserver-policy"].update({
        "geosite:cn": f"{IP}:{direct_dns}",
        "+.trusted.lan": f"{IP}:{direct_dns}",
        "printer": f"{IP}:{direct_dns}",
        "*": "rcode://refused",
        **{"+." + name: "rcode://refused" for name in ("local", "lan", "internal", "home.arpa")},
    })
    return cfg


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
        spawn(stack, DnsUdp, host=SYSTEM_IP, port=53, protocol=Udp, answer=lambda *_: IP, events=system_queries)
        spawn(stack, DnsTcp, host=SYSTEM_IP, port=53, answer=lambda *_: IP, events=system_queries)
        direct_dns = spawn(
            stack, DnsUdp, protocol=Udp, events=plaintext,
            answer=lambda name, kind: DIRECT_IPV6 if name == "allowed.local.test" and kind == 28 else IP,
        )
        bootstrap = spawn(
            stack, DnsUdp, protocol=Udp,
            answer=lambda name, _: IP if bootstrap_ready and name == "node.entry.test" else None,
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
            ctrl, direct, routed, fakeip_port = free_ports(4)
            base = (exit_port, entry, doh, direct_dns, bootstrap, ctrl, direct, routed)
            def choose(name, **kwargs):
                if fixtures:
                    return fixture_config(fixtures, name, (ctrl, direct, routed, exit_port, entry, doh, direct_dns, bootstrap))
                cfg = config(*base, **kwargs)
                if name == "geosite":
                    cfg["dns"]["nameserver-policy"]["geosite:cn"] = f"{IP}:{direct_dns}"
                return cfg

            # A deliberately unprotected positive control is never a generated config.
            with running(core, root, config(*base, system_control=True), ctrl, cert, ready_proxy=direct):
                assert query(ctrl, "positive-control.external.test") == IP
                assert ("positive-control.external.test", 1) in system_queries, system_queries
            system_queries.clear()
            with running(core, root, choose("single"), ctrl, cert, ready_proxy=direct) as log:
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
            with running(core, root, secure, ctrl, cert, ready_proxy=direct):
                before = len(exit_calls)
                assert query(ctrl, "secure-bootstrap.external.test") == IP
                assert ("secure-bootstrap.external.test", 1) in doh_queries
                assert {name for name, _ in tls_bootstrap_queries} == {"node.entry.test"}
                assert exit_calls[before:] == [f"{IP}:{doh}"]
            with running(core, root, choose("unavailable", alias="REJECT"), ctrl, cert, ready_proxy=direct) as log:
                before, attempts = len(doh_queries), len(exit_calls)
                assert query(ctrl, "missing-egress.external.test") is None
                assert len(doh_queries) == before and len(exit_calls) == attempts
                assert "[DNS] system dns update" not in log.read_text()
            with running(core, root, choose("single"), ctrl, cert, ready_proxy=direct) as log:
                bootstrap_ready = False
                before, attempts, queries = len(doh_queries), len(exit_calls), len(bootstrap_queries)
                assert query(ctrl, "bootstrap-failed.external.test") is None
                assert len(bootstrap_queries) > queries, bootstrap_queries
                assert len(doh_queries) == before and len(exit_calls) == attempts
                assert "[DNS] system dns update" not in log.read_text()
                bootstrap_ready = True
            with running(core, root, choose("single"), ctrl, None, ready_proxy=direct) as log:
                before, attempts = len(doh_queries), len(exit_calls)
                assert query(ctrl, "tls-failed.external.test") is None
                assert len(doh_queries) == before and len(exit_calls) > attempts
                assert "certificate" in log.read_text()
            with running(core, root, choose("chain", chain=True), ctrl, cert, ready_proxy=direct) as log:
                before, last = len(entry_calls), len(exit_calls)
                assert query(ctrl, "two-hop.external.test") == IP
                assert entry_calls[before:] == [f"{IP}:{exit_port}"], entry_calls
                assert exit_calls[last:] == [f"{IP}:{doh}"], exit_calls
                entry_hop.available = False
                before, last = len(doh_queries), len(exit_calls)
                assert query(ctrl, "two-hop-failed.external.test") is None
                assert len(doh_queries) == before and len(exit_calls) == last, (doh_queries, exit_calls)
                assert "[DNS] system dns update" not in log.read_text()
            with running(core, root, choose("geosite"), ctrl, cert, ready_proxy=direct) as log:
                assert query(ctrl, "sub.fixture-cn.test") == IP
                assert ("sub.fixture-cn.test", 1) in plaintext, plaintext
                assert query(ctrl, "unlisted.cn") == IP
                assert ("unlisted.cn", 1) in doh_queries, doh_queries
                assert "[DNS] system dns update" not in log.read_text()
            exit_hop.available = True
            def fakeip(name, **kwargs):
                return fakeip_wire_config(choose(name, **kwargs), fakeip_port, direct_dns)

            pool = ipaddress.ip_network("198.18.0.0/16")
            fake_name = "fake-wire.external.test"
            with running(core, root, fakeip("fakeip"), ctrl, cert, ready_proxy=direct,
                         dns_port=fakeip_port) as log:
                before = (len(doh_queries), len(plaintext), len(bootstrap_queries))
                rcode, synthetic = dns_wire(fakeip_port, fake_name)
                assert rcode == 0 and ipaddress.ip_address(synthetic) in pool, synthetic
                assert dns_wire(fakeip_port, fake_name, tcp=True) == (0, synthetic)
                assert dns_wire(fakeip_port, fake_name, 28) == (0, None)
                for name in ("unlisted.cn", "notlocal.test", "sub.node.entry.test"):
                    rcode, address = dns_wire(fakeip_port, name)
                    assert rcode == 0 and ipaddress.ip_address(address) in pool, name
                assert (len(doh_queries), len(plaintext), len(bootstrap_queries)) == before
                target_count = len(target_calls)
                assert b" 200 " in visit_socks_fake(direct, synthetic, target)
                assert len(target_calls) == target_count + 1 and (fake_name, 1) in doh_queries
                # The DoH outbound's own dial uses the distinct bootstrap resolver.
                assert ("node.entry.test", 1) in bootstrap_queries[before[2]:]

                for name in ("allowed.local.test", "sub.fixture-cn.test", "thing.trusted.lan", "printer"):
                    assert dns_wire(fakeip_port, name) == (0, IP), name
                    assert (name, 1) in plaintext[before[1]:], plaintext
                assert dns_wire(fakeip_port, "allowed.local.test", 28, tcp=True) == (0, DIRECT_IPV6)
                assert ("allowed.local.test", 28) in plaintext[before[1]:], plaintext
                for name in ("www.msftconnecttest.com", "node.entry.test"):
                    assert dns_wire(fakeip_port, name) == (0, IP), name
                    assert (name, 1) in doh_queries, doh_queries
                before = (len(doh_queries), len(exit_calls), len(bootstrap_queries), len(plaintext))
                assert dns_wire(fakeip_port, "service.localhost") == (0, IP)
                assert dns_wire(fakeip_port, "localhost", 28) == (0, "::1")
                for name in ("router.lan", "nas", "router.home.arpa", "device.local", "private.internal"):
                    assert dns_wire(fakeip_port, name) == (5, None), name
                assert (len(doh_queries), len(exit_calls), len(bootstrap_queries), len(plaintext)) == before
                assert dns_wire(fakeip_port, "fake-txt.external.test", 16, tcp=True) == (0, None)
                assert ("fake-txt.external.test", 16) in doh_queries

                exit_hop.available = False
                before, attempts = len(doh_queries), len(exit_calls)
                # A synthetically allocated address does not prove the upstream
                # is reachable. A real lookup must fail, without DNS fallback.
                rcode, synthetic = dns_wire(fakeip_port, "fake-dead-a.external.test")
                assert rcode == 0 and ipaddress.ip_address(synthetic) in pool
                assert len(doh_queries) == before and len(exit_calls) == attempts
                assert dns_wire(fakeip_port, "fake-dead-txt.external.test", 16) == (2, None)
                assert len(doh_queries) == before and len(exit_calls) > attempts
                assert dns_wire(fakeip_port, "fake-dead.local.test") == (0, IP)
                assert ("fake-dead.local.test", 1) in plaintext
                assert "[DNS] system dns update" not in log.read_text()
                exit_hop.available = True

            with running(core, root, fakeip("fakeip-unavailable", alias="REJECT"), ctrl, cert,
                         ready_proxy=direct, dns_port=fakeip_port) as log:
                before = (len(doh_queries), len(exit_calls), len(bootstrap_queries), len(plaintext))
                assert dns_wire(fakeip_port, "fake-missing-a.external.test") == (2, None)
                assert dns_wire(fakeip_port, "fake-missing-txt.external.test", 16, tcp=True) == (2, None)
                assert (len(doh_queries), len(exit_calls), len(bootstrap_queries), len(plaintext)) == before
                assert "[DNS] system dns update" not in log.read_text()

            assert not system_queries, system_queries
            assert {name for name, _ in bootstrap_queries} == {"node.entry.test"}, bootstrap_queries
            assert {name for name, _ in plaintext} == {
                "allowed.local.test", "failure-survival.local.test", "sub.fixture-cn.test", "fake-dead.local.test",
                "thing.trusted.lan", "printer",
            }, plaintext
    source = "Routa-exported YAML" if fixtures else "independent core config"
    print(f"{PIN} ({source}): named DoH, explicit suffix and GEOSITE policy, bootstrap, "
          "direct/IP rules, two-hop, TLS failure, Fake-IP wire DNS and SOCKS mapping passed; "
          "no system or plaintext fallback observed.")


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
