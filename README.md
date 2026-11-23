# Routa

English | [简体中文](README.zh-CN.md)

A Windows desktop proxy manager built on [mihomo](https://github.com/MetaCubeX/mihomo). Choose a node and connect in Simple mode, or manage multiple proxy ports, routing rules, and network interfaces in Full mode—without writing YAML.

> Windows x64 only; the application UI is currently in Simplified Chinese.

## Features

- **Two interface modes**: Simple mode focuses on node selection and connecting; Full mode provides an overview, proxy management, process routing, subscriptions, and nodes. Switch modes in Settings while keeping existing configuration and connections.
- **Three ways to connect**: Windows system proxy, selected applications through process routing, or TUN through a virtual adapter. TUN requires running Routa as administrator.
- **Independent proxy ports**: create `mixed` (HTTP + SOCKS5), `http`, or `socks` listeners. Configure each port's node, proxy group or direct outbound, network interface, authentication, and LAN access together.
- **Network interface isolation**: when a configured outbound becomes unavailable or its bound adapter disconnects, the affected listener is disabled rather than silently switching to direct or the default adapter. It resumes when the adapter is available again.
- **Per-port routing rules**: match domains (including keywords), IPv4/IPv6 CIDR, local process name or executable path, GeoIP/GeoSite, or rule sets in order. Each rule can use the port default, a selected node/group, direct, or reject.
- **Subscriptions and nodes**: import Clash/mihomo YAML or base64 share-link subscriptions, schedule updates, and select a fallback proxy for subscription downloads. Create HTTP/SOCKS5 nodes with a form or import other mihomo node types from YAML, including batch imports. Search nodes, sort by latency, and organize custom groups.
- **Proxy groups and Tailscale**: use `url-test`, `fallback`, `load-balance`, or `select` groups; manage Tailscale nodes, login state, and exit settings.
- **Process routing**: rules send a group of programs to a Mixed/Socks listener; inspect each rule's connections and traffic. Programs match by process name (such as `ChatGPT.exe`) by default, or by full path from the advanced options; only full-path rules can block on component failure. A separate policy in Settings → 进程分流 controls behavior when Routa exits normally.
- **Monitoring and diagnostics**: view core and capture status separately, live and total traffic, active connections and their routes, core logs, port conflicts, and component status.
- **Desktop integration**: bundled mihomo core, configuration hot reload, automatic core restart after a crash, Windows startup, optional auto-connect, and a choice of minimizing to the tray or exiting when closing the window.
- **Automatic updates**: NSIS installs check for new versions, download them in the background, and install after you confirm. Process routing follows the "when Routa exits" policy throughout the upgrade.

## Install

Download `routa_<version>_x64-setup.exe` from [Releases](https://github.com/c0010c/Routa/releases) and run it. Verify downloads against `SHA256SUMS.txt` on the corresponding release. Builds bundle mihomo; the source pins its version in [`MIHOMO_VERSION`](src-tauri/binaries/MIHOMO_VERSION).

The [WebView2 runtime](https://developer.microsoft.com/microsoft-edge/webview2/) is required. Windows 11 and up-to-date Windows 10 already include it; otherwise the regular installer downloads it from Microsoft during setup. For PCs without WebView2 that cannot reach Microsoft, use `routa_<version>_x64-offline-setup.exe` instead: it is much larger because it bundles the WebView2 offline installer. Auto-updates always use the regular installer.

## Quick start

### Simple mode

1. On first launch, choose **简洁版** (Simple).
2. Import a subscription or add a node manually, then select a node.
3. Choose **系统代理** (System proxy), **指定应用** (Selected apps), or **TUN** and turn the connection on. Selected apps requires installing the process-routing component and adding applications; TUN requires restarting Routa as administrator.
4. Open Settings to change interface mode, auto-connect, startup behavior, or the close-window action.

System proxy affects applications that honor Windows proxy settings. For applications that bypass those settings, use selected-app routing or TUN as appropriate.

### Full mode

1. Add subscriptions or nodes from **订阅** (Subscriptions) or **节点** (Nodes).
2. Create a proxy on **代理** (Proxies): set its port, outbound node/group/direct connection, and optionally routing rules, network interface, authentication, or LAN access.
3. Point a client at that port, or select a default proxy on **概览 → 运行概况** (Overview → Runtime summary) and enable system proxy or TUN. System proxy requires a Mixed listener bound to local IPv4.
4. Use **进程分流** (Process routing) to assign individual applications to proxies. Inspect **概览 → 连接 / 日志** (Overview → Connections / Logs) when troubleshooting.

Stopping system proxy or TUN leaves the core and proxy ports available; manually configured clients and independently enabled process-routing rules may still use them.

### Ordered proxy chains

Under **节点 → 新增 → 新增代理链** (Nodes → Add → Add Proxy Chain), choose 2–8 ordinary nodes in dialing order. Add, remove or move hops and check the route preview: the first node is the entry and the last is the exit. Existing two-hop chains keep their order and ID. Select the saved chain as a single fixed port outbound or a specific rule target. Measure its end-to-end delay in Nodes. If the original subscription node can no longer be resolved, repair the hop manually; Routa does not choose another node.

Two-hop-only profiles remain readable in the prior two-hop preview. Do not open a profile containing a longer chain with that preview. Before first saving a longer chain over an existing compatible profile, Routa keeps its exact previous `state.json` as `state.before-multihop.json`. To roll back, close Routa, keep a copy of your current state file, then copy the backup over `state.json`; later changes are not part of that snapshot.

The first version supports TCP with eligible HTTP, SOCKS5, Shadowsocks without plugins, VMess, VLESS, and Trojan nodes. UDP, nested chains, Tailscale, and using chains as strategy-group members are not supported. A connection timeout never falls back to Direct. Only an explicit Direct rule, or an explicitly configured Direct policy for a rule whose target can no longer be resolved, uses that route.

### DNS diversion (off by default)

Under **设置 → 网络与内核 → DNS 分流**, choose a fixed supported TCP node or ordered chain. The core sends unclassified target lookups through that exit to your trusted HTTPS resolver. Fresh queries fail when the exit, its bound interface, any hop, the resolver, or certificate verification fails: there is no automatic system or plaintext DNS fallback. Cached answers do not require a fresh query.

- Explicit domain suffixes and optional `GEOSITE:cn` use the separate direct DNS upstream. GeoSite needs local data (first use may download it). A traffic-routing `GEOIP,CN` decision needs an IP and cannot classify a DNS query before the answer.
- The core bootstraps locally resolved proxy-server names via an independent, directly reachable resolver. Later chain hops may resolve on the preceding proxy instead. Direct DNS and bootstrap use the default network path, not each traffic port's bound adapter.
- Use literal-IP HTTPS endpoints, with certificates trusted for that IP. The direct and bootstrap roles also accept explicit UDP IP addresses/ports, which disclose their respective queries in plaintext. Trust the configured DoH operator, including its replies and redirects.

This is **one resolver policy per core**, including fixed-direct ports, IP-based routing lookups, and auxiliary traffic when it actually uses the core. It does not change a port's traffic exit. In ordinary proxy mode, DNS stays on real addresses (`redir-host`). HTTP proxies and domain-forwarding SOCKS5 clients usually hand the host name straight to the proxy and do not need a synthetic address. No DNS listener is opened.

**Optional: TUN 使用 DNS 分流（Fake-IP）.** Saving this option never starts TUN. If you separately enter TUN, its existing DNS capture uses the policy above. Otherwise TUN retains its legacy Fake-IP/DNS settings. Neither the traffic exit, per-port routing nor WebRTC is changed by this option.

- For ordinary DNS captured by TUN, an unfiltered A query gets a synthetic IPv4 address in `198.18.0.0/16`. Its connection must return to the same core to recover the name. Synthetic AAAA and HTTPS/SVCB answers are empty (no synthetic IPv6); exceptions can receive real A/AAAA answers.
- Direct suffixes and optional `GEOSITE:cn` get real answers from direct DNS. Windows connectivity probes and the configured DNS/TUN exits’ physical server names are not synthesized. An application looking up such a server still follows the normal DNS policy, not an extra direct route. The core's own node bootstrap is separate.
- Localhost and its subdomains resolve to loopback. Single-label names and `.local`, `.lan`, `.internal`, and `.home.arpa` are refused rather than disclosed upstream unless explicitly allowed. For a NAS on `home.arpa`, add that suffix and set **直连 DNS** to a trusted LAN resolver (also used for other direct exceptions). Multicast mDNS is separate.
- A synthetic answer is not a connectivity test: a route known to be missing suppresses synthesis; a configured but unreachable proxy can still yield a fake IP. When real resolution is needed, it does not fall back to system DNS. A material change can restart the core, interrupt capture/connections and discard mappings; do not pin synthetic addresses, since an old address can be reassigned; resolve the name again. This is not an OS kill switch: app/browser DoH, remote resolution and queries outside active TUN capture (including restart gaps) are not protected by this profile.


## Shared routing rules

In Full mode, open **共享规则** (Shared rules) to edit, reorder, and toggle common rules or add the mainland-China direct preset. To use a remote mihomo rule set, register it first and then reference it from a `RULE-SET` rule. Routa fetches these sources directly, independently of proxy ports; prefer trusted HTTPS sources.

Opt in separately for each listener in **代理** (Proxies). Routa checks **per-port rules → enabled shared rules → the port's existing fallback**, in that order. A Proxy action still uses the listener's own outbound. Existing listeners do not opt in automatically. Process-routing settings do not need to change.

Explicit node or group targets remain bound to the port's chosen network interface. Groups try their members in order using mihomo fallback. If a target is missing or unusable in the current configuration, its rule rejects traffic by default, or goes directly through the same interface if you select that explicitly. This does not retry failed live connections on a direct route. If the selected node cannot carry UDP, that traffic is blocked rather than falling through to the port default. These new rule types and explicit targets apply to the proxy port, not to its ancillary TUN or subscription-refresh paths.

Process matchers use Windows information for connections made by local applications to the port. They cannot identify the executable on another device or behind another proxy; keep using **进程分流** (Process routing) for apps that need to be captured automatically. Process and live data matches require actual traffic; the offline rule preview cannot verify them.

## Process-routing component

Process routing runs as the `RoutaProcSvc` Windows service, built on [ProxyBridge](https://github.com/InterceptSuite/ProxyBridge) and [WinDivert](https://github.com/basil00/WinDivert). The installer registers it with a UAC prompt; if you decline, enable it later in the app.

Uninstalling removes the service as well. If that fails, run this in an administrator PowerShell, then delete the `%ProgramFiles%\Routa\ProcessRouting` folder:

```powershell
& "$env:ProgramFiles\Routa\ProcessRouting\routa-procsvc.exe" --uninstall
```

Notes:

- Targets must be Mixed/Socks listeners on IPv4 (such as `127.0.0.1`); HTTP-only and IPv6 listeners are unsupported.
- Rules apply to the program for every Windows user on the computer. DNS queries made by the Windows DNS Client service are not routed.
- Block rules persist after crashes and restarts, so blocked programs stay offline until the component is running; direct-on-failure rules may connect directly before the service starts.
- Antivirus software may quarantine WinDivert. Check it first if routing fails.

## Build from source

Use Node.js 24 and pnpm 10 to match CI, plus the Rust toolchain and [Tauri 2 Windows prerequisites](https://tauri.app/start/prerequisites/) (MSVC build tools and WebView2).

Prepare dependencies and bundled components:

```powershell
pnpm install --frozen-lockfile
pnpm fetch-mihomo       # Download and verify the pinned core
pnpm fetch-windivert    # Download the WinDivert files
pnpm build-proxybridge  # Build ProxyBridgeCore.dll with MSVC
pnpm build-procsvc      # Build the process-routing service
```

Run or package the application:

```powershell
pnpm tauri dev        # Development mode
pnpm tauri build      # NSIS installer in src-tauri/target/release/bundle
```

`pnpm tauri build` rebuilds the service and frontend automatically.

Before a direct `cargo build --release --features custom-protocol`, run `node scripts/build-procsvc.mjs` and `node scripts/build-frontend.mjs`.

### Checks

```powershell
pnpm typecheck
pnpm test
pnpm build
node --test scripts/build-artifacts.test.mjs scripts/updater-manifest.test.mjs
cargo test --locked --manifest-path src-tauri/Cargo.toml --workspace
```

Some Rust tests are ignored by default because they need administrator rights or a real core. To run the real-core integration test:

```powershell
$env:MIHOMO_BIN = (Resolve-Path src-tauri/binaries/mihomo-x86_64-pc-windows-msvc.exe).Path
$env:NO_PROXY = ''
cargo test --locked --manifest-path src-tauri/Cargo.toml --test e2e_real_core -- --ignored --nocapture
```

Stack: Tauri 2 (Rust and tokio), React, TypeScript, Vite, and MUI. Frontend/backend bindings are generated with tauri-specta.

## License

[MIT](LICENSE). Third-party components retain their respective licenses; see [ProxyBridge's license](third_party/proxybridge/LICENSE) and [upstream notes](third_party/proxybridge/UPSTREAM.md).
