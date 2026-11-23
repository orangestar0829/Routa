//! End-to-end test against the real mihomo binary.
//!
//! Run: MIHOMO_BIN=<path to mihomo exe> cargo test --test e2e_real_core -- --ignored --nocapture

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv6Addr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use routa_lib::core::api::{HttpMihomoApi, MihomoApi};
use routa_lib::core::ports::WindowsPortOwners;
use routa_lib::core::process::{CoreLauncher, CoreState, ProcessLauncher};
use routa_lib::model::{
    Exit, ExitId, ExitKind, ExitMember, Listener, ListenerRouting, ManualNode, ManualNodeId,
    ManualNodeKind, Model, NodeRef, PortRule, RuleAction, RuleMatch, RuleProviderBehavior,
    RuleProviderFormat, RuleUnavailable, Settings, SharedRule, SharedRuleProvider,
};
use routa_lib::netif::WindowsInterfaces;
use routa_lib::runtime::{ApiFor, LauncherFor, Runtime};
use routa_lib::store::Store;
use tokio::sync::mpsc;

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn refuses(port: u16) -> bool {
    TcpStream::connect_timeout(&format!("127.0.0.1:{port}").parse().unwrap(), Duration::from_secs(2)).is_err()
}

/// Tiny HTTP server: answers every request with 204 after `delay`.
fn spawn_target(delay: Duration) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = s;
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf);
                std::thread::sleep(delay);
                let _ = s.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
            });
        }
    });
    port
}

/// A fake HTTP upstream proxy for routing assertions. It accepts CONNECT
/// and responds to the tunneled GET with a distinct code, never sends it out.
fn spawn_tagged_http_proxy(status: &'static str) -> u16 {
    fn read_headers(stream: &mut BufReader<&mut TcpStream>, method: &str) -> bool {
        let mut line = String::new();
        if stream.read_line(&mut line).unwrap_or(0) == 0 || !line.starts_with(method) {
            return false;
        }
        loop {
            line.clear();
            if stream.read_line(&mut line).unwrap_or(0) == 0 {
                return false;
            }
            if line == "\r\n" {
                return true;
            }
        }
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut socket in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let _ = socket.set_read_timeout(Some(Duration::from_secs(3)));
                let mut stream = BufReader::new(&mut socket);
                if read_headers(&mut stream, "CONNECT ")
                    && stream.get_mut().write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").is_ok()
                    && read_headers(&mut stream, "GET ")
                {
                    let response = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    let _ = stream.get_mut().write_all(response.as_bytes());
                }
            });
        }
    });
    port
}

fn spawn_rule_provider() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let body = b"payload:\n  - '127.0.0.1/32'\n";
        for mut socket in listener.incoming().flatten() {
            let mut buf = [0u8; 4096];
            let _ = socket.set_read_timeout(Some(Duration::from_secs(2)));
            if socket.read(&mut buf).unwrap_or(0) == 0 {
                continue;
            }
            let headers = format!("HTTP/1.1 200 OK\r\nContent-Type: text/yaml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
            let _ = socket.write_all(headers.as_bytes());
            let _ = socket.write_all(body);
        }
    });
    port
}

async fn wait_for_one_rule(ctrl: u16, secret: &str, name: &str) {
    let http = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(2)).build().unwrap();
    let url = format!("http://127.0.0.1:{ctrl}/providers/rules");
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut last = String::new();
    while Instant::now() < deadline {
        match http.get(&url).bearer_auth(secret).send().await {
            Ok(response) => match response.error_for_status() {
                Ok(response) => match response.json::<serde_json::Value>().await {
                    Ok(data) => {
                        let count = data["providers"][name]["ruleCount"].as_u64();
                        if count == Some(1) {
                            return;
                        }
                        last = format!("{name} ruleCount={count:?}");
                    }
                    Err(error) => last = error.to_string(),
                },
                Err(error) => last = error.to_string(),
            },
            Err(error) => last = error.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("real HTTP rule provider did not initialize: {last}");
}

fn curl_status(proxy_port: u16, url: &str) -> String {
    curl_status_from(Path::new("curl.exe"), proxy_port, url)
}

fn curl_status_from(program: &Path, proxy_port: u16, url: &str) -> String {
    let out = Command::new(program)
        .args(["-sS", "-o", "NUL", "-w", "%{http_code}", "-m", "15", "--noproxy", "", "-x"])
        .arg(format!("http://127.0.0.1:{proxy_port}"))
        .arg(url)
        .output()
        .expect("curl.exe");
    if !out.status.success() {
        eprintln!(
            "{} through port {proxy_port} to {url}: exit {:?}; {}",
            program.display(), out.status.code(), String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Exercise the real proxy with a protocol-level IPv6 destination, avoiding
/// platform-specific URL parsing in curl while keeping the underlying fixture
/// entirely on IPv4 loopback (the tagged upstream handles the destination).
fn socks_ipv6_status(proxy_port: u16, destination: Ipv6Addr) -> io::Result<String> {
    let mut tcp = TcpStream::connect(("127.0.0.1", proxy_port))?;
    tcp.set_read_timeout(Some(Duration::from_secs(5)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(5)))?;
    tcp.write_all(&[5, 1, 0])?;
    let mut greeting = [0u8; 2];
    tcp.read_exact(&mut greeting)?;
    if greeting != [5, 0] {
        return Err(io::Error::other(format!("SOCKS5 no-auth greeting rejected: {greeting:?}")));
    }

    let mut request = vec![5, 1, 0, 4]; // v5, CONNECT, reserved, ATYP IPv6
    request.extend_from_slice(&destination.octets());
    request.extend_from_slice(&80_u16.to_be_bytes());
    tcp.write_all(&request)?;
    let mut reply = [0u8; 4];
    tcp.read_exact(&mut reply)?;
    if reply[..3] != [5, 0, 0] {
        return Err(io::Error::other(format!("SOCKS5 CONNECT to [{destination}]:80 failed: {reply:?}")));
    }
    let len = match reply[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut len = [0u8; 1];
            tcp.read_exact(&mut len)?;
            usize::from(len[0])
        }
        atyp => return Err(io::Error::other(format!("unexpected SOCKS5 reply ATYP {atyp}"))),
    };
    tcp.read_exact(&mut vec![0u8; len + 2])?; // BND.ADDR and BND.PORT
    write!(tcp, "GET / HTTP/1.1\r\nHost: [{destination}]\r\nConnection: close\r\n\r\n")?;
    let mut status_line = String::new();
    BufReader::new(tcp).read_line(&mut status_line)?;
    let mut fields = status_line.split_ascii_whitespace();
    if !fields.next().is_some_and(|version| version.starts_with("HTTP/1.")) {
        return Err(io::Error::other(format!("invalid tagged HTTP response: {status_line:?}")));
    }
    fields.next().map(str::to_owned)
        .ok_or_else(|| io::Error::other(format!("missing HTTP status: {status_line:?}")))
}

fn test_http_node(name: &str, port: u16) -> ManualNode {
    ManualNode {
        id: ManualNodeId::new(),
        name: name.to_owned(),
        groups: vec![],
        kind: ManualNodeKind::Proxy { raw: serde_json::json!({
            "name": name, "type": "http", "server": "127.0.0.1", "port": port,
        }) },
    }
}
fn use_node(node: &ManualNode) -> RuleAction {
    RuleAction::Target {
        target: ExitMember::Node(NodeRef::Manual { manual_id: node.id.clone() }),
        unavailable: RuleUnavailable::Reject,
    }
}

fn ps_count(marker: &str) -> usize {
    // Matches only mihomo processes whose command line mentions our temp workdir.
    let action = "Measure-Object | ForEach-Object { $_.Count }";
    let out = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "Get-CimInstance Win32_Process | Where-Object {{ $_.CommandLine -like '*{}*' -and $_.Name -like '*mihomo*' }} | {}",
                marker.replace('\'', ""),
                action
            ),
        ])
        .output()
        .expect("powershell");
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    text.parse::<usize>().unwrap_or_else(|_| {
        panic!("could not parse process count {text:?}; stderr: {}", String::from_utf8_lossy(&out.stderr))
    })
}

fn mihomo_running(marker: &str) -> bool {
    ps_count(marker) > 0
}

/// Kills the test's own mihomo (matched by temp-dir marker) even when an
/// assertion fails before `shutdown` runs.
struct KillOnDrop(String);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "Get-CimInstance Win32_Process | Where-Object {{ $_.CommandLine -like '*{}*' -and $_.Name -like '*mihomo*' }} | ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force }}",
                    self.0.replace('\'', "")
                ),
            ])
            .output();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn real_core_two_listeners_direct_exit() {
    let bin = PathBuf::from(std::env::var("MIHOMO_BIN").expect("set MIHOMO_BIN"));
    assert!(bin.exists(), "MIHOMO_BIN not found: {bin:?}");

    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path().to_path_buf()).unwrap();
    let workdir = store.core_workdir();
    let marker = tmp.path().file_name().unwrap().to_string_lossy().to_string();
    let _guard = KillOnDrop(marker.clone());

    // Model: one Direct exit, two listeners, free ports (controller included).
    let (p1, p2, ctrl) = (free_port(), free_port(), free_port());
    let exit = Exit { id: ExitId::new(), name: "直连".into(), kind: ExitKind::Direct, interface: None, hidden: false };
    let mut l1 = Listener::new_default("监听一".into(), p1);
    l1.exit = Some(exit.id.clone());
    let l1_id = l1.id.clone();
    let mut l2 = Listener::new_default("监听二".into(), p2);
    l2.exit = Some(exit.id.clone());
    let l2_id = l2.id.clone();
    let model = Model {
        subscriptions: vec![],
        exits: vec![exit],
        listeners: vec![l1, l2],
        settings: Settings { controller_port: ctrl, ..Settings::default() },
        ..Model::default()
    };
    store.save_model(&model).unwrap();

    let wd = workdir.clone();
    let launcher_for: LauncherFor = Arc::new(move |_s: &Settings| {
        Arc::new(ProcessLauncher { bin: bin.clone(), workdir: wd.clone() }) as Arc<dyn CoreLauncher>
    });
    // Capture the per-run secret so the test can talk to /connections itself.
    let api_slot: Arc<Mutex<Option<Arc<HttpMihomoApi>>>> = Arc::new(Mutex::new(None));
    let slot = api_slot.clone();
    let secret_slot = Arc::new(Mutex::new(String::new()));
    let shared_secret = secret_slot.clone();
    let api_for: ApiFor = Box::new(move |port, secret| {
        *secret_slot.lock().unwrap() = secret.clone();
        let api = Arc::new(HttpMihomoApi::new(port, secret));
        *slot.lock().unwrap() = Some(api.clone());
        api as Arc<dyn MihomoApi>
    });
    let (tx, mut rx) = mpsc::channel(1024);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let rt = Arc::new(Runtime::new(
        store,
        Arc::new(WindowsInterfaces),
        launcher_for,
        api_for,
        Arc::new(WindowsPortOwners),
        tx,
    ));
    rt.start().await.expect("runtime start");
    assert_eq!(rt.status().core, CoreState::Running);
    assert!(mihomo_running(&marker), "mihomo should be running");
    let api = api_slot.lock().unwrap().clone().expect("api created");

    // Both listeners must come up (no failed listeners reported).
    assert!(rt.status().failed_listeners.is_empty(), "{:?}", rt.status().failed_listeners);

    // 1. Traffic through listener 1: real internet if reachable, else local target.
    let real = tokio::task::spawn_blocking(move || curl_status(p1, "https://www.gstatic.com/generate_204"))
        .await
        .unwrap();
    if real == "204" {
        println!("gstatic via listener 1 -> 204 (real internet)");
    } else {
        println!("gstatic unreachable (curl status {real:?}); falling back to a local HTTP target");
        let t = spawn_target(Duration::ZERO);
        let code = tokio::task::spawn_blocking(move || curl_status(p1, &format!("http://127.0.0.1:{t}/")))
            .await
            .unwrap();
        assert_eq!(code, "204", "local target via listener 1");
    }
    // Listener 2 works too.
    let t = spawn_target(Duration::ZERO);
    let code = tokio::task::spawn_blocking(move || curl_status(p2, &format!("http://127.0.0.1:{t}/")))
        .await
        .unwrap();
    assert_eq!(code, "204", "local target via listener 2");

    // 2. /connections during a slow request shows inboundName == listener name.
    let slow = spawn_target(Duration::from_secs(4));
    let h = tokio::task::spawn_blocking(move || curl_status(p1, &format!("http://127.0.0.1:{slow}/")));
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut seen = false;
    while Instant::now() < deadline && !seen {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let snap = api.connections().await.expect("connections");
        seen = snap.connections.iter().any(|c| c.metadata.inbound_name == "监听一");
    }
    assert!(seen, "no connection with inboundName 监听一 seen");
    println!("/connections showed inboundName=监听一");
    assert_eq!(h.await.unwrap(), "204");

    // An opt-in shared rule changes only listener 1. Its local exception
    // must then take precedence over the shared rule.
    rt.mutate(|m| {
        m.shared_rules = vec![SharedRule {
            enabled: true,
            matcher: RuleMatch::Ipv4Cidr,
            value: "127.0.0.1/32".into(),
            action: RuleAction::Reject,
        }];
        m.listeners.iter_mut().find(|l| l.id == l1_id).unwrap().inherit_shared_rules = true;
    })
    .await
    .expect("apply shared routing");
    assert!(rt.status().failed_listeners.is_empty(), "{:?}", rt.status().failed_listeners);
    assert!(!refuses(p1), "inheriting listener must stay open");
    let url = format!("http://127.0.0.1:{t}/");
    let probe = url.clone();
    let (first, second) = tokio::task::spawn_blocking(move || {
        (curl_status(p1, &probe), curl_status(p2, &probe))
    })
    .await
    .unwrap();
    assert_ne!(first, "204", "shared reject must apply to its inheriting listener");
    assert_eq!(second, "204", "non-inheriting listener must remain unchanged");

    rt.mutate(|m| {
        m.listeners.iter_mut().find(|l| l.id == l1_id).unwrap().routing = Some(ListenerRouting {
            rules: vec![PortRule {
                matcher: RuleMatch::Ipv4Cidr,
                value: "127.0.0.1/32".into(),
                action: RuleAction::Direct,
            }],
            unmatched: RuleAction::Proxy,
        });
    })
    .await
    .expect("apply local exception");
    let probe = url.clone();
    let code = tokio::task::spawn_blocking(move || curl_status(p1, &probe)).await.unwrap();
    assert_eq!(code, "204", "local exception must override the shared reject");

    // Serve a real YAML rule provider locally, so the RuleSet test does not
    // depend on the runner's access to a third-party rules site.
    let rules_port = spawn_rule_provider();
    rt.mutate(|m| {
        m.shared_rules = vec![SharedRule {
            enabled: true,
            matcher: RuleMatch::RuleSet,
            value: "loopback-fixture".into(),
            action: RuleAction::Reject,
        }];
        m.shared_rule_providers = vec![SharedRuleProvider {
            name: "loopback-fixture".into(),
            url: format!("http://127.0.0.1:{rules_port}/rules.yaml"),
            behavior: RuleProviderBehavior::IpCidr,
            format: RuleProviderFormat::Yaml,
            interval: 3600,
        }];
        m.listeners.iter_mut().find(|l| l.id == l1_id).unwrap().routing = None;
    })
    .await
    .expect("apply remote ruleset");
    assert!(rt.status().failed_listeners.is_empty(), "{:?}", rt.status().failed_listeners);
    assert!(!refuses(p1), "ruleset listener must stay open");
    let secret = shared_secret.lock().unwrap().clone();
    wait_for_one_rule(ctrl, &secret, "loopback-fixture").await;
    let (first, second) = tokio::task::spawn_blocking(move || {
        (curl_status(p1, &url), curl_status(p2, &url))
    })
    .await
    .unwrap();
    assert_ne!(first, "204", "the real provider must block through listener 1");
    assert_eq!(second, "204", "the rule provider must not affect listener 2");

    // Local process discovery + explicit destination, on the same inbound.
    // Two copies of Windows curl allow us to prove name and exact path matches
    // rather than accidentally accepting the listener's default destination.
    let curl = PathBuf::from(std::env::var_os("SystemRoot").expect("Windows SystemRoot"))
        .join("System32").join("curl.exe");
    assert!(curl.is_file(), "Windows curl.exe missing: {curl:?}");
    let named = tmp.path().join("routa-name-probe.exe");
    let by_path = tmp.path().join("routa-path-probe.exe");
    std::fs::copy(&curl, &named).expect("copy name fixture");
    std::fs::copy(&curl, &by_path).expect("copy path fixture");
    let path_value = by_path.to_string_lossy().into_owned();
    let one = test_http_node("process name tagged node", spawn_tagged_http_proxy("201 Created"));
    let two = test_http_node("process path tagged node", spawn_tagged_http_proxy("202 Accepted"));
    let named_action = use_node(&one);
    let path_action = use_node(&two);
    rt.mutate(move |m| {
        m.manual_nodes.extend([one, two]);
        m.shared_rules = vec![
            SharedRule {
                enabled: true, matcher: RuleMatch::ProcessName, value: "routa-name-probe.exe".into(),
                action: named_action.clone(),
            },
            SharedRule {
                enabled: true, matcher: RuleMatch::DomainKeyword, value: "routa-keyword".into(),
                action: named_action.clone(),
            },
            SharedRule {
                enabled: true, matcher: RuleMatch::Ipv6Cidr, value: "2001:db8:1::/48".into(),
                action: path_action.clone(),
            },
            SharedRule {
                enabled: true, matcher: RuleMatch::Ipv6Cidr, value: "2001:db8::/32".into(),
                action: named_action,
            },
        ];
        m.listeners.iter_mut().find(|l| l.id == l1_id).unwrap().routing = Some(ListenerRouting {
            rules: vec![PortRule {
                matcher: RuleMatch::ProcessPath, value: path_value, action: path_action,
            }],
            unmatched: RuleAction::Proxy,
        });
    }).await.expect("apply extended matchers and explicit rule destinations");
    assert!(rt.status().failed_listeners.is_empty(), "{:?}", rt.status().failed_listeners);
    let test_url = format!("http://127.0.0.1:{t}/");
    let codes = tokio::task::spawn_blocking(move || [
        curl_status_from(&named, p1, &test_url),
        curl_status_from(&by_path, p1, &test_url),
        curl_status_from(&named, p2, &test_url),
        curl_status(p1, &test_url),
        curl_status(p1, "http://api-routa-keyword.example.invalid/"),
    ]).await.unwrap();
    assert_eq!(codes, ["201", "202", "204", "204", "201"],
        "name, path, isolated port, default, and keyword must take the expected destinations");
    let (ipv6_inside, ipv6_outside) = tokio::task::spawn_blocking(move || {
        let probe = |address: &str| {
            socks_ipv6_status(p1, address.parse().unwrap())
                .unwrap_or_else(|error| panic!("IPv6 SOCKS5 probe to [{address}] via {p1}: {error}"))
        };
        (probe("2001:db8:1::1"), probe("2001:db8:2::1"))
    }).await.unwrap();
    assert_eq!(ipv6_inside, "202", "narrow /48 must take its explicit target");
    assert_eq!(ipv6_outside, "201", "neighboring IPv6 /48 must only match the broader /32 target");

    // 3. Disable listener 2 -> its port refuses connections; listener 1 still works.
    assert!(!refuses(p2));
    rt.mutate(|m| {
        m.listeners.iter_mut().find(|l| l.id == l2_id).unwrap().user_enabled = false;
    })
    .await
    .expect("mutate");
    assert!(refuses(p2), "disabled listener port should refuse connections");
    assert!(!refuses(p1));
    println!("listener 2 disabled -> port {p2} refuses connections");

    // 4. Shutdown -> mihomo process gone, listener 1 closed.
    rt.shutdown().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!mihomo_running(&marker), "mihomo should be gone after shutdown");
    assert!(refuses(p1));
    println!("shutdown -> mihomo process gone");
}

/// A loopback-only CONNECT hop: log the requested authority, forward only to
/// the expected next socket, and allow tests to make the entry unavailable.
fn spawn_chain_hop(
    hop: &'static str,
    connector: TcpListener,
    next_port: u16,
    trace: Arc<Mutex<Vec<(&'static str, String)>>>,
    available: Arc<std::sync::atomic::AtomicBool>,
) -> u16 {
    use std::net::Shutdown;
    use std::sync::atomic::Ordering;

    let port = connector.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut inbound in connector.incoming().flatten() {
            let trace = trace.clone();
            let available = available.clone();
            std::thread::spawn(move || {
                let _ = inbound.set_read_timeout(Some(Duration::from_secs(10)));
                let mut header = Vec::new();
                for byte in (&mut inbound).bytes().take(8192) {
                    let Ok(byte) = byte else { return };
                    header.push(byte);
                    if header.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let text = String::from_utf8_lossy(&header);
                let mut parts = text.lines().next().unwrap_or_default().split_whitespace();
                if parts.next() != Some("CONNECT") {
                    return;
                }
                let authority = parts.next().unwrap_or_default();
                trace.lock().unwrap().push((hop, authority.to_owned()));
                if !available.load(Ordering::SeqCst) || authority != format!("127.0.0.1:{next_port}") {
                    let _ = inbound.write_all(
                        b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n",
                    );
                    return;
                }
                let Ok(mut outbound) = TcpStream::connect(("127.0.0.1", next_port)) else { return };
                let _ = outbound.set_read_timeout(Some(Duration::from_secs(10)));
                if inbound.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").is_err() {
                    return;
                }
                let (Ok(mut client), Ok(mut server)) = (inbound.try_clone(), outbound.try_clone()) else { return };
                std::thread::spawn(move || {
                    let _ = std::io::copy(&mut client, &mut server);
                    let _ = server.shutdown(Shutdown::Write);
                });
                let _ = std::io::copy(&mut outbound, &mut inbound);
                let _ = inbound.shutdown(Shutdown::Write);
            });
        }
    });
    port
}

/// Absolute-form HTTP, avoiding curl's ambient proxy and NO_PROXY variables.
fn local_http_proxy_status(proxy_port: u16, target_port: u16) -> Option<u16> {
    use std::io::{BufRead, BufReader};

    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(8))).ok()?;
    let target = format!("127.0.0.1:{target_port}");
    write!(stream, "GET http://{target}/ HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n").ok()?;
    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response).ok()?;
    response.split_whitespace().nth(1)?.parse().ok()
}

fn spawn_udp_echo() -> (u16, Arc<Mutex<Vec<Vec<u8>>>>) {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    let packets = Arc::new(Mutex::new(Vec::new()));
    let observed = packets.clone();
    std::thread::spawn(move || {
        let mut buf = [0; 64];
        while let Ok((len, sender)) = socket.recv_from(&mut buf) {
            observed.lock().unwrap().push(buf[..len].to_vec());
            let _ = socket.send_to(&buf[..len], sender);
        }
    });
    (port, packets)
}

/// The port's SOCKS listener still admits UDP association, so the rule and
/// its Direct fallback, rather than a blanket inbound guard, are exercised.
fn local_socks_udp_echo(proxy_port: u16, echo_port: u16, payload: &[u8]) -> bool {
    use std::io::ErrorKind;
    use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};

    let mut control = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    control.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    control.write_all(&[5, 1, 0]).unwrap();
    let mut method = [0; 2];
    control.read_exact(&mut method).unwrap();
    assert_eq!(method, [5, 0], "SOCKS server must allow unauthenticated testing");

    let [local_high, local_low] = udp.local_addr().unwrap().port().to_be_bytes();
    control.write_all(&[5, 3, 0, 1, 127, 0, 0, 1, local_high, local_low]).unwrap();
    let mut relay = [0; 10];
    control.read_exact(&mut relay).unwrap();
    assert_eq!(relay[..4], [5, 0, 0, 1], "expected a local IPv4 UDP relay");
    let ip = Ipv4Addr::new(relay[4], relay[5], relay[6], relay[7]);
    let relay_port = u16::from_be_bytes([relay[8], relay[9]]);
    udp.connect(SocketAddrV4::new(if ip.is_unspecified() { Ipv4Addr::LOCALHOST } else { ip }, relay_port)).unwrap();
    let [high, low] = echo_port.to_be_bytes();
    let mut packet = vec![0, 0, 0, 1, 127, 0, 0, 1, high, low];
    packet.extend_from_slice(payload);
    udp.send(&packet).unwrap();

    let mut reply = [0; 64];
    match udp.recv(&mut reply) {
        Ok(len) => {
            assert_eq!(&reply[..len], packet.as_slice(), "incorrect SOCKS UDP echo");
            true
        }
        Err(err) if matches!(err.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => false,
        Err(err) => panic!("wait for UDP relay: {err}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn real_core_chained_proxy_visits_two_hops_in_order_and_never_bypasses() {
    use routa_lib::model::{ExitMember, ManualNode, ManualNodeId, ManualNodeKind, NodeRef, RuleUnavailable};
    use std::sync::atomic::{AtomicBool, Ordering};

    let bin = PathBuf::from(std::env::var("MIHOMO_BIN").expect("set MIHOMO_BIN"));
    assert!(bin.exists(), "MIHOMO_BIN not found: {bin:?}");
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path().to_path_buf()).unwrap();
    let workdir = store.core_workdir();
    let _guard = KillOnDrop(tmp.path().file_name().unwrap().to_string_lossy().into_owned());

    let target = spawn_target(Duration::ZERO);
    // Reserve the sockets together so parallel real-core tests can't pick the
    // same port twice during setup. Release the core's sockets right at start.
    let reserve = || TcpListener::bind("127.0.0.1:0").unwrap();
    let (entry_socket, exit_socket, routed_socket, control_socket, ctrl_socket) =
        (reserve(), reserve(), reserve(), reserve(), reserve());
    let (routed_port, control_port, ctrl) = (
        routed_socket.local_addr().unwrap().port(),
        control_socket.local_addr().unwrap().port(),
        ctrl_socket.local_addr().unwrap().port(),
    );
    let trace = Arc::new(Mutex::new(Vec::new()));
    let entry_available = Arc::new(AtomicBool::new(true));
    let exit_port = spawn_chain_hop(
        "exit", exit_socket, target, trace.clone(), Arc::new(AtomicBool::new(true)),
    );
    let entry_port = spawn_chain_hop(
        "entry", entry_socket, exit_port, trace.clone(), entry_available.clone(),
    );
    let http_node = |name: &str, port| ManualNode {
        id: ManualNodeId::new(),
        name: name.into(),
        groups: vec![],
        kind: ManualNodeKind::Proxy {
            raw: serde_json::json!({
                "name": name, "type": "http", "server": "127.0.0.1", "port": port,
            }),
        },
    };
    let entry = http_node("first hop", entry_port);
    let exit = http_node("last hop", exit_port);
    let chain = ManualNode {
        id: ManualNodeId::new(),
        name: "two hop chain".into(),
        groups: vec![],
        kind: ManualNodeKind::Chain {
            entry: NodeRef::Manual { manual_id: entry.id.clone() },
            exit: NodeRef::Manual { manual_id: exit.id.clone() },
        },
    };
    let control = Exit {
        id: ExitId::new(),
        name: "loopback control".into(),
        kind: ExitKind::Direct,
        interface: None,
        hidden: false,
    };
    let listener = |name: &str, port, exit_id: ExitId| {
        let mut listener = Listener::new_default(name.into(), port);
        listener.listen = "127.0.0.1".into();
        listener.exit = Some(exit_id);
        listener
    };
    // Explicit "Direct" after the matching route makes accidental fallthrough
    // observable: the same destination below replies to unproxied traffic.
    let mut routed_listener = listener("chain port", routed_port, control.id.clone());
    routed_listener.routing = Some(ListenerRouting {
        rules: vec![PortRule {
            matcher: RuleMatch::Ipv4Cidr,
            value: "127.0.0.1/32".into(),
            action: RuleAction::Target {
                target: ExitMember::Node(NodeRef::Manual { manual_id: chain.id.clone() }),
                // Even an explicitly selected, configuration-only fallback
                // must not reroute live UDP or a failed TCP connection.
                unavailable: RuleUnavailable::Direct,
            },
        }],
        unmatched: RuleAction::Direct,
    });
    let model = Model {
        exits: vec![control.clone()],
        listeners: vec![routed_listener, listener("control port", control_port, control.id)],
        manual_nodes: vec![entry, exit, chain],
        settings: Settings { controller_port: ctrl, ..Settings::default() },
        ..Model::default()
    };
    store.save_model(&model).unwrap();

    let launcher_for: LauncherFor = Arc::new(move |_s: &Settings| {
        Arc::new(ProcessLauncher { bin: bin.clone(), workdir: workdir.clone() }) as Arc<dyn CoreLauncher>
    });
    let api_for: ApiFor = Box::new(|port, secret| Arc::new(HttpMihomoApi::new(port, secret)));
    let (tx, mut rx) = mpsc::channel(1024);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let rt = Runtime::new(
        store, Arc::new(WindowsInterfaces), launcher_for, api_for, Arc::new(WindowsPortOwners), tx,
    );
    drop((routed_socket, control_socket, ctrl_socket));
    rt.start().await.expect("start real core with chain");
    assert_eq!(rt.status().core, CoreState::Running);
    assert!(rt.status().failed_listeners.is_empty(), "{:?}", rt.status().failed_listeners);
    let probe = |port| tokio::task::spawn_blocking(move || local_http_proxy_status(port, target));

    assert_eq!(probe(control_port).await.unwrap(), Some(204), "target must really be reachable");
    assert!(trace.lock().unwrap().is_empty(), "control must not hit either chain hop");
    assert_eq!(probe(routed_port).await.unwrap(), Some(204));
    assert_eq!(trace.lock().unwrap().as_slice(), &[
        ("entry", format!("127.0.0.1:{exit_port}")),
        ("exit", format!("127.0.0.1:{target}")),
    ]);

    let (echo_port, udp_packets) = spawn_udp_echo();
    let udp_probe = |port, payload: &'static [u8]| {
        tokio::task::spawn_blocking(move || local_socks_udp_echo(port, echo_port, payload))
    };
    assert!(udp_probe(control_port, b"direct-control").await.unwrap(), "UDP echo must be reachable");
    assert!(!udp_probe(routed_port, b"chain-must-reject").await.unwrap(),
        "TCP-only chain rule must reject UDP, not fall through to Direct");
    assert_eq!(udp_packets.lock().unwrap().as_slice(), &[b"direct-control".to_vec()]);

    trace.lock().unwrap().clear();
    entry_available.store(false, Ordering::SeqCst);
    assert_ne!(probe(routed_port).await.unwrap(), Some(204), "broken entry must not fall back");
    {
        let trace = trace.lock().unwrap();
        assert!(!trace.is_empty(), "the chain was not attempted");
        assert!(trace.iter().all(|(hop, _)| *hop == "entry"), "bypassed first hop: {trace:?}");
    }
    assert_eq!(probe(control_port).await.unwrap(), Some(204), "destination remains reachable directly");
    rt.shutdown().await;
}
