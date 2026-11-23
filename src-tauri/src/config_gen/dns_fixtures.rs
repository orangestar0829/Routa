//! Model -> generated YAML snapshots, also exported for the pinned-core smoke
//! test. The smoke test only replaces fixture ports with private loopback ports.
use super::{generate, generate_for_capture, GenInput, Generated};
use crate::model::health::evaluate;
use crate::model::{
    DnsProtection, Exit, ExitId, ExitKind, ExitMember, GroupStrategy, InterfaceGuid, Listener,
    ListenerId, ListenerRouting, ManualNode, ManualNodeId, ManualNodeKind, Model, Node, NodeRef,
    PortRule, ProxyChain, RuleAction, RuleMatch, Subscription, SubscriptionId,
};
use serde_json::json;
use serde_yaml_ng::Value;

const DNS_EXIT: &str = "精选 # &, 出口";
const DNS_ALIAS: &str = "__routa_dns__";
const DNS_EXIT_ID: &str = "dns-exit";

fn node(id: &str, name: &str, host: &str, port: u16) -> (ManualNode, NodeRef) {
    let id = ManualNodeId(id.into());
    (
        ManualNode {
            id: id.clone(),
            name: name.into(),
            groups: vec![],
            kind: ManualNodeKind::Proxy {
                raw: json!({"type": "http", "server": host, "port": port}),
            },
        },
        NodeRef::Manual { manual_id: id },
    )
}

fn fixture(chain: bool, geosite: bool) -> Model {
    let (terminal, terminal_ref) = node(
        "terminal",
        "terminal",
        if chain { "127.0.0.1" } else { "node.entry.test" },
        31004,
    );
    let mut nodes = vec![terminal];
    let selected = if chain {
        let (entry, entry_ref) = node("entry", "entry", "node.entry.test", 31005);
        nodes.push(entry);
        let manual_id = ManualNodeId("chain".into());
        nodes.push(ManualNode {
            id: manual_id.clone(),
            name: "chain".into(),
            groups: vec![],
            kind: ManualNodeKind::Chain(ProxyChain {
                hops: vec![entry_ref, terminal_ref],
            }),
        });
        NodeRef::Manual { manual_id }
    } else {
        terminal_ref
    };
    let direct_id = ExitId("loopback-direct".into());
    let dns_id = ExitId(DNS_EXIT_ID.into());
    let mut fixed = Listener::new_default("fixed-direct".into(), 31002);
    fixed.id = ListenerId("fixed-direct".into());
    fixed.listen = "127.0.0.1".into();
    fixed.exit = Some(direct_id.clone());
    let mut routed = Listener::new_default("ip-routed".into(), 31003);
    routed.id = ListenerId("ip-routed".into());
    routed.listen = "127.0.0.1".into();
    routed.exit = Some(direct_id.clone());
    routed.routing = Some(ListenerRouting {
        rules: vec![PortRule {
            matcher: RuleMatch::Ipv4Cidr,
            value: "127.0.0.1/32".into(),
            action: RuleAction::Direct,
        }],
        unmatched: RuleAction::Reject,
    });
    let mut model = Model {
        exits: vec![
            Exit {
                id: direct_id,
                name: "loopback-direct".into(),
                kind: ExitKind::Direct,
                interface: None,
                hidden: false,
            },
            Exit {
                id: dns_id.clone(),
                name: DNS_EXIT.into(),
                kind: ExitKind::Node { node: selected },
                interface: None,
                hidden: false,
            },
        ],
        listeners: vec![fixed, routed],
        manual_nodes: nodes,
        ..Default::default()
    };
    model.settings.controller_port = 31001;
    model.settings.dns_protection = DnsProtection {
        enabled: true,
        proxy_exit: Some(dns_id),
        direct_dns: "127.0.0.1:31007".into(),
        proxy_doh: "https://127.0.0.1:31006/dns-query".into(),
        bootstrap_dns: "127.0.0.1:31008".into(),
        direct_suffixes: vec!["local.test".into()],
        direct_geosite_cn: geosite,
        tun_fake_ip: false,
    };
    model
}

fn generated(model: &Model, tun: Option<&ExitId>) -> Generated {
    let health = evaluate(model, &[]);
    let input = GenInput {
        model,
        health: &health,
        secret: "test",
        fetch_listeners: &[],
        nics: &[],
    };
    if tun.is_some() {
        generate_for_capture(&input, tun)
    } else {
        generate(&input)
    }
}

fn parse(yaml: &str) -> Value {
    serde_yaml_ng::from_str(yaml).expect("valid YAML")
}

fn outbound<'v>(root: &'v Value, key: &str, name: &str) -> Option<&'v Value> {
    root[key]
        .as_sequence()
        .expect(key)
        .iter()
        .find(|row| row["name"].as_str() == Some(name))
}

fn assert_dns_snapshot(root: &Value, geosite: bool) {
    let mut dns = parse(
        "
enable: true
ipv6: true
enhanced-mode: redir-host
use-hosts: false
use-system-hosts: false
respect-rules: false
prefer-h3: false
default-nameserver: ['127.0.0.1:31008']
proxy-server-nameserver: ['127.0.0.1:31008']
nameserver: ['https://127.0.0.1:31006/dns-query#__routa_dns__']
fallback: []
nameserver-policy:
  '+.local.test': ['127.0.0.1:31007']
",
    );
    if geosite {
        dns["nameserver-policy"]["geosite:cn"] = parse("['127.0.0.1:31007']");
    }
    assert_eq!(root["dns"], dns);
    assert!(root.get("tun").is_none());
    assert_eq!(root["rules"], parse("['MATCH,REJECT']"));
    assert_eq!(
        root["listeners"],
        parse(
            "
- name: fixed-direct
  type: mixed
  listen: 127.0.0.1
  port: 31002
  proxy: loopback-direct
- name: ip-routed
  type: mixed
  listen: 127.0.0.1
  port: 31003
  rule: __port_ip-routed
",
        )
    );
    assert_eq!(
        root["sub-rules"],
        parse(
            "
__port_ip-routed:
  - 'IP-CIDR,127.0.0.1/32,__direct_ip-routed'
  - 'MATCH,REJECT'
",
        )
    );
}

#[test]
fn protected_dns_fixture_snapshot_and_optional_export() {
    let single = fixture(false, false);
    let chain = fixture(true, false);
    let geosite = fixture(false, true);
    let mut unavailable = single.clone();
    // Simulates the chosen exit disappearing while its node is still in the catalog.
    unavailable.exits.retain(|exit| exit.id.0 != DNS_EXIT_ID);
    let dir = std::env::var_os("ROUTA_DNS_FIXTURE_DIR").map(std::path::PathBuf::from);
    if let Some(dir) = &dir {
        std::fs::create_dir_all(dir).unwrap();
    }
    for (file, model, has_chain, is_geosite, chosen) in [
        ("single.yaml", &single, false, false, DNS_EXIT),
        ("chain.yaml", &chain, true, false, DNS_EXIT),
        ("geosite.yaml", &geosite, false, true, DNS_EXIT),
        ("unavailable.yaml", &unavailable, false, false, "REJECT"),
    ] {
        let config = generated(model, None);
        let root = parse(&config.yaml);
        assert!(config.protected_dns_fingerprint.is_some(), "{file}");
        assert_dns_snapshot(&root, is_geosite);
        let alias = outbound(&root, "proxy-groups", DNS_ALIAS).expect("alias must never be absent");
        assert_eq!(alias["type"], "select");
        assert_eq!(alias["proxies"], serde_yaml_ng::to_value([chosen]).unwrap(), "{file}");
        match outbound(&root, "proxies", DNS_EXIT) {
            None => assert_eq!(chosen, "REJECT"),
            Some(terminal) => {
                assert_eq!(terminal["type"], "http");
                assert_eq!(terminal["port"].as_u64(), Some(31004));
                if has_chain {
                    assert_eq!(terminal["server"], "127.0.0.1");
                    let entry_name = terminal["dialer-proxy"].as_str().expect("chain is intact");
                    let entry = outbound(&root, "proxies", entry_name).expect("entry hop exists");
                    assert_eq!(entry["type"], "http");
                    assert_eq!(entry["server"], "node.entry.test");
                    assert_eq!(entry["port"].as_u64(), Some(31005));
                    assert!(entry.get("dialer-proxy").is_none());
                } else {
                    assert_eq!(terminal["server"], "node.entry.test");
                    assert!(terminal.get("dialer-proxy").is_none());
                }
            }
        }
        if let Some(dir) = &dir {
            std::fs::write(dir.join(file), &config.yaml).unwrap();
        }
    }

    // Real production TUN configs (no extra DNS listen address). The wire
    // smoke substitutes only the capture device with a private test listener.
    let capture = ExitId("loopback-direct".into());
    let mut fake = geosite;
    fake.settings.dns_protection.direct_suffixes.extend(["TrUsTeD.LaN".into(), "printer".into()]);
    let ordinary = generated(&fake, None);
    let legacy = generated(&fake, Some(&capture));
    fake.settings.dns_protection.tun_fake_ip = true;
    assert_eq!(ordinary, generated(&fake, None), "arming Fake-IP must not affect proxy ports");
    let mut missing = fake.clone();
    missing.exits.retain(|e| e.id.0 != DNS_EXIT_ID);
    for (file, model, chosen) in [("fakeip.yaml", &fake, DNS_EXIT), ("fakeip-unavailable.yaml", &missing, "REJECT")] {
        let generated = generated(model, Some(&capture));
        let root = parse(&generated.yaml);
        let dns = &root["dns"];
        assert!(generated.protected_dns_fingerprint.is_some());
        assert_ne!(ordinary.protected_dns_fingerprint, generated.protected_dns_fingerprint);
        let legacy = parse(&legacy.yaml);
        for field in ["tun", "rules", "sub-rules", "listeners", "auto-detect-interface"] {
            assert_eq!(root[field], legacy[field], "{field}");
        }
        assert_eq!(outbound(&root, "proxy-groups", DNS_ALIAS).unwrap()["proxies"][0], chosen);
        assert_eq!(dns["enhanced-mode"], "fake-ip");
        assert_eq!(dns["fake-ip-range"], "198.18.0.1/16");
        assert!(dns.get("listen").is_none());
        assert!(dns.get("direct-nameserver").is_none());
        assert_eq!(dns["use-system-hosts"], false);
        assert_eq!(root["hosts"]["+.localhost"], parse("['127.0.0.1', '::1']"));
        assert_eq!(dns["nameserver-policy"]["+.lan"], parse("['rcode://refused']"));
        assert_eq!(dns["nameserver-policy"]["+.trusted.lan"], parse("['127.0.0.1:31007']"));
        assert_eq!(dns["nameserver-policy"]["geosite:cn"], parse("['127.0.0.1:31007']"));
        assert!(dns["nameserver-policy"].get("node.entry.test").is_none());
        assert_eq!(dns["proxy-server-nameserver"], parse("['127.0.0.1:31008']"));
        if chosen == "REJECT" {
            assert_eq!(dns["fake-ip-filter-mode"], "whitelist");
            assert_eq!(dns["fake-ip-filter"], parse("[]"));
        } else {
            assert_eq!(dns["fake-ip-filter-mode"], "blacklist");
            let filter = dns["fake-ip-filter"].as_sequence().unwrap();
            for item in ["node.entry.test", "*", "+.lan", "+.local.test", "+.trusted.lan", "geosite:cn", "www.msftconnecttest.com"] {
                assert!(filter.contains(&Value::String(item.into())), "{item}");
            }
            assert!(!filter.contains(&Value::String("+.node.entry.test".into())));
        }
        if let Some(dir) = &dir { std::fs::write(dir.join(file), &generated.yaml).unwrap(); }
    }
    fake.settings.dns_protection.enabled = false;
    assert_eq!(legacy, generated(&fake, Some(&capture)), "the opt-in is inert with DNS diversion off");
}

#[test]
fn fake_ip_only_accepts_literal_node_hostnames_and_honors_explicit_lan_suffixes() {
    let mut model = fixture(true, false);
    model.settings.dns_protection.tun_fake_ip = true;
    model.settings.dns_protection.direct_suffixes = vec!["lAn".into(), "ARPA".into(), "notinternal".into()];
    if let ManualNodeKind::Proxy { raw } = &mut model.manual_nodes[0].kind {
        raw["server"] = json!("HoP.FqDn.");
    }
    let before = generated(&model, Some(&model.exits[0].id));
    for (i, server) in ["*.invalid", "geosite:us", "+.local", "host,DIRECT", "unrelated.example", "192.0.2.9"].iter().enumerate() {
        model.manual_nodes.push(node(&format!("n{i}"), &format!("n{i}"), server, 1234).0);
    }
    let after = generated(&model, Some(&model.exits[0].id));
    assert_eq!(before.protected_dns_fingerprint, after.protected_dns_fingerprint);
    let root = parse(&after.yaml);
    let exclusions = root["dns"]["fake-ip-filter"].as_sequence().unwrap();
    assert!(exclusions.contains(&Value::String("hop.fqdn".into())));
    assert!(exclusions.contains(&Value::String("node.entry.test".into())));
    for bad in ["*.invalid", "geosite:us", "host,DIRECT", "unrelated.example", "192.0.2.9"] {
        assert!(!exclusions.contains(&Value::String(bad.into())));
    }
    let policy = &root["dns"]["nameserver-policy"];
    assert_eq!(policy["+.lan"], parse("['127.0.0.1:31007']"));
    assert!(policy.get("+.home.arpa").is_none()); // explicit ancestor "arpa" wins
    assert_eq!(policy["+.arpa"], parse("['127.0.0.1:31007']"));
    assert_eq!(policy["+.internal"], parse("['rcode://refused']"));
    assert!(policy.get("hop.fqdn").is_none());
    assert!(policy.get("geosite:cn").is_none());
}

#[test]
fn protected_dns_egress_change_never_changes_port_routing() {
    let mut model = fixture(false, false);
    let first = generated(&model, None);
    let first_yaml = parse(&first.yaml);

    let (replacement, replacement_ref) = node("replacement", "replacement", "127.0.0.1", 31005);
    model.manual_nodes.push(replacement);
    let replacement_id = ExitId("replacement-exit".into());
    model.exits.push(Exit {
        id: replacement_id.clone(),
        name: "replacement-exit".into(),
        kind: ExitKind::Node { node: replacement_ref },
        ..Default::default()
    });
    model.settings.dns_protection.proxy_exit = Some(replacement_id);
    let second = generated(&model, None);
    let second_yaml = parse(&second.yaml);
    for key in ["listeners", "rules", "sub-rules", "dns"] {
        assert_eq!(first_yaml[key], second_yaml[key], "{key}");
    }
    assert_eq!(
        outbound(&second_yaml, "proxy-groups", DNS_ALIAS).unwrap()["proxies"],
        parse("['replacement-exit']")
    );
    assert_ne!(first.protected_dns_fingerprint, second.protected_dns_fingerprint);

    // The chosen exit's NIC is unavailable: keep its saved selection and
    // fail closed instead of creating an unbound copy or changing the listener.
    model.exits.last_mut().unwrap().interface = Some(InterfaceGuid("{gone}".into()));
    let third = generated(&model, None);
    let third_yaml = parse(&third.yaml);
    assert_eq!(
        outbound(&third_yaml, "proxy-groups", DNS_ALIAS).unwrap()["proxies"],
        parse("['REJECT']")
    );
    assert_eq!(first_yaml["listeners"], third_yaml["listeners"]);
    assert_ne!(second.protected_dns_fingerprint, third.protected_dns_fingerprint);
}

#[test]
fn disabled_and_tun_configs_keep_the_legacy_dns_behavior() {
    let mut model = fixture(false, true);
    let tun_exit = ExitId("loopback-direct".into());
    let protected_tun = generated(&model, Some(&tun_exit));
    model.settings.dns_protection.enabled = false;
    assert_eq!(protected_tun, generated(&model, Some(&tun_exit)));
    assert!(protected_tun.protected_dns_fingerprint.is_none());
    let root = parse(&protected_tun.yaml);
    assert_eq!(root["dns"]["enhanced-mode"], "fake-ip");
    assert_eq!(root["dns"]["fake-ip-range"], "198.18.0.1/16");
    assert_eq!(root["tun"]["dns-hijack"], parse("['any:53', 'tcp://any:53']"));

    let disabled = generated(&model, None);
    model.settings.dns_protection = DnsProtection::default();
    assert_eq!(disabled, generated(&model, None));
    let root = parse(&disabled.yaml);
    assert!(root.get("dns").is_none());
    assert!(outbound(&root, "proxy-groups", DNS_ALIAS).is_none());
}

#[test]
fn malformed_persisted_dns_policy_never_creates_external_resolvers() {
    let mut model = fixture(false, true);
    let valid = model.settings.dns_protection.clone();
    for bad in [
        DnsProtection { proxy_doh: "https://127.0.0.1/dns-query#DIRECT".into(), ..valid.clone() },
        DnsProtection { bootstrap_dns: "system://".into(), ..valid.clone() },
        DnsProtection { direct_dns: "https://dns.example/dns-query#skip-cert-verify=true".into(), ..valid.clone() },
        DnsProtection { direct_suffixes: vec!["*".into()], ..valid.clone() },
        DnsProtection { proxy_exit: None, ..valid.clone() },
    ] {
        model.settings.dns_protection = bad;
        let ordinary = generated(&model, None);
        let root = parse(&ordinary.yaml);
        assert!(ordinary.protected_dns_fingerprint.is_some());
        assert_eq!(
            outbound(&root, "proxy-groups", DNS_ALIAS).unwrap()["proxies"],
            parse("['REJECT']")
        );
        let dns = &root["dns"];
        assert_eq!(dns["nameserver"], parse("['rcode://refused']"));
        assert_eq!(dns["proxy-server-nameserver"], parse("['rcode://refused']"));
        // Mihomo requires a literal IP here, even though this resolver is
        // unreachable. The explicit reserved REJECT alias makes it inert.
        assert_eq!(dns["default-nameserver"], parse("['https://127.0.0.1/dns-query#__routa_dns__']"));
        assert_eq!(dns["fallback"], parse("[]"));
        assert!(dns.get("direct-nameserver").is_none());
        assert!(dns.get("nameserver-policy").is_none());
        // Hand-edited malformed settings must not introduce any upstream
        // when the user separately enters TUN; keep TUN but disable synthesis.
        model.settings.dns_protection.tun_fake_ip = true;
        let capture = ExitId("loopback-direct".into());
        let root = parse(&generated(&model, Some(&capture)).yaml);
        let dns = &root["dns"];
        assert_eq!(dns["enhanced-mode"], "fake-ip");
        assert_eq!(dns["fake-ip-filter-mode"], "whitelist");
        assert_eq!(dns["fake-ip-filter"], parse("[]"));
        assert_eq!(dns["nameserver"], parse("['rcode://refused']"));
        assert_eq!(dns["proxy-server-nameserver"], parse("['rcode://refused']"));
        assert!(dns["nameserver-policy"].as_mapping().unwrap().values()
            .all(|v| *v == parse("['rcode://refused']")));
        assert_eq!(outbound(&root, "proxy-groups", DNS_ALIAS).unwrap()["proxies"], parse("['REJECT']"));
    }
}

#[test]
fn a_refreshed_pseudo_proxy_or_group_can_never_be_dns_egress() {
    let mut model = fixture(false, false);
    let subscription_id = SubscriptionId("source".into());
    let reference = NodeRef::Subscription {
        subscription_id: subscription_id.clone(),
        name: "source-node".into(),
    };
    model.subscriptions.push(Subscription {
        id: subscription_id,
        name: "test-source".into(),
        nodes: vec![Node {
            name: "source-node".into(),
            proxy_type: "http".into(),
            server: "node.entry.test".into(),
            raw: json!({"type": "http", "server": "node.entry.test", "port": 31004}),
        }],
        ..Default::default()
    });
    model.exits[1].kind = ExitKind::Node { node: reference.clone() };
    let before = generated(&model, None);
    let root = parse(&before.yaml);
    assert_eq!(
        outbound(&root, "proxy-groups", DNS_ALIAS).unwrap()["proxies"],
        serde_yaml_ng::to_value([DNS_EXIT]).unwrap()
    );

    // A subscription refresh retains the selected ID/name, but can change
    // what this proxy actually does. The generator checks current raw data,
    // not stale cached type metadata or the fact it is modeled as a Node.
    model.subscriptions[0].nodes[0].raw = json!({"type": "direct"});
    let pseudo = generated(&model, None);
    let root = parse(&pseudo.yaml);
    assert_eq!(outbound(&root, "proxies", DNS_EXIT).unwrap()["type"], "direct");
    assert_eq!(
        outbound(&root, "proxy-groups", DNS_ALIAS).unwrap()["proxies"],
        parse("['REJECT']")
    );
    assert_ne!(before.protected_dns_fingerprint, pseudo.protected_dns_fingerprint);

    model.subscriptions[0].nodes[0].raw =
        json!({"type": "http", "server": "node.entry.test", "port": 31004});
    model.exits[1].kind = ExitKind::Group {
        strategy: GroupStrategy::Select,
        members: vec![ExitMember::Node(reference)],
        selected: None,
    };
    let root = parse(&generated(&model, None).yaml);
    assert!(outbound(&root, "proxy-groups", DNS_EXIT).is_some());
    assert_eq!(
        outbound(&root, "proxy-groups", DNS_ALIAS).unwrap()["proxies"],
        parse("['REJECT']")
    );
}

#[test]
fn protected_dns_keeps_fetch_subrules_and_adapter_pins_independent() {
    use crate::netif::NetInterface;
    fn nic(id: &str, name: &str) -> NetInterface {
        NetInterface {
            guid: InterfaceGuid(id.into()),
            friendly_name: name.into(),
            description: String::new(),
            is_up: true,
            ipv4: vec!["10.0.0.2".parse().unwrap()],
            ipv6: vec![],
            mihomo_name: name.into(),
        }
    }
    let mut model = fixture(true, false);
    model.exits[0].interface = Some(InterfaceGuid("A".into()));
    model.exits[1].interface = Some(InterfaceGuid("B".into()));
    model.listeners[1].routing.as_mut().unwrap().rules.push(PortRule {
        matcher: RuleMatch::DomainKeyword,
        value: "advanced".into(),
        action: RuleAction::Reject,
    });
    let nics = [nic("A", "LAN"), nic("B", "WAN")];
    let fetch = [(model.exits[0].id.clone(), 31009)];
    let run = |model: &Model| {
        let health = evaluate(model, &nics);
        parse(&generate(&GenInput {
            model,
            health: &health,
            secret: "test",
            fetch_listeners: &fetch,
            nics: &nics,
        }).yaml)
    };
    let protected = run(&model);
    model.settings.dns_protection.enabled = false;
    let legacy = run(&model);
    for key in ["listeners", "sub-rules", "rules", "proxies"] {
        assert_eq!(protected[key], legacy[key], "{key}");
    }
    assert_eq!(
        outbound(&protected, "listeners", "__fetch__loopback-direct").unwrap()["rule"],
        "__aux_ip-routed"
    );
    assert_eq!(
        protected["sub-rules"]["__aux_ip-routed"],
        parse("['IP-CIDR,127.0.0.1/32,__direct_ip-routed', 'MATCH,REJECT']")
    );
    let terminal = outbound(&protected, "proxies", DNS_EXIT).unwrap();
    assert!(terminal.get("interface-name").is_none());
    let entry = outbound(&protected, "proxies", terminal["dialer-proxy"].as_str().unwrap()).unwrap();
    assert_eq!(entry["interface-name"], "WAN");
    assert_eq!(
        outbound(&protected, "proxies", "__direct_ip-routed").unwrap()["interface-name"],
        "LAN"
    );
}

#[test]
fn reserved_dns_alias_cannot_be_used_as_a_selected_even_hidden_exit() {
    let mut model = fixture(false, false);
    for hidden in [false, true] {
        model.exits[1].name = DNS_ALIAS.into();
        model.exits[1].hidden = hidden;
        assert!(!crate::model::dns::eligible_exit(&model, &model.exits[1]));
        assert!(crate::model::validate(&model).unwrap_err().iter().any(|error| {
            matches!(
                error,
                crate::model::ValidationError::InvalidName { name, .. } if name == DNS_ALIAS
            )
        }));
    }
}
