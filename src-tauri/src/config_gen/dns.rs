//! A DNS lookup has no originating Routa listener metadata. Classify only
//! the user's explicit, process-wide domain exceptions; route everything
//! else through one specifically selected, stable proxy (or reject).
use super::*;
use crate::model::dns::{eligible_exit, DNS_EGRESS_ALIAS as ALIAS};

fn list(value: &str) -> Value { Value::Sequence(vec![s(value)]) }

pub(super) fn install(
    root: &mut Value,
    input: &GenInput,
    fingerprints: &BTreeMap<&ExitId, u64>,
    tun_exit: Option<&ExitId>,
) -> u64 {
    let model = input.model;
    let p = &model.settings.dns_protection;
    // generate() may also consume a hand-edited/migrated state without a save.
    // Never install unvalidated fragments or broaden DNS policy on that path.
    let valid = p.problem().is_none();
    let selected = p.proxy_exit.as_ref().and_then(|id| {
        let e = model.exits.iter().find(|e| &e.id == id)?;
        let fingerprint = fingerprints.get(id)?;
        (valid && eligible_exit(model, e)).then_some((e.name.as_str(), *fingerprint))
    });
    let target = selected.map_or("REJECT", |(name, _)| name);

    // In v1.19.33 an unknown #name is treated as an interface, not rejected!
    // Use a single-member group even when the selected exit/chain/NIC vanished.
    root["proxy-groups"].as_sequence_mut().expect("proxy groups").push(map(vec![
        ("name", s(ALIAS)), ("type", s("select")), ("proxies", list(target)),
        ("empty-fallback", s("REJECT")), ("hidden", Value::Bool(true)),
    ]));
    let upstream = format!("{}#{ALIAS}", p.proxy_doh);
    // Do not use direct-nameserver: it would override the default policy for
    // every DIRECT dial. Do not set respect-rules: global MATCH,REJECT is not a
    // per-listener routing table. Pure IP endpoints avoid circular bootstrap.
    let inert_bootstrap = format!("https://127.0.0.1/dns-query#{ALIAS}");
    let mut dns = map(vec![
        ("enable", Value::Bool(true)),
        ("enhanced-mode", s("redir-host")),
        ("ipv6", Value::Bool(true)),
        ("use-hosts", Value::Bool(false)),
        ("use-system-hosts", Value::Bool(false)),
        ("prefer-h3", Value::Bool(false)),
        ("respect-rules", Value::Bool(false)),
        ("nameserver", list(if valid { &upstream } else { "rcode://refused" })),
        // Even an invalid persisted model gets a syntactically valid *inert*
        // default resolver. Its host is an IP; its only possible relay rejects.
        ("default-nameserver", list(if valid { &p.bootstrap_dns } else { &inert_bootstrap })),
        ("proxy-server-nameserver", list(if valid { &p.bootstrap_dns } else { "rcode://refused" })),
        ("fallback", Value::Sequence(vec![])),
    ]);
    let mut policy = Mapping::new();
    if let Some(tun_exit) = tun_exit {
        // In v1.19.33 Fake-IP synthesis happens in the DNS service, not in
        // internal lookups used for outbound dials. TUN supplies that service
        // with captured DNS; do not open a listener or change OS settings.
        dns["enhanced-mode"] = s("fake-ip");
        dns["fake-ip-range"] = s("198.18.0.1/16");
        dns["fake-ip-ttl"] = Value::from(1);
        dns["use-hosts"] = Value::Bool(true);
        root["hosts"] = map(vec![("+.localhost", Value::Sequence(vec![s("127.0.0.1"), s("::1")]))]);
        if selected.is_some() {
            dns["fake-ip-filter-mode"] = s("blacklist");
            dns["fake-ip-filter"] = fake_ip_exceptions(input, tun_exit, p);
        } else {
            // Do not mint usable-looking answers when generation already
            // knows the selected DNS egress is gone or the policy is invalid.
            dns["fake-ip-filter-mode"] = s("whitelist");
            dns["fake-ip-filter"] = Value::Sequence(vec![]);
        }
        // Neither public DoH nor an implicit system resolver should receive
        // private names by default. Explicit user suffixes below override an
        // exact or less-specific LAN guard (including the one-label wildcard).
        policy.insert(s("*"), list("rcode://refused"));
        for suffix in PRIVATE_SUFFIXES {
            if !valid || !p.direct_suffixes.iter().any(|explicit| suffix_covers(explicit, suffix)) {
                policy.insert(s(&format!("+.{suffix}")), list("rcode://refused"));
            }
        }
    }
    if valid {
        for suffix in &p.direct_suffixes {
            policy.insert(s(&format!("+.{}", suffix.to_ascii_lowercase())), list(&p.direct_dns));
        }
        if p.direct_geosite_cn {
            policy.insert(s("geosite:cn"), list(&p.direct_dns));
        }
    }
    if !policy.is_empty() { dns["nameserver-policy"] = Value::Mapping(policy); }
    let fingerprint = hash_yaml(&map(vec![
        ("dns", dns.clone()),
        ("target", s(target)),
        ("route", selected.map_or(Value::Null, |(_, fp)| Value::from(fp))),
    ]));
    root["dns"] = dns;
    fingerprint
}

const PRIVATE_SUFFIXES: &[&str] = &["local", "lan", "internal", "home.arpa", "localhost"];
const CONNECTIVITY_HOSTS: &[&str] = &["dns.msftncsi.com", "www.msftncsi.com",
    // Also preserve the exact v1.19.33 default entries.
    "dns.msftnsci.com", "www.msftnsci.com", "www.msftconnecttest.com"];

fn suffix_covers(explicit: &str, local: &str) -> bool {
    let explicit = explicit.to_ascii_lowercase();
    local == explicit || local.strip_suffix(&explicit).is_some_and(|prefix| prefix.ends_with('.'))
}

fn fake_ip_exceptions(input: &GenInput, tun_exit: &ExitId, p: &DnsProtection) -> Value {
    let mut skip = BTreeSet::from(["*".to_owned()]); // exactly one label in Mihomo's DNS trie
    skip.extend(PRIVATE_SUFFIXES.iter().map(|suffix| format!("+.{suffix}")));
    skip.extend(CONNECTIVITY_HOSTS.iter().map(|host| host.to_string()));
    skip.extend(p.direct_suffixes.iter().map(|suffix| format!("+.{}", suffix.to_ascii_lowercase())));
    if p.direct_geosite_cn { skip.insert("geosite:cn".into()); }
    // Only effective DNS/TUN exits, not arbitrary catalog entries: an
    // unrelated subscription refresh must not restart a protected TUN.
    // An exact node exception changes the answer type, never the DNS route.
    let mut add_server = |raw: &serde_json::Value| {
        if let Some(server) = raw.get("server").and_then(|v| v.as_str()) {
            let host = server.strip_suffix('.').unwrap_or(server);
            if crate::model::dns::valid_suffix(host) { skip.insert(host.to_ascii_lowercase()); }
        }
    };
    for id in p.proxy_exit.iter().chain(std::iter::once(tun_exit)) {
        let Some(h) = input.health.exits.get(id).filter(|h| h.status == ExitStatus::Ok) else { continue };
        for node in &h.effective_members {
            match resolve(input.model, node) {
                Some(Resolved::Copyable { raw, .. }) => add_server(raw),
                Some(Resolved::Chain { hops, .. }) => {
                    for hop in hops { add_server(hop.raw); }
                }
                _ => {}
            }
        }
    }
    Value::Sequence(skip.into_iter().map(|v| s(&v)).collect())
}
