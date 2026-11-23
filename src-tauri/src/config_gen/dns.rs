//! A DNS lookup has no originating Routa listener metadata. Classify only
//! the user's explicit, process-wide domain exceptions; route everything
//! else through one specifically selected, stable proxy (or reject).
use super::*;
use crate::model::dns::{eligible_exit, DNS_EGRESS_ALIAS as ALIAS};

fn list(value: &str) -> Value { Value::Sequence(vec![s(value)]) }

pub(super) fn install(
    root: &mut Value,
    model: &Model,
    fingerprints: &BTreeMap<&ExitId, u64>,
) -> u64 {
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
    if valid {
        let mut policy = Mapping::new();
        for suffix in &p.direct_suffixes {
            policy.insert(s(&format!("+.{}", suffix.to_ascii_lowercase())), list(&p.direct_dns));
        }
        if p.direct_geosite_cn {
            policy.insert(s("geosite:cn"), list(&p.direct_dns));
        }
        if !policy.is_empty() { dns["nameserver-policy"] = Value::Mapping(policy); }
    }
    let fingerprint = hash_yaml(&map(vec![
        ("dns", dns.clone()),
        ("target", s(target)),
        ("route", selected.map_or(Value::Null, |(_, fp)| Value::from(fp))),
    ]));
    root["dns"] = dns;
    fingerprint
}
