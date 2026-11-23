//! Generates the mihomo YAML config from the model and its derived health.
//! Everything is built as `serde_yaml_ng` values (never string concatenation)
//! so any name round-trips; key order is fixed so output is byte-stable.

mod dns;
mod route_names;
pub(crate) use route_names::{RouteName, RouteNames};
#[cfg(test)]
mod dns_fixtures;

use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::{Hash, Hasher};

use serde_yaml_ng::{Mapping, Value};

use crate::model::health::{exit_health, ExitHealth, ExitStatus, Health, ListenerStatus};
use crate::model::*;
use crate::netif::NetInterface;

fn route_keyword(matcher: &RuleMatch) -> &'static str {
    match matcher {
        RuleMatch::Domain => "DOMAIN",
        RuleMatch::DomainSuffix => "DOMAIN-SUFFIX",
        RuleMatch::DomainKeyword => "DOMAIN-KEYWORD",
        RuleMatch::Ipv4Cidr => "IP-CIDR",
        RuleMatch::Ipv6Cidr => "IP-CIDR6",
        RuleMatch::ProcessName => "PROCESS-NAME",
        RuleMatch::ProcessPath => "PROCESS-PATH",
        RuleMatch::Geosite => "GEOSITE",
        RuleMatch::Geoip => "GEOIP",
        RuleMatch::RuleSet => "RULE-SET",
    }
}

fn advanced_rule(matcher: &RuleMatch, action: &RuleAction) -> bool {
    matches!(matcher, RuleMatch::DomainKeyword | RuleMatch::Ipv6Cidr | RuleMatch::ProcessName | RuleMatch::ProcessPath)
        || matches!(action, RuleAction::Target { .. })
}

fn listener_subrule_name(sub_rules: &Mapping, listener: &Listener, auxiliary: bool) -> Value {
    if auxiliary {
        let name = s(&format!("__aux_{}", listener.id.0));
        if sub_rules.contains_key(&name) {
            return name;
        }
    }
    s(&format!("__port_{}", listener.id.0))
}

fn rule_provider_yaml(provider: &SharedRuleProvider) -> Value {
    let behavior = match provider.behavior {
        RuleProviderBehavior::Domain => "domain",
        RuleProviderBehavior::IpCidr => "ipcidr",
        RuleProviderBehavior::Classical => "classical",
    };
    let format = match provider.format {
        RuleProviderFormat::Yaml => "yaml",
        RuleProviderFormat::Text => "text",
        RuleProviderFormat::Mrs => "mrs",
    };
    // Leave the path to mihomo: it uses a URL-derived cache path in its home.
    // Fetch an explicitly configured provider directly. Without this override
    // the core's internal HTTP request hits the global fail-closed MATCH,REJECT
    // and silently leaves a new provider empty. Listener routing is unchanged.
    map(vec![
        ("type", s("http")),
        ("url", s(&provider.url)),
        ("proxy", s("DIRECT")),
        ("behavior", s(behavior)),
        ("format", s(format)),
        ("interval", Value::from(provider.interval)),
        ("size-limit", Value::from(16 * 1024 * 1024_u32)),
    ])
}

pub struct GenInput<'a> {
    pub model: &'a Model,
    pub health: &'a Health,
    pub secret: &'a str,
    /// Internal listeners used to fetch through an exit (Task 11).
    pub fetch_listeners: &'a [(ExitId, u16)],
    /// Same adapter list `health` was evaluated against; resolves Tailscale
    /// instance NICs.
    pub nics: &'a [NetInterface],
}

#[derive(Debug, Clone, PartialEq)]
pub struct Generated {
    pub yaml: String,
    /// Material DNS policy and actual egress, used to retire old transports and caches.
    pub protected_dns_fingerprint: Option<u64>,
    pub plan: EffectivePlan,
    pub(crate) route_names: RouteNames,
    /// (group name, member copy name) for each Ok select group whose selection is effective.
    pub selects: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PlannedListener {
    pub id: ListenerId,
    pub exit_name: String,
    pub exit_fingerprint: u64,
    /// Hash of the listener's own settings (type, listen, port, users): a
    /// change means existing connections were accepted under old rules.
    pub listener_fingerprint: u64,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EffectivePlan {
    /// Keyed by listener name; user listeners only, never `__fetch__`.
    pub listeners: BTreeMap<String, PlannedListener>,
}

pub fn node_proxy_name(sub: &Subscription, node: &Node) -> String {
    format!("{}/{}", sub.name, node.name)
}

/// Per-exit copy of a copyable node: `<出口>/<base>`, where base is
/// `<订阅>/<节点>` or `手动/<名>`.
pub fn member_proxy_name(exit: &Exit, base_name: &str) -> String {
    format!("{}/{}", exit.name, base_name)
}

fn s(x: &str) -> Value {
    Value::String(x.to_string())
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    let mut m = Mapping::new();
    for (k, v) in entries {
        m.insert(s(k), v);
    }
    Value::Mapping(m)
}

fn json_to_yaml(v: &serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::from(i)
            } else if let Some(u) = n.as_u64() {
                Value::from(u)
            } else {
                Value::from(n.as_f64().unwrap_or(0.0))
            }
        }
        serde_json::Value::String(x) => Value::String(x.clone()),
        serde_json::Value::Array(a) => Value::Sequence(a.iter().map(json_to_yaml).collect()),
        serde_json::Value::Object(o) => {
            let mut m = Mapping::new();
            for (k, val) in o {
                m.insert(s(k), json_to_yaml(val));
            }
            Value::Mapping(m)
        }
    }
}

/// Copy of the node's raw proxy mapping with `name` (and optionally
/// `interface-name`) replaced.
///
/// Subscription-supplied `interface-name`, `routing-mark` and `dialer-proxy`
/// are stripped: they would bind traffic to a NIC the user did not choose, or
/// reference a proxy that has been renamed. `None` if `raw` is not an object.
fn proxy_copy(raw: &serde_json::Value, name: &str, interface: Option<&str>) -> Option<Value> {
    let Value::Mapping(mut m) = json_to_yaml(raw) else {
        return None;
    };
    remove_proxy_keys(&mut m, &["interface-name", "routing-mark", "dialer-proxy"]);
    let noncanonical_names: Vec<_> = m.keys().filter(|key| key.as_str().is_some_and(|key| {
        key != "name" && proxy_option_matches(key, "name")
    })).cloned().collect();
    for key in noncanonical_names {
        m.remove(&key);
    }
    m.insert(s("name"), s(name));
    if let Some(i) = interface {
        m.insert(s("interface-name"), s(i));
    }
    Some(Value::Mapping(m))
}

/// Match the pinned core's `DefaultKeyReplacer` and ASCII-key EqualFold
/// aliases. Otherwise, for example, `dialer_proxy` survives sanitization.
pub(crate) fn proxy_option_matches(key: &str, canonical: &str) -> bool {
    key.chars().map(|c| match c {
        '_' => '-',
        'K' => 'k',
        'ſ' => 's',
        c => c.to_ascii_lowercase(),
    }).eq(canonical.chars())
}

fn remove_proxy_keys(mapping: &mut Mapping, keys: &[&str]) {
    let remove: Vec<_> = mapping.keys().filter(|key| key.as_str().is_some_and(|key| {
        keys.iter().any(|protected| proxy_option_matches(key, protected))
    })).cloned().collect();
    for key in remove {
        mapping.remove(&key);
    }
}

/// Manual nodes (proxy and Tailscale) default to `ip-version: dual`; an
/// explicit value is kept.
fn manual_defaults(proxy: Option<Value>) -> Option<Value> {
    proxy.map(|mut v| {
        if let Value::Mapping(m) = &mut v {
            if !m.contains_key("ip-version") {
                m.insert(s("ip-version"), s("dual"));
            }
        }
        v
    })
}

/// Copy of a resolved copyable node; manual nodes get [`manual_defaults`].
fn resolved_copy(raw: &serde_json::Value, manual: bool, name: &str, interface: Option<&str>) -> Option<Value> {
    let p = proxy_copy(raw, name, interface);
    if manual { manual_defaults(p) } else { p }
}

#[derive(Clone, Copy)]
enum ChainScope<'a> {
    Base,
    Exit(&'a str),
    Rule(&'a str),
}

impl ChainScope<'_> {
    fn suffix(self) -> String {
        let (kind, id) = match self {
            Self::Base => return "base".into(),
            Self::Exit(id) => ("exit", id),
            Self::Rule(id) => ("rule", id),
        };
        let encoded: String = id.bytes().map(|b| format!("{b:02x}")).collect();
        format!("{kind}_{encoded}")
    }
}

fn chain_proxies(
    node: &ManualNode,
    hops: &[ChainHop<'_>],
    target_name: &str,
    scope: ChainScope<'_>,
    interface: Option<&str>,
) -> Option<Vec<Value>> {
    let scope = scope.suffix();
    let mut previous = None;
    let mut proxies = Vec::with_capacity(hops.len());
    for (i, hop) in hops.iter().enumerate() {
        // Only the terminal copy is addressable as the user's chosen outlet.
        // Earlier copies use reserved, scope- and position-specific names.
        let name = if i + 1 == hops.len() { target_name.to_owned() }
            else { format!("__chain_hop{}_{}_{scope}", i + 1, node.id.0) };
        let nic = if i == 0 { interface } else { None };
        let Value::Mapping(mut proxy) = resolved_copy(hop.raw, hop.manual, &name, nic)? else {
            return None;
        };
        remove_proxy_keys(&mut proxy, &["udp", "udp-over-tcp"]);
        proxy.insert(s("udp"), Value::Bool(false));
        if let Some(parent) = previous {
            proxy.insert(s("dialer-proxy"), Value::String(parent));
        }
        proxies.push(Value::Mapping(proxy));
        previous = Some(name);
    }
    Some(proxies)
}

fn chain_exit(model: &Model, exit: &Exit) -> bool {
    matches!(&exit.kind, ExitKind::Node { node } if is_chain_ref(model, node))
}

/// mihomo skips a TCP-only outbound during UDP lookup. A transport branch
/// preserves normal precedence without putting user values inside expressions
/// (e.g. a literal parenthesis in a Windows process path).
fn install_udp_subrule(sub_rules: &mut Mapping, rules: &mut Vec<Value>, alias: String, udp_rules: Vec<Value>) {
    rules.insert(0, s(&format!("SUB-RULE,(NETWORK,udp),{alias}")));
    sub_rules.insert(s(&alias), Value::Sequence(udp_rules));
}

/// The instance's own NIC. `None`: configured but absent or unusable, so the
/// instance must not be written (fail closed, never the default NIC).
/// `Some(None)`: none configured, i.e. the system default.
fn tailscale_iface<'n>(opts: &TailscaleOpts, nics: &'n [NetInterface]) -> Option<Option<&'n str>> {
    match &opts.interface {
        None => Some(None),
        Some(g) => nics
            .iter()
            .find(|n| &n.guid == g)
            .filter(|n| n.is_usable())
            .map(|n| Some(n.mihomo_name.as_str())),
    }
}

/// The single definition of a Tailscale instance; every exit references it
/// by name and never copies it (copies would share hostname and state-dir).
fn tailscale_proxy(node: &ManualNode, opts: &TailscaleOpts, iface: Option<&str>) -> Value {
    let mut entries = vec![
        ("name", s(&manual_proxy_name(node))),
        ("type", s("tailscale")),
        ("hostname", s(&opts.hostname)),
        ("state-dir", s(&tailscale_state_dir(&node.id))),
        ("ephemeral", Value::Bool(opts.ephemeral)),
        ("udp", Value::Bool(opts.udp)),
    ];
    // Empty = no exit node: the instance only reaches tailnet devices.
    let exit_node = opts.exit_node.trim();
    if !exit_node.is_empty() {
        entries.push(("exit-node", s(exit_node)));
    }
    if let Some(k) = opts.auth_key.as_deref().filter(|k| !k.is_empty()) {
        entries.push(("auth-key", s(k)));
    }
    if let Some(i) = iface {
        entries.push(("interface-name", s(i)));
    }
    map(entries)
}

/// `None` when the instance must not be written (see `tailscale_iface`).
fn tailscale_def(node: &ManualNode, opts: &TailscaleOpts, nics: &[NetInterface]) -> Option<Value> {
    manual_defaults(tailscale_iface(opts, nics).map(|i| tailscale_proxy(node, opts, i)))
}

fn manual_node_parts(model: &Model, node: &ManualNode, nics: &[NetInterface]) -> Vec<Value> {
    let name = manual_proxy_name(node);
    match &node.kind {
        ManualNodeKind::Proxy { raw } => manual_defaults(proxy_copy(raw, &name, None))
            .into_iter().collect(),
        ManualNodeKind::Tailscale(opts) => tailscale_def(node, opts, nics).into_iter().collect(),
        ManualNodeKind::Chain(_) => {
            let r = NodeRef::Manual { manual_id: node.id.clone() };
            match resolve(model, &r) {
                Some(Resolved::Chain { node, hops }) =>
                    chain_proxies(node, &hops, &name, ChainScope::Base, None).unwrap_or_default(),
                _ => vec![],
            }
        }
    }
}

/// Proxy names (`手动/<名>`) of the Tailscale instances `generate` writes for
/// this model and adapter list (an instance whose NIC is unusable is skipped).
pub fn emitted_tailscale_names(model: &Model, nics: &[NetInterface]) -> Vec<String> {
    model
        .manual_nodes
        .iter()
        .filter(|n| matches!(&n.kind, ManualNodeKind::Tailscale(o) if tailscale_iface(o, nics).is_some()))
        .map(manual_proxy_name)
        .collect()
}

fn strategy_type(st: &GroupStrategy) -> &'static str {
    match st {
        GroupStrategy::UrlTest => "url-test",
        GroupStrategy::Fallback => "fallback",
        GroupStrategy::LoadBalance => "load-balance",
        GroupStrategy::Select => "select",
    }
}

/// Everything generated for one Ok exit: its own proxy entries, optional
/// group entry, and the Tailscale definitions it references. `shared` is
/// written once globally, so it only feeds the fingerprint.
struct ExitParts {
    proxies: Vec<Value>,
    group: Option<Value>,
    shared: Vec<Value>,
    route_names: RouteNames,
}

/// `None` when nothing could be emitted for the exit (treated as not Ok).
fn exit_parts(model: &Model, exit: &Exit, h: &ExitHealth, nics: &[NetInterface], scope: ChainScope<'_>) -> Option<ExitParts> {
    let iface = h.interface.as_ref().map(|n| n.mihomo_name.as_str());
    let mut route_names = RouteNames::default();
    let (proxies, group, shared) = match &exit.kind {
        ExitKind::Node { .. } => match h.effective_members.first().and_then(|r| resolve(model, r)) {
            Some(Resolved::Copyable { raw, manual, .. }) => {
                let proxy = resolved_copy(raw, manual, &exit.name, iface)?;
                if let Some(label) = h.effective_members.first().and_then(|r| route_names::node_name(model, r)) {
                    route_names.node(&exit.name, label);
                }
                (vec![proxy], None, vec![])
            }
            Some(Resolved::Chain { node, hops }) => {
                let proxies = chain_proxies(node, &hops, &exit.name, scope, iface)?;
                route_names.chain(&proxies, &node.name, &hops);
                (proxies, None, vec![])
            }
            Some(Resolved::Tailscale { node, opts }) => {
                let def = tailscale_def(node, opts, nics)?;
                let group = map(vec![
                    ("name", s(&exit.name)),
                    ("type", s("select")),
                    ("proxies", Value::Sequence(vec![s(&manual_proxy_name(node))])),
                ]);
                route_names.node(&exit.name, &node.name);
                (vec![], Some(group), vec![def])
            }
            None => return None,
        },
        ExitKind::Group { strategy, .. } => {
            let mut proxies = Vec::new();
            let mut shared = Vec::new();
            let mut names = Vec::new();
            for r in &h.effective_members {
                match resolve(model, r) {
                    Some(Resolved::Copyable { base_name, raw, manual }) => {
                        let name = member_proxy_name(exit, &base_name);
                        if let Some(p) = resolved_copy(raw, manual, &name, iface) {
                            proxies.push(p);
                            names.push(s(&name));
                            if let Some(label) = route_names::node_name(model, r) {
                                route_names.node(&name, label);
                            }
                        }
                    }
                    Some(Resolved::Tailscale { node, opts }) => {
                        if let Some(def) = tailscale_def(node, opts, nics) {
                            shared.push(def);
                            names.push(s(&manual_proxy_name(node)));
                        }
                    }
                    Some(Resolved::Chain { .. }) => return None,
                    None => {}
                }
            }
            let interval = model.settings.delay_test_interval_mins.map_or(0, |m| u64::from(m) * 60);
            let group = map(vec![
                ("name", s(&exit.name)),
                ("type", s(strategy_type(strategy))),
                ("proxies", Value::Sequence(names)),
                ("url", s(&model.settings.delay_test_url)),
                ("interval", Value::from(interval)),
            ]);
            if !matches!(scope, ChainScope::Rule(_)) {
                let mut owners = model.visible_listeners().filter(|l| l.exit.as_ref() == Some(&exit.id));
                let owner = owners.next();
                let label = if let (Some(owner), None) = (owner, owners.next()) {
                    format!("{} · 策略组", owner.name)
                } else if exit.name.starts_with("__")
                    || exit.name.strip_prefix("代理-").is_some_and(|id| uuid::Uuid::parse_str(id).is_ok())
                {
                    "策略组".into()
                } else {
                    format!("{} · 策略组", exit.name)
                };
                route_names.route(&exit.name, label);
            }
            (proxies, Some(group), shared)
        }
        ExitKind::Direct => {
            let mut entries = vec![("name", s(&exit.name)), ("type", s("direct"))];
            if let Some(i) = iface {
                entries.push(("interface-name", s(i)));
            }
            route_names.terminal(&exit.name, "直连");
            (vec![map(entries)], None, vec![])
        }
    };
    (!proxies.is_empty() || !shared.is_empty()).then_some(ExitParts { proxies, group, shared, route_names })
}

/// A rule target gets its own name and copies of its proxies for each port,
/// so it inherits that port's interface instead of using the global node copy.
fn rule_target_parts(input: &GenInput<'_>, port_exit: &Exit, alias: &str, target: &ExitMember) -> Option<ExitParts> {
    let kind = match target {
        ExitMember::Node(node) => ExitKind::Node { node: node.clone() },
        ExitMember::Group { .. } => ExitKind::Group {
            strategy: GroupStrategy::Fallback, members: vec![target.clone()], selected: None,
        },
    };
    let exit = Exit {
        id: ExitId(alias.into()),
        name: alias.into(),
        kind,
        interface: port_exit.interface.clone(),
        hidden: true,
    };
    let mut health = exit_health(input.model, &exit, input.nics);
    if health.status != ExitStatus::Ok {
        return None;
    }
    // A Tailscale instance has its own NIC and cannot honor a conflicting
    // port pin. Match the same exact NIC policy as normal port exits.
    health.effective_members.retain(|r| match resolve(input.model, r) {
        Some(Resolved::Tailscale { opts, .. }) => opts.interface == port_exit.interface,
        _ => true,
    });
    let mut parts = exit_parts(input.model, &exit, &health, input.nics, ChainScope::Rule(alias))?;
    if let ExitMember::Group { group } = target {
        let label = match group {
            GroupRef::Custom(id) => input.model.node_groups.iter().find(|g| &g.id == id).map(|g| g.name.as_str()),
            GroupRef::Subscription(id) => input.model.subscriptions.iter().find(|s| &s.id == id).map(|s| s.name.as_str()),
        };
        parts.route_names.route(alias, label.map_or_else(|| "节点组".into(), |name| format!("{name} · 节点组")));
    }
    Some(parts)
}

fn hash_yaml(v: &Value) -> u64 {
    let text = serde_yaml_ng::to_string(v).expect("yaml serialization");
    let mut hasher = DefaultHasher::new();
    text.hash(&mut hasher);
    hasher.finish()
}

/// What the exit routes through. The group's delay-test `url`/`interval`
/// are left out: changing them must not cut every connection of the group.
/// Referenced Tailscale definitions count: they are what the exit dials.
fn fingerprint(parts: &ExitParts) -> u64 {
    let mut all = parts.proxies.clone();
    all.extend(parts.shared.iter().cloned());
    if let Some(Value::Mapping(mut g)) = parts.group.clone() {
        g.remove("url");
        g.remove("interval");
        all.push(Value::Mapping(g));
    }
    hash_yaml(&Value::Sequence(all))
}

/// Measurement identity, independent of listener names, UI groups and update intervals.
/// Base nodes and per-exit copies deliberately have different identities.
pub fn delay_fingerprints(model: &Model, health: &Health, nics: &[NetInterface]) -> HashMap<String, u64> {
    let mut out = HashMap::new();
    let mut record = |name: String, path: Value| {
        out.insert(name, hash_yaml(&map(vec![("path", path), ("url", s(&model.settings.delay_test_url))])));
    };
    for sub in &model.subscriptions {
        for node in &sub.nodes {
            let name = node_proxy_name(sub, node);
            if let Some(proxy) = proxy_copy(&node.raw, &name, None) {
                record(name, proxy);
            }
        }
    }
    for node in &model.manual_nodes {
        let parts = manual_node_parts(model, node, nics);
        match parts.as_slice() {
            [] => {}
            [single] => record(manual_proxy_name(node), single.clone()),
            _ => record(manual_proxy_name(node), Value::Sequence(parts)),
        }
    }
    for exit in &model.exits {
        let Some(h) = health.exits.get(&exit.id).filter(|h| h.status == ExitStatus::Ok) else { continue };
        let Some(parts) = exit_parts(model, exit, h, nics, ChainScope::Exit(&exit.id.0)) else { continue };
        let selected = match &exit.kind { ExitKind::Group { selected, .. } => serde_yaml_ng::to_value(selected).expect("selection serialization"), _ => Value::Null };
        record(exit.name.clone(), map(vec![("config", Value::from(fingerprint(&parts))), ("selected", selected)]));
    }
    out
}

fn base_config(
    controller_port: u16,
    secret: &str,
    proxies: Vec<Value>,
    groups: Vec<Value>,
    listeners: Vec<Value>,
) -> String {
    let root = map(vec![
        ("mode", s("rule")),
        ("log-level", s("warning")),
        ("unified-delay", Value::Bool(true)),
        ("allow-lan", Value::Bool(true)),
        ("external-controller", s(&format!("127.0.0.1:{controller_port}"))),
        ("secret", s(secret)),
        ("profile", map(vec![("store-selected", Value::Bool(false))])),
        ("proxies", Value::Sequence(proxies)),
        ("proxy-groups", Value::Sequence(groups)),
        ("listeners", Value::Sequence(listeners)),
        ("rules", Value::Sequence(vec![s("MATCH,REJECT")])),
    ]);
    serde_yaml_ng::to_string(&root).expect("yaml serialization")
}

/// Config with only the controller: no outbounds, no listeners.
pub fn empty_config(controller_port: u16, secret: &str) -> String {
    base_config(controller_port, secret, vec![], vec![], vec![])
}

/// `empty_config` plus `nodes` as proxies, named and sanitized exactly like
/// `generate` emits them: what `mihomo -t` checks before fetched nodes are
/// accepted.
pub fn nodes_check_config(controller_port: u16, secret: &str, sub: &Subscription, nodes: &[Node]) -> String {
    let proxies = nodes
        .iter()
        .filter_map(|n| proxy_copy(&n.raw, &node_proxy_name(sub, n), None))
        .collect();
    base_config(controller_port, secret, proxies, vec![], vec![])
}

pub fn generate(input: &GenInput) -> Generated {
    generate_base(input, None)
}

fn generate_base(input: &GenInput, tun_exit: Option<&ExitId>) -> Generated {
    let model = input.model;
    let mut route_names = RouteNames::builtins();

    // Every subscription node, for the node page's delay tests.
    let mut proxies = Vec::new();
    for sub in &model.subscriptions {
        for node in &sub.nodes {
            let id = node_proxy_name(sub, node);
            if let Some(proxy) = proxy_copy(&node.raw, &id, None) {
                route_names.node(&id, &node.name);
                proxies.push(proxy);
            }
        }
    }
    // Base copies for measurement. Each Tailscale instance is emitted once;
    // each chain emits its entire ordered set of physical hops.
    for node in &model.manual_nodes {
        let parts = manual_node_parts(model, node, input.nics);
        if !parts.is_empty() {
            let r = NodeRef::Manual { manual_id: node.id.clone() };
            if let Some(Resolved::Chain { hops, .. }) = resolve(model, &r) {
                route_names.chain(&parts, &node.name, &hops);
            } else {
                route_names.node(&manual_proxy_name(node), &node.name);
            }
            proxies.extend(parts);
        }
    }

    let mut groups = Vec::new();
    let mut selects = Vec::new();
    let mut fingerprints: BTreeMap<&ExitId, u64> = BTreeMap::new();

    for exit in &model.exits {
        let Some(h) = input.health.exits.get(&exit.id) else {
            continue;
        };
        if h.status != ExitStatus::Ok {
            continue;
        }
        let Some(parts) = exit_parts(model, exit, h, input.nics, ChainScope::Exit(&exit.id.0)) else {
            continue;
        };
        fingerprints.insert(&exit.id, fingerprint(&parts));
        route_names.merge(parts.route_names);
        proxies.extend(parts.proxies);
        groups.extend(parts.group);

        if let ExitKind::Group {
            strategy: GroupStrategy::Select,
            selected: Some(sel),
            ..
        } = &exit.kind
        {
            if h.effective_members.contains(sel) {
                let member = match resolve(model, sel) {
                    Some(Resolved::Copyable { base_name, raw, .. }) if raw.is_object() => {
                        Some(member_proxy_name(exit, &base_name))
                    }
                    Some(Resolved::Tailscale { node, opts }) if tailscale_iface(opts, input.nics).is_some() => {
                        Some(manual_proxy_name(node))
                    }
                    _ => None,
                };
                if let Some(member) = member {
                    selects.push((exit.name.clone(), member));
                }
            }
        }
    }

    let mut sub_rules = Mapping::new();
    let provider_config: BTreeMap<_, _> = model.shared_rule_providers.iter()
        .map(|provider| (provider.name.as_str(), rule_provider_yaml(provider)))
        .collect();
    let mut used_providers = BTreeSet::new();
    let mut find_process = false;
    let mut listeners = Vec::new();
    let mut plan = BTreeMap::new();
    for l in &model.listeners {
        if input.health.listeners.get(&l.id) != Some(&ListenerStatus::Active) {
            continue;
        }
        let Some(exit) = l.exit.as_ref().and_then(|id| model.exits.iter().find(|e| &e.id == id)) else {
            continue;
        };
        let Some(&fp) = fingerprints.get(&exit.id) else {
            continue;
        };
        let tcp_only = chain_exit(model, exit);
        let ty = match l.listener_type {
            ListenerType::Mixed => "mixed",
            ListenerType::Http => "http",
            ListenerType::Socks => "socks",
        };
        let mut own = vec![("type", s(ty)), ("listen", s(&l.listen)), ("port", Value::from(l.port))];
        if let Some(a) = &l.auth {
            let user = map(vec![("username", s(&a.username)), ("password", s(&a.password))]);
            own.push(("users", Value::Sequence(vec![user])));
        }
        let mut fingerprint_fields = own.clone();
        fingerprint_fields.push(("routing", json_to_yaml(&serde_json::to_value(&l.routing).expect("routing"))));
        let mut entries = vec![("name", s(&l.name))];
        entries.extend(own.drain(..3));

        let inherited: Vec<_> = model.shared_rules.iter()
            .filter(|rule| l.inherit_shared_rules && !l.hidden && rule.enabled)
            .collect();
        if l.routing.is_some() || !inherited.is_empty() {
            let alias = format!("__port_{}", l.id.0);
            let target_alias = format!("__target_{}", l.id.0);
            groups.push(map(vec![("name", s(&target_alias)), ("type", s("select")), ("proxies", Value::Sequence(vec![s(&exit.name)]))]));
            let direct_alias = format!("__direct_{}", l.id.0);
            route_names.alias(&target_alias, &exit.name);
            route_names.terminal(&direct_alias, "直连");
            let mut direct = vec![("name", s(&direct_alias)), ("type", s("direct"))];
            if let Some(nic) = input.health.exits.get(&exit.id).and_then(|h| h.interface.as_ref()) { direct.push(("interface-name", s(&nic.mihomo_name))); }
            proxies.push(map(direct));
            let basic_action = |a: &RuleAction| match a {
                RuleAction::Proxy => target_alias.as_str(),
                RuleAction::Direct => direct_alias.as_str(),
                RuleAction::Reject | RuleAction::Target { .. } => "REJECT",
            };

            let local = l.routing.iter().flat_map(|routing| routing.rules.iter())
                .map(|rule| (&rule.matcher, rule.value.as_str(), &rule.action));
            let shared = inherited.iter().copied()
                .map(|rule| (&rule.matcher, rule.value.as_str(), &rule.action));
            let mut effective_providers = Mapping::new();
            let mut effective_targets = Mapping::new();
            let mut has_target_action = false;
            let mut has_chain_target = false;
            let mut rules = Vec::new();
            let mut udp_rules = Vec::new();
            let mut auxiliary_rules = Vec::new();
            let mut auxiliary_udp_rules = Vec::new();
            let mut has_advanced_rule = false;
            for (index, (matcher, value, r_action)) in local.chain(shared).enumerate() {
                if *matcher == RuleMatch::RuleSet {
                    if let Some(provider) = provider_config.get(value) {
                        used_providers.insert(value);
                        effective_providers.insert(s(value), provider.clone());
                    }
                    // An invalid reference in manually edited persisted JSON
                    // must be rejected by the core, not silently skipped.
                }
                if matches!(matcher, RuleMatch::ProcessName | RuleMatch::ProcessPath) {
                    find_process = true;
                }
                let mut guard_unsupported_transport = false;
                let mut route_is_chain = tcp_only && *r_action == RuleAction::Proxy;
                let target_name = if let RuleAction::Target { target, unavailable } = r_action {
                    has_target_action = true;
                    let route_alias = format!("__rule_target_{}_{index}", l.id.0);
                    if let Some(parts) = rule_target_parts(input, exit, &route_alias, target) {
                        route_is_chain = matches!(target, ExitMember::Node(node) if is_chain_ref(model, node));
                        has_chain_target |= route_is_chain;
                        effective_targets.insert(s(&route_alias), Value::from(fingerprint(&parts)));
                        route_names.merge(parts.route_names);
                        proxies.extend(parts.proxies);
                        groups.extend(parts.group);
                        guard_unsupported_transport = true;
                        route_alias
                    } else {
                        match unavailable {
                            RuleUnavailable::Reject => "REJECT".to_owned(),
                            RuleUnavailable::Direct => direct_alias.clone(),
                        }
                    }
                } else {
                    basic_action(r_action).to_owned()
                };
                let resolved_value;
                let value = if *matcher == RuleMatch::ProcessPath {
                    resolved_value = crate::model::normalize::normalize_exe_path(value);
                    resolved_value.as_str()
                } else {
                    value
                };
                let keyword = route_keyword(matcher);
                let line = s(&format!("{keyword},{value},{target_name}"));
                let udp_line = if route_is_chain {
                    s(&format!("{keyword},{value},REJECT"))
                } else {
                    line.clone()
                };
                if advanced_rule(matcher, r_action) {
                    has_advanced_rule = true;
                } else {
                    auxiliary_rules.push(line.clone());
                    if tcp_only {
                        auxiliary_udp_rules.push(udp_line.clone());
                    }
                }
                rules.push(line);
                udp_rules.push(udp_line);
                // mihomo skips a matched outbound that cannot transport UDP.
                // Never let an explicit node/group selection fall through to
                // a broader or direct rule for that same traffic.
                if guard_unsupported_transport {
                    let reject = s(&format!("{keyword},{value},REJECT"));
                    rules.push(reject.clone());
                    if !route_is_chain {
                        udp_rules.push(reject);
                    }
                }
            }
            let unmatched = l.routing.as_ref().map_or(&RuleAction::Proxy, |routing| &routing.unmatched);
            let fallback = s(&format!("MATCH,{}", basic_action(unmatched)));
            let udp_fallback = if tcp_only && *unmatched == RuleAction::Proxy {
                s("MATCH,REJECT")
            } else {
                fallback.clone()
            };
            rules.push(fallback.clone());
            udp_rules.push(udp_fallback.clone());
            if has_target_action && *unmatched == RuleAction::Proxy {
                // A TCP-only port default may also be skipped; do not let
                // mihomo fall back to its unbound built-in DIRECT route.
                rules.push(s("MATCH,REJECT"));
                if !tcp_only {
                    udp_rules.push(s("MATCH,REJECT"));
                }
            }
            if tcp_only || has_chain_target {
                fingerprint_fields.push(("effective-udp-rules", Value::Sequence(udp_rules.clone())));
                install_udp_subrule(&mut sub_rules, &mut rules, format!("__udp_port_{}", l.id.0), udp_rules);
            }
            if has_advanced_rule && l.routing.is_some() {
                // TUN and subscription refresh historically borrow the local
                // port's rule list. Keep legacy rules for them, but do not let
                // newly added app/target rules silently change that traffic.
                auxiliary_rules.push(fallback);
                if tcp_only {
                    auxiliary_udp_rules.push(udp_fallback);
                    install_udp_subrule(&mut sub_rules, &mut auxiliary_rules, format!("__udp_aux_{}", l.id.0), auxiliary_udp_rules);
                }
                sub_rules.insert(s(&format!("__aux_{}", l.id.0)), Value::Sequence(auxiliary_rules));
            }
            if !inherited.is_empty() || has_target_action || tcp_only {
                fingerprint_fields.push(("effective-rules", Value::Sequence(rules.clone())));
            }
            if !effective_targets.is_empty() {
                fingerprint_fields.push(("effective-targets", Value::Mapping(effective_targets)));
            }
            if !effective_providers.is_empty() {
                fingerprint_fields.push(("effective-providers", Value::Mapping(effective_providers)));
            }
            sub_rules.insert(s(&alias), Value::Sequence(rules));
            entries.push(("rule", s(&alias)));
        } else {
            if tcp_only && l.listener_type != ListenerType::Http {
                // Fixed inbound "proxy" mode bypasses the rule matcher.
                entries.push(("udp", Value::Bool(false)));
                fingerprint_fields.push(("udp", Value::Bool(false)));
            }
            entries.push(("proxy", s(&exit.name)));
        }
        let listener_fingerprint = hash_yaml(&map(fingerprint_fields));
        entries.extend(own);
        listeners.push(map(entries));
        plan.insert(
            l.name.clone(),
            PlannedListener {
                id: l.id.clone(),
                exit_name: exit.name.clone(),
                exit_fingerprint: fp,
                listener_fingerprint,
                port: l.port,
            },
        );
    }

    for (exit_id, port) in input.fetch_listeners {
        let selected = model.subscriptions.iter().find(|s| s.fallback_exit.as_ref() == Some(exit_id)).and_then(|s| s.fallback_listener.as_ref());
        if selected.is_some_and(|id| input.health.listeners.get(id) != Some(&ListenerStatus::Active)) { continue; }
        if !fingerprints.contains_key(exit_id) {
            continue;
        }
        let Some(exit) = model.exits.iter().find(|e| &e.id == exit_id) else {
            continue;
        };
        let routed = model.listeners.iter().find(|l| {
            l.exit.as_ref() == Some(exit_id) && l.routing.is_some()
                && selected.is_none_or(|id| &l.id == id)
                && sub_rules.contains_key(&listener_subrule_name(&sub_rules, l, true))
        });
        let destination = routed.map(|l| ("rule", listener_subrule_name(&sub_rules, l, true)))
            .unwrap_or(("proxy", s(&exit.name)));
        let fixed_chain = destination.0 == "proxy" && chain_exit(model, exit);
        let mut fetch = vec![
            ("name", s(&format!("__fetch__{}", exit_id.0))),
            ("type", s("mixed")),
            ("listen", s("127.0.0.1")),
            ("port", Value::from(*port)),
            destination,
        ];
        if fixed_chain {
            fetch.push(("udp", Value::Bool(false)));
        }
        listeners.push(map(fetch));
    }

    let mut root: Value = serde_yaml_ng::from_str(&base_config(model.settings.controller_port, input.secret, proxies, groups, listeners)).expect("generated config");
    if !sub_rules.is_empty() { root["sub-rules"] = Value::Mapping(sub_rules); }
    if find_process { root["find-process-mode"] = s("strict"); }
    if !used_providers.is_empty() {
        root["rule-providers"] = Value::Mapping(used_providers.into_iter().map(|name| {
            (s(name), provider_config[name].clone())
        }).collect());
    }
    let dns = &model.settings.dns_protection;
    let protected_dns_fingerprint = (dns.enabled && (tun_exit.is_none() || dns.tun_fake_ip))
        .then(|| dns::install(&mut root, input, &fingerprints, tun_exit));
    if protected_dns_fingerprint.is_some() {
        route_names.route(crate::model::dns::DNS_EGRESS_ALIAS, "代理 DNS");
    }
    Generated {
        route_names,
        protected_dns_fingerprint,
        yaml: serde_yaml_ng::to_string(&root).expect("routing config"),
        plan: EffectivePlan { listeners: plan },
        selects,
    }
}

/// TUN has its own explicit exit. User listeners keep their per-listener proxy.
/// An invalid exit is rejected rather than falling back to DIRECT.
pub fn generate_for_capture(input: &GenInput, tun_exit: Option<&ExitId>) -> Generated {
    let mut generated = generate_base(input, tun_exit);
    let Some(id) = tun_exit else { return generated };
    let mut root: Value = serde_yaml_ng::from_str(&generated.yaml).expect("generated yaml");
    let selected = input
        .model
        .exits
        .iter()
        .find(|e| &e.id == id)
        .filter(|e| {
            input
                .health
                .exits
                .get(&e.id)
                .is_some_and(|h| h.status == ExitStatus::Ok)
        });
    let target = selected.map(|e| e.name.as_str()).unwrap_or("REJECT");
    generated.route_names.alias("__routa_tun__", target);
    // A reserved alias keeps user names (including commas) out of the rule grammar.
    root["proxy-groups"]
        .as_sequence_mut()
        .expect("proxy groups")
        .push(map(vec![
            ("name", s("__routa_tun__")),
            ("type", s("select")),
            ("proxies", Value::Sequence(vec![s(target)])),
        ]));
    let mut rules = Vec::new();
    if selected.is_some_and(|e| chain_exit(input.model, e)) {
        rules.push(s("NETWORK,udp,REJECT"));
    }
    rules.push(s("MATCH,__routa_tun__"));
    root["rules"] = Value::Sequence(rules);
    if let Some(l) = input.model.listeners.iter().find(|l| l.exit.as_ref() == Some(id) && l.routing.is_some()) {
        if let Some(rules) = root.get("sub-rules").and_then(Value::as_mapping)
            .and_then(|sets| sets.get(&listener_subrule_name(sets, l, true))).cloned()
        {
            root["rules"] = rules;
        }
    }
    root["auto-detect-interface"] = Value::Bool(true);
    root["tun"] = map(vec![
        ("enable", Value::Bool(true)),
        ("device", s(crate::TUN_DEVICE_NAME)),
        ("stack", s("gvisor")),
        ("auto-route", Value::Bool(true)),
        ("strict-route", Value::Bool(true)),
        ("auto-detect-interface", Value::Bool(true)),
        ("dns-hijack", Value::Sequence(vec![s("any:53"), s("tcp://any:53")])),
    ]);
    if generated.protected_dns_fingerprint.is_none() {
        root["dns"] = map(vec![
            ("enable", Value::Bool(true)),
            ("enhanced-mode", s("fake-ip")),
            ("fake-ip-range", s("198.18.0.1/16")),
            (
                "nameserver",
                Value::Sequence(vec![s("https://1.1.1.1/dns-query"), s("https://8.8.8.8/dns-query")]),
            ),
        ]);
    }
    generated.yaml = serde_yaml_ng::to_string(&root).expect("capture yaml");
    generated
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::health::{evaluate, ExitStatus};
    use serde_json::json;
    use std::net::Ipv4Addr;

    fn nic(guid: &str, name: &str) -> NetInterface {
        NetInterface {
            guid: InterfaceGuid(guid.into()),
            friendly_name: name.into(),
            description: "d".into(),
            is_up: true,
            ipv4: vec![Ipv4Addr::new(10, 0, 0, 2)],
            ipv6: vec![],
            mihomo_name: name.into(),
        }
    }
    fn nics() -> Vec<NetInterface> {
        vec![nic("{G1}", "以太网"), nic("{G2}", "WLAN"), nic("{G3}", "USB")]
    }
    fn node(raw: serde_json::Value) -> Node {
        Node {
            name: raw["name"].as_str().unwrap().into(),
            proxy_type: raw["type"].as_str().unwrap().into(),
            server: raw["server"].as_str().unwrap().into(),
            raw,
        }
    }
    fn nref(n: &str) -> NodeRef {
        NodeRef::Subscription { subscription_id: SubscriptionId("s1".into()),
            name: n.into(),
        }
    }
    fn base() -> Model {
        let sub = Subscription {
            info: None,
            fallback_listener: None,
            id: SubscriptionId("s1".into()),
            name: "机场".into(),
            url: "https://x".into(),
            update_interval_mins: Some(1440),
            fallback_exit: None,
            last_updated: None,
            last_result: None,
            nodes: vec![
                node(
                    json!({"name":"HK 01","type":"ss","server":"1.1.1.1","port":443,"cipher":"aes-128-gcm","password":"pw"}),
                ),
                node(json!({"name":"JP 01","type":"trojan","server":"jp.example.com","port":443,"password":"pw2"})),
            ],
        };
        let exit = |id: &str, name: &str, kind, g: &str| Exit {
            id: ExitId(id.into()),
            name: name.into(),
            kind,
            interface: Some(InterfaceGuid(g.into())),
            hidden: false,
        };
        let lis = |id: &str, name: &str, t, listen: &str, port, auth, e: &str| Listener {
            routing: None,
            inherit_shared_rules: false,
            hidden: false,
            id: ListenerId(id.into()),
            name: name.into(),
            listener_type: t,
            listen: listen.into(),
            port,
            auth,
            exit: Some(ExitId(e.into())),
            user_enabled: true,
        };
        Model {
            subscriptions: vec![sub],
            exits: vec![
                exit("ea", "出口A", ExitKind::Node { node: nref("HK 01") }, "{G1}"),
                exit(
                    "eb",
                    "出口B",
                    ExitKind::Group {
                        strategy: GroupStrategy::UrlTest,
                        members: [nref("HK 01"), nref("JP 01")].map(ExitMember::Node).into(),
                        selected: None,
                    },
                    "{G2}",
                ),
                exit("ec", "出口C", ExitKind::Direct, "{G3}"),
            ],
            listeners: vec![
                lis(
                    "la",
                    "入口A",
                    ListenerType::Mixed,
                    "0.0.0.0",
                    7891,
                    Some(Auth {
                        username: "u".into(),
                        password: "p".into(),
                    }),
                    "ea",
                ),
                lis("lb", "入口B", ListenerType::Http, "127.0.0.1", 7892, None, "eb"),
                lis("lc", "入口C", ListenerType::Socks, "0.0.0.0", 7893, None, "ec"),
            ],
            settings: Settings::default(),
            manual_nodes: vec![],
            node_groups: vec![],
            process_routing: ProcessRouting::default(),
            shared_rules: vec![],
            shared_rule_providers: vec![],
        }
    }
    fn gen_with(m: &Model, nics: &[NetInterface], fetch: &[(ExitId, u16)]) -> Generated {
        let h = evaluate(m, nics);
        generate(&GenInput {
            model: m,
            health: &h,
            secret: "sekret",
            fetch_listeners: fetch,
            nics,
        })
    }
    fn gen(m: &Model) -> Generated {
        gen_with(m, &nics(), &[])
    }
    fn parse(y: &str) -> serde_yaml_ng::Value {
        serde_yaml_ng::from_str(y).unwrap()
    }
    fn names(v: &serde_yaml_ng::Value, key: &str) -> Vec<String> {
        v[key]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|p| p["name"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn per_port_rules_checked_by_bundled_core_and_isolated_from_forwarding() {
        let mut m = Model::default();
        let e = Exit { name: "outbound".into(), ..Exit::default() };
        let free = || std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        m.settings.controller_port = free();
        let rules_port=free(); let forward_port=free();
        let mut l = Listener::new_default("rules-port".into(), rules_port);
        l.exit = Some(e.id.clone());
        l.routing = Some(ListenerRouting { rules: vec![PortRule { matcher: RuleMatch::DomainSuffix, value: "example.com".into(), action: RuleAction::Reject }, PortRule {matcher:RuleMatch::Domain,value:"localhost".into(),action:RuleAction::Direct}, PortRule {matcher:RuleMatch::Ipv4Cidr,value:"127.0.0.0/8".into(),action:RuleAction::Proxy}], unmatched: RuleAction::Direct });
        let mut forward = Listener::new_default("forward-port".into(), forward_port);
        forward.exit = Some(e.id.clone());
        m.exits.push(e); m.listeners = vec![l, forward];
        let h = evaluate(&m, &[]);
        let g = generate(&GenInput { model: &m, health: &h, secret: "test", fetch_listeners: &[], nics: &[] });
        let v: Value = serde_yaml_ng::from_str(&g.yaml).unwrap();
        assert!(v["listeners"][0].get("proxy").is_none());
        assert!(v["listeners"][0].get("rule").is_some());
        assert_eq!(v["listeners"][1]["proxy"], "outbound");
        let td = tempfile::tempdir().unwrap();
        let config = td.path().join("config.yaml"); std::fs::write(&config, &g.yaml).unwrap();
        let bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("binaries/mihomo-x86_64-pc-windows-msvc.exe");
        let result = std::process::Command::new(bin).arg("-t").arg("-d").arg(td.path()).arg("-f").arg(&config).output().unwrap();
        assert!(result.status.success(), "{} {}", String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
        // Real loopback HTTP traffic through both generated listeners.
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin_port = origin.local_addr().unwrap().port();
            let server = tokio::spawn(async move {
                loop {
                    let Ok((mut socket, _)) = origin.accept().await else { break; };
                    tokio::spawn(async move { let mut buf = [0;4096]; let _ = socket.read(&mut buf).await; let _ = socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nrouta-ok").await; });
                }
            });
            struct ChildGuard(std::process::Child);
            impl Drop for ChildGuard { fn drop(&mut self) { let _=self.0.kill(); let _=self.0.wait(); } }
            let bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("binaries/mihomo-x86_64-pc-windows-msvc.exe");
            let _child = ChildGuard(std::process::Command::new(bin).arg("-d").arg(td.path()).arg("-f").arg(&config).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().unwrap());
            let mut ready = false;
            for _ in 0..100 { if tokio::net::TcpStream::connect(("127.0.0.1",rules_port)).await.is_ok() { ready=true; break; } tokio::time::sleep(std::time::Duration::from_millis(50)).await; }
            assert!(ready, "bundled core did not start");
            let routed = reqwest::Client::builder().proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{rules_port}")).unwrap()).timeout(std::time::Duration::from_secs(3)).build().unwrap();
            let forwarded = reqwest::Client::builder().proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{forward_port}")).unwrap()).timeout(std::time::Duration::from_secs(3)).build().unwrap();
            let body = routed.get(format!("http://127.0.0.1:{origin_port}/")).send().await.unwrap().text().await.unwrap(); assert_eq!(body,"routa-ok");
            let direct = routed.get(format!("http://localhost:{origin_port}/")).send().await.unwrap().text().await.unwrap(); assert_eq!(direct,"routa-ok");
            let blocked = routed.get("http://example.com/").send().await;
            assert!(blocked.is_err() || !blocked.unwrap().status().is_success());
            let body = forwarded.get(format!("http://127.0.0.1:{origin_port}/")).send().await.unwrap().text().await.unwrap(); assert_eq!(body,"routa-ok");
            server.abort();
        });
        let before = g.plan.listeners["rules-port"].listener_fingerprint;
        m.listeners[0].routing.as_mut().unwrap().unmatched = RuleAction::Reject;
        let after = generate(&GenInput { model: &m, health: &h, secret: "test", fetch_listeners: &[], nics: &[] });
        assert_ne!(before, after.plan.listeners["rules-port"].listener_fingerprint);
        assert_eq!(g.plan.listeners["forward-port"], after.plan.listeners["forward-port"]);
    }

    fn remote_provider(name: &str) -> SharedRuleProvider {
        SharedRuleProvider {
            name: name.into(), url: format!("https://example.com/{name}.mrs"),
            behavior: RuleProviderBehavior::Domain, format: RuleProviderFormat::Mrs, interval: 86400,
        }
    }

    #[test]
    fn shared_rules_follow_local_overrides_and_keep_nic_and_fallback() {
        let mut m = base();
        m.shared_rule_providers = vec![remote_provider("domains"), remote_provider("unused")];
        m.shared_rules = vec![
            SharedRule { enabled: true, matcher: RuleMatch::Geosite, value: "cn".into(), action: RuleAction::Direct },
            SharedRule { enabled: true, matcher: RuleMatch::Geoip, value: "CN".into(), action: RuleAction::Direct },
            SharedRule { enabled: false, matcher: RuleMatch::RuleSet, value: "unused".into(), action: RuleAction::Reject },
            SharedRule { enabled: true, matcher: RuleMatch::RuleSet, value: "domains".into(), action: RuleAction::Proxy },
        ];
        let unused = gen(&m);
        assert!(parse(&unused.yaml).get("rule-providers").is_none());
        m.listeners[0].inherit_shared_rules = true;
        m.listeners[0].routing = Some(ListenerRouting {
            rules: vec![PortRule { matcher: RuleMatch::Domain, value: "local.example".into(), action: RuleAction::Reject }],
            unmatched: RuleAction::Direct,
        });
        let out = gen(&m);
        let cfg = parse(&out.yaml);
        assert_eq!(cfg["listeners"][0]["rule"], "__port_la");
        assert_eq!(cfg["listeners"][1]["proxy"], "出口B");
        assert_eq!(cfg["sub-rules"]["__port_la"], serde_yaml_ng::to_value([
            "DOMAIN,local.example,REJECT",
            "GEOSITE,cn,__direct_la",
            "GEOIP,CN,__direct_la",
            "RULE-SET,domains,__target_la",
            "MATCH,__direct_la",
        ]).unwrap());
        let nic = nics().into_iter().find(|nic| nic.guid.0 == "{G1}").unwrap();
        assert_eq!(find(&cfg, "proxies", "__direct_la").unwrap()["interface-name"], nic.mihomo_name.as_str());
        assert_eq!(cfg["rule-providers"]["domains"]["type"], "http");
        assert_eq!(cfg["rule-providers"]["domains"]["proxy"], "DIRECT");
        assert_eq!(cfg["rules"][0], "MATCH,REJECT");
        assert_eq!(cfg["rule-providers"]["domains"]["behavior"], "domain");
        assert_eq!(cfg["rule-providers"]["domains"]["format"], "mrs");
        assert_eq!(cfg["rule-providers"]["domains"]["interval"], 86400);
        assert!(cfg["rule-providers"].get("unused").is_none());
        assert_ne!(unused.plan.listeners["入口A"].listener_fingerprint, out.plan.listeners["入口A"].listener_fingerprint);
        assert_eq!(unused.plan.listeners["入口B"], out.plan.listeners["入口B"]);

        m.shared_rule_providers[0].url = "https://example.com/updated.mrs".into();
        let updated = gen(&m);
        assert_ne!(out.plan.listeners["入口A"].listener_fingerprint, updated.plan.listeners["入口A"].listener_fingerprint);
        assert_eq!(out.plan.listeners["入口B"], updated.plan.listeners["入口B"]);
        m.shared_rule_providers[1].interval += 1;
        assert_eq!(updated.plan.listeners, gen(&m).plan.listeners);
    }

    #[test]
    fn inherit_only_defaults_to_port_exit_and_does_not_change_subscription_fetch() {
        let mut m = base();
        m.shared_rules.push(SharedRule {
            enabled: true, matcher: RuleMatch::DomainSuffix, value: "example.com".into(),
            action: RuleAction::Reject,
        });
        m.listeners[0].inherit_shared_rules = true;
        let nics = nics();
        let fetch = vec![(m.exits[0].id.clone(), 24000)];
        let cfg = parse(&gen_with(&m, &nics, &fetch).yaml);
        assert_eq!(cfg["sub-rules"]["__port_la"][1], "MATCH,__target_la");
        assert_eq!(find(&cfg, "listeners", "__fetch__ea").unwrap()["proxy"], "出口A");
        m.listeners[0].hidden = true;
        let cfg = parse(&gen(&m).yaml);
        assert!(cfg.get("sub-rules").is_none());
    }

    fn target_action(target: ExitMember, unavailable: RuleUnavailable) -> RuleAction {
        RuleAction::Target { target, unavailable }
    }

    #[test]
    fn extended_matchers_render_and_targets_preserve_port_isolation() {
        let mut m = base();
        let subscription = m.subscriptions[0].id.clone();
        m.listeners[0].inherit_shared_rules = true;
        m.listeners[0].routing = Some(ListenerRouting {
            rules: vec![PortRule {
                matcher: RuleMatch::ProcessPath,
                value: "C:/Program Files/Tools/probe.exe".into(),
                action: target_action(ExitMember::Node(nref("HK 01")), RuleUnavailable::Reject),
            }],
            unmatched: RuleAction::Proxy,
        });
        m.shared_rules = vec![
            SharedRule { enabled: true, matcher: RuleMatch::ProcessName, value: "browser.exe".into(),
                action: target_action(ExitMember::Group { group: GroupRef::Subscription(subscription) }, RuleUnavailable::Reject) },
            SharedRule { enabled: true, matcher: RuleMatch::Ipv6Cidr, value: "2001:db8::/32".into(), action: RuleAction::Reject },
            SharedRule { enabled: true, matcher: RuleMatch::DomainKeyword, value: "example".into(), action: RuleAction::Direct },
        ];
        let out = gen(&m);
        let cfg = parse(&out.yaml);
        assert_eq!(cfg["find-process-mode"], "strict");
        assert_eq!(cfg["sub-rules"]["__port_la"], serde_yaml_ng::to_value([
            r"PROCESS-PATH,C:\Program Files\Tools\probe.exe,__rule_target_la_0",
            r"PROCESS-PATH,C:\Program Files\Tools\probe.exe,REJECT",
            "PROCESS-NAME,browser.exe,__rule_target_la_1",
            "PROCESS-NAME,browser.exe,REJECT",
            "IP-CIDR6,2001:db8::/32,REJECT",
            "DOMAIN-KEYWORD,example,__direct_la",
            "MATCH,__target_la",
            "MATCH,REJECT",
        ]).unwrap());
        assert_eq!(find(&cfg, "proxies", "__rule_target_la_0").unwrap()["interface-name"], "以太网");
        let group = find(&cfg, "proxy-groups", "__rule_target_la_1").unwrap();
        assert_eq!(group["type"], "fallback");
        assert_eq!(group["proxies"].as_sequence().unwrap().len(), 2);
        assert_eq!(cfg["listeners"][1]["proxy"], "出口B");

        // A selected node changing underneath an unchanged rule must cut only
        // connections on that listener (not other listeners with no dependency).
        m.subscriptions[0].nodes[0].raw["server"] = serde_json::json!("changed.example.com");
        let updated = gen(&m);
        assert_ne!(out.plan.listeners["入口A"].listener_fingerprint, updated.plan.listeners["入口A"].listener_fingerprint);
        assert_eq!(out.plan.listeners["入口C"], updated.plan.listeners["入口C"]);
    }

    #[test]
    fn advanced_port_rules_do_not_leak_to_subscription_refresh_or_tun() {
        let mut m = base();
        m.listeners[0].inherit_shared_rules = true;
        m.listeners[0].routing = Some(ListenerRouting {
            rules: vec![PortRule {
                matcher: RuleMatch::DomainSuffix, value: "legacy.example".into(), action: RuleAction::Reject,
            }],
            unmatched: RuleAction::Proxy,
        });
        m.shared_rules = vec![
            SharedRule { enabled: true, matcher: RuleMatch::Domain, value: "legacy-shared.example".into(), action: RuleAction::Direct },
            SharedRule { enabled: true, matcher: RuleMatch::Domain, value: "selected.example".into(),
                action: target_action(ExitMember::Node(nref("HK 01")), RuleUnavailable::Reject) },
            SharedRule { enabled: true, matcher: RuleMatch::DomainKeyword, value: "extended".into(), action: RuleAction::Direct },
        ];
        m.subscriptions[0].fallback_listener = Some(m.listeners[0].id.clone());
        m.subscriptions[0].fallback_exit = m.listeners[0].exit.clone();
        let adapters = nics();
        let health = evaluate(&m, &adapters);
        let fetch = [(m.exits[0].id.clone(), 24000)];
        let cfg = parse(&generate_for_capture(&GenInput {
            model: &m, health: &health, secret: "test", fetch_listeners: &fetch, nics: &adapters,
        }, Some(&m.exits[0].id)).yaml);
        let legacy = serde_yaml_ng::to_value([
            "DOMAIN-SUFFIX,legacy.example,REJECT",
            "DOMAIN,legacy-shared.example,__direct_la",
            "MATCH,__target_la",
        ]).unwrap();
        assert_eq!(cfg["sub-rules"]["__aux_la"], legacy);
        assert_eq!(cfg["rules"], legacy);
        assert_eq!(find(&cfg, "listeners", "__fetch__ea").unwrap()["rule"], "__aux_la");
        assert_eq!(cfg["listeners"][0]["rule"], "__port_la");
        assert_eq!(cfg["sub-rules"]["__port_la"][2], "DOMAIN,selected.example,__rule_target_la_2");
        assert_eq!(cfg["sub-rules"]["__port_la"][3], "DOMAIN,selected.example,REJECT");
    }

    #[test]
    fn target_missing_stays_blocked_unless_bound_direct_is_explicit() {
        let mut m = base();
        m.listeners[0].inherit_shared_rules = true;
        m.shared_rules = vec![
            SharedRule { enabled: true, matcher: RuleMatch::DomainKeyword, value: "blocked".into(),
                action: target_action(ExitMember::Node(nref("removed-node")), RuleUnavailable::Reject) },
            SharedRule { enabled: true, matcher: RuleMatch::DomainKeyword, value: "direct".into(),
                action: target_action(ExitMember::Group { group: GroupRef::Custom(NodeGroupId("removed-group".into())) }, RuleUnavailable::Direct) },
        ];
        let out = gen(&m);
        let yaml = parse(&out.yaml);
        assert_eq!(yaml["sub-rules"]["__port_la"][0], "DOMAIN-KEYWORD,blocked,REJECT");
        assert_eq!(yaml["sub-rules"]["__port_la"][1], "DOMAIN-KEYWORD,direct,__direct_la");
        assert_eq!(find(&yaml, "proxies", "__direct_la").unwrap()["interface-name"], "以太网");
        assert!(find(&yaml, "proxies", "__rule_target_la_0").is_none());
        assert!(find(&yaml, "proxy-groups", "__rule_target_la_1").is_none());
        m.subscriptions[0].nodes.push(node(serde_json::json!(
            {"name":"removed-node","type":"http","server":"test.example","port":8080}
        )));
        let recovered = gen(&m);
        assert_eq!(parse(&recovered.yaml)["sub-rules"]["__port_la"][0], "DOMAIN-KEYWORD,blocked,__rule_target_la_0");
        assert_ne!(recovered.plan.listeners["入口A"].listener_fingerprint, out.plan.listeners["入口A"].listener_fingerprint);
    }

    #[test]
    fn basic_matches_fixture() {
        let expected = include_str!("../../tests/fixtures/gen_expected_basic.yaml").replace("\r\n", "\n");
        assert_eq!(gen(&base()).yaml, expected);
    }

    #[test]
    fn tun_uses_reserved_alias_and_rejects_a_missing_exit() {
        let mut m = base();
        m.exits[0].name = "出口,包含逗号".into();
        let adapters = nics();
        let h = evaluate(&m, &adapters);
        let input = GenInput {
            model: &m,
            health: &h,
            secret: "test",
            fetch_listeners: &[],
            nics: &adapters,
        };
        let enabled = parse(&generate_for_capture(&input, Some(&m.exits[0].id)).yaml);
        assert_eq!(enabled["tun"]["enable"], true);
        assert_eq!(enabled["rules"][0], "MATCH,__routa_tun__");
        let alias = enabled["proxy-groups"]
            .as_sequence()
            .unwrap()
            .iter()
            .find(|g| g["name"] == "__routa_tun__")
            .unwrap();
        assert_eq!(alias["proxies"][0], "出口,包含逗号");
        let missing = parse(&generate_for_capture(&input, Some(&ExitId("missing".into()))).yaml);
        let alias = missing["proxy-groups"]
            .as_sequence()
            .unwrap()
            .iter()
            .find(|g| g["name"] == "__routa_tun__")
            .unwrap();
        assert_eq!(alias["proxies"][0], "REJECT");
        assert_eq!(generate_for_capture(&input, None), generate(&input));
    }

    #[test]
    #[ignore = "requires MIHOMO_BIN; validates YAML only, does not start networking"]
    fn real_core_accepts_tun_capture_config() {
        let mut m = base();
        for e in &mut m.exits {
            e.interface = None;
        }
        let h = evaluate(&m, &[]);
        let g = generate_for_capture(
            &GenInput {
                model: &m,
                health: &h,
                secret: "test",
                fetch_listeners: &[],
                nics: &[],
            },
            Some(&m.exits[0].id),
        );
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("tun.yaml");
        std::fs::write(&path, g.yaml).unwrap();
        let output = std::process::Command::new(std::env::var("MIHOMO_BIN").expect("MIHOMO_BIN"))
            .args(["-t", "-f"])
            .arg(&path)
            .arg("-d")
            .arg(td.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore = "requires MIHOMO_BIN; validates YAML only, does not start networking"]
    fn real_core_accepts_manual_node_ip_version() {
        let mut m = with_group_exit(vec![proxy_manual("m1", "a", &["g1"]), ts_manual("t1", "ts", &["g1"], None)]);
        for e in &mut m.exits {
            e.interface = None;
        }
        let g = gen_with(&m, &[], &[]);
        assert!(g.yaml.contains("ip-version: dual"), "{}", g.yaml);
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("manual.yaml");
        std::fs::write(&path, g.yaml).unwrap();
        let output = std::process::Command::new(std::env::var("MIHOMO_BIN").expect("MIHOMO_BIN"))
            .args(["-t", "-f"])
            .arg(&path)
            .arg("-d")
            .arg(td.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn fixed_top_level() {
        let v = parse(&gen(&base()).yaml);
        assert_eq!(v["allow-lan"], true);
        // info logs one line per connection: the log would grow without bound.
        assert_eq!(v["log-level"], "warning");
        assert_eq!(v["external-controller"], "127.0.0.1:19097");
        assert_eq!(v["rules"], serde_yaml_ng::to_value(["MATCH,REJECT"]).unwrap());
        for k in ["port", "socks-port", "mixed-port", "tun", "dns"] {
            assert!(v.get(k).is_none(), "{k}");
        }
    }

    #[test]
    fn broken_exit_and_listener_omitted() {
        let mut m = base();
        m.subscriptions[0].nodes.remove(0); // HK 01 gone -> 出口A NodeMissing
        let h = evaluate(&m, &nics());
        assert_eq!(h.exits[&ExitId("ea".into())].status, ExitStatus::NodeMissing);
        let g = gen(&m);
        let v = parse(&g.yaml);
        assert!(!names(&v, "proxies").contains(&"出口A".to_string()));
        assert_eq!(names(&v, "listeners"), ["入口B", "入口C"]);
        assert!(!g.plan.listeners.contains_key("入口A"));
    }

    #[test]
    fn user_disabled_listener_omitted() {
        let mut m = base();
        m.listeners[1].user_enabled = false;
        let g = gen(&m);
        assert_eq!(names(&parse(&g.yaml), "listeners"), ["入口A", "入口C"]);
        assert_eq!(g.plan.listeners.len(), 2);
    }

    #[test]
    fn group_skips_missing_members() {
        let mut m = base();
        m.subscriptions[0].nodes.remove(1); // JP 01 gone
        let v = parse(&gen(&m).yaml);
        assert_eq!(
            v["proxy-groups"][0]["proxies"],
            serde_yaml_ng::to_value(["出口B/机场/HK 01"]).unwrap()
        );
        let ps = names(&v, "proxies");
        assert!(!ps.contains(&"出口B/机场/JP 01".to_string()));
        assert!(ps.contains(&"出口B/机场/HK 01".to_string()));
    }

    #[test]
    fn unicode_names_roundtrip() {
        let mut m = base();
        let weird = "🇭🇰 香港: \"01\"";
        m.subscriptions[0].nodes[0] = node(json!({"name":weird,"type":"ss","server":"1.1.1.1","port":443}));
        m.exits[0].kind = ExitKind::Node { node: nref(weird) };
        m.exits[1].kind = ExitKind::Group {
            strategy: GroupStrategy::Fallback,
            members: vec![ExitMember::Node(nref(weird))],
            selected: None,
        };
        let mut n = nics();
        n[0].mihomo_name = "以太网 2".into();
        let v = parse(&gen_with(&m, &n, &[]).yaml);
        let ps = v["proxies"].as_sequence().unwrap();
        assert_eq!(ps[0]["name"].as_str().unwrap(), format!("机场/{weird}"));
        let a = ps.iter().find(|p| p["name"] == "出口A").unwrap();
        assert_eq!(a["interface-name"].as_str().unwrap(), "以太网 2");
        let member = format!("出口B/机场/{weird}");
        assert!(ps.iter().any(|p| p["name"].as_str() == Some(&member)));
        assert_eq!(v["proxy-groups"][0]["proxies"][0].as_str().unwrap(), member);
    }

    #[test]
    fn strips_subscription_interface_and_dialer_proxy() {
        let mut m = base();
        m.subscriptions[0].nodes[0] = node(json!({"name":"HK 01","type":"ss","server":"1.1.1.1","port":443,
            "interface-name":"X","routing-mark":1,"dialer-proxy":"foo"}));
        m.exits[2].interface = None;
        m.exits[0].interface = None; // no-NIC node exit
        let h = evaluate(&m, &nics());
        let n = nics();
        let v = parse(
            &generate(&GenInput {
                model: &m,
                health: &h,
                secret: "s",
                fetch_listeners: &[],
                nics: &n,
            })
            .yaml,
        );
        let ps = v["proxies"].as_sequence().unwrap();
        let get = |n: &str| ps.iter().find(|p| p["name"].as_str() == Some(n)).unwrap();
        for n in ["机场/HK 01", "出口A"] {
            for k in ["interface-name", "routing-mark", "dialer-proxy"] {
                assert!(get(n).get(k).is_none(), "{n} {k}");
            }
        }
        let member = get("出口B/机场/HK 01");
        assert_eq!(member["interface-name"], "WLAN");
        assert!(member.get("routing-mark").is_none() && member.get("dialer-proxy").is_none());
        assert_eq!(
            member
                .as_mapping()
                .unwrap()
                .keys()
                .filter(|k| *k == "interface-name")
                .count(),
            1
        );
    }

    #[test]
    fn non_object_raw_is_not_emitted() {
        let mut m = base();
        m.subscriptions[0].nodes[0].raw = serde_json::Value::Null;
        let g = gen(&m);
        let v = parse(&g.yaml);
        let ps = names(&v, "proxies");
        assert!(!ps.contains(&"机场/HK 01".to_string()));
        assert!(!ps.contains(&"出口A".to_string()));
        assert!(!ps.contains(&"出口B/机场/HK 01".to_string()));
        assert!(ps.contains(&"出口B/机场/JP 01".to_string()));
        assert_eq!(
            v["proxy-groups"][0]["proxies"],
            serde_yaml_ng::to_value(["出口B/机场/JP 01"]).unwrap()
        );
        assert_eq!(names(&v, "listeners"), ["入口B", "入口C"]);
        assert!(!g.plan.listeners.contains_key("入口A"));
    }

    #[test]
    fn exit_and_listener_names_roundtrip() {
        let mut m = base();
        m.exits[0].name = "出 \"口\": 🚀".into();
        m.listeners[0].name = "入 \"口\": 🎯".into();
        let g = gen(&m);
        let v = parse(&g.yaml);
        assert!(names(&v, "proxies").contains(&"出 \"口\": 🚀".to_string()));
        let l = &v["listeners"][0];
        assert_eq!(l["name"].as_str().unwrap(), "入 \"口\": 🎯");
        assert_eq!(l["proxy"].as_str().unwrap(), "出 \"口\": 🚀");
        assert_eq!(g.plan.listeners["入 \"口\": 🎯"].exit_name, "出 \"口\": 🚀");
    }

    #[test]
    fn interval_none_gives_zero() {
        let mut m = base();
        m.settings.delay_test_interval_mins = None;
        let v = parse(&gen(&m).yaml);
        assert_eq!(v["proxy-groups"][0]["interval"].as_u64(), Some(0));
    }

    #[test]
    fn unified_delay_enabled() {
        let v = parse(&gen(&base()).yaml);
        assert_eq!(v["unified-delay"].as_bool(), Some(true));
        let e = parse(&empty_config(19098, "s"));
        assert_eq!(e["unified-delay"].as_bool(), Some(true));
    }

    #[test]
    fn deterministic() {
        assert_eq!(gen(&base()), gen(&base()));
    }

    #[test]
    fn plan_fingerprint_changes_when_exit_interface_changes() {
        let m = base();
        let before = gen(&m);
        let mut n = nics();
        n[1].mihomo_name = "WLAN 2".into();
        let after = gen_with(&m, &n, &[]);
        let fp = |g: &Generated, l: &str| g.plan.listeners[l].exit_fingerprint;
        assert_ne!(fp(&before, "入口B"), fp(&after, "入口B"));
        assert_eq!(fp(&before, "入口A"), fp(&after, "入口A"));
        assert_eq!(fp(&before, "入口C"), fp(&after, "入口C"));
        let p = &before.plan.listeners["入口B"];
        assert_eq!(
            (p.exit_name.as_str(), p.port, &p.id),
            ("出口B", 7892, &ListenerId("lb".into()))
        );
    }

    #[test]
    fn exit_fingerprint_ignores_delay_test_settings() {
        let fp = |m: &Model| gen(m).plan.listeners["入口B"].exit_fingerprint;
        let before = fp(&base());
        let mut m = base();
        m.settings.delay_test_url = "https://cp.cloudflare.com".into();
        m.settings.delay_test_interval_mins = Some(30);
        assert_eq!(fp(&m), before);
        assert_ne!(gen(&m).yaml, gen(&base()).yaml, "the group itself still changes");
        let mut m = base();
        m.exits[1].kind = ExitKind::Group {
            strategy: GroupStrategy::Fallback,
            members: [nref("HK 01"), nref("JP 01")].map(ExitMember::Node).into(),
            selected: None,
        };
        assert_ne!(fp(&m), before, "a strategy change still counts");
    }

    #[test]
    fn listener_fingerprint_tracks_own_settings_only() {
        let lfp = |m: &Model| gen(m).plan.listeners["入口A"].listener_fingerprint;
        let before = lfp(&base());
        let changed: [fn(&mut Listener); 5] = [
            |l| l.listener_type = ListenerType::Http,
            |l| l.listen = "127.0.0.1".into(),
            |l| l.port = 7999,
            |l| l.auth.as_mut().unwrap().password = "p2".into(),
            |l| l.auth = None,
        ];
        for (i, change) in changed.iter().enumerate() {
            let mut m = base();
            change(&mut m.listeners[0]);
            assert_ne!(lfp(&m), before, "change {i}");
        }
        let mut m = base();
        m.exits[0].interface = Some(InterfaceGuid("{G2}".into())); // exit, not listener
        assert_eq!(lfp(&m), before);
    }

    #[test]
    fn empty_config_has_no_listeners() {
        let v = parse(&empty_config(9097, "s"));
        assert_eq!(v["listeners"].as_sequence().unwrap().len(), 0);
        assert_eq!(v["proxies"].as_sequence().unwrap().len(), 0);
        assert_eq!(v["proxy-groups"].as_sequence().unwrap().len(), 0);
        assert_eq!(v["external-controller"], "127.0.0.1:9097");
        assert_eq!(v["secret"], "s");
        assert_eq!(v["rules"], serde_yaml_ng::to_value(["MATCH,REJECT"]).unwrap());
    }

    #[test]
    fn nodes_check_config_has_only_sanitized_nodes() {
        let mut m = base();
        m.subscriptions[0].nodes[0].raw["interface-name"] = json!("X");
        let sub = &m.subscriptions[0];
        let v = parse(&nodes_check_config(19097, "s", sub, &sub.nodes));
        assert_eq!(names(&v, "proxies"), ["机场/HK 01", "机场/JP 01"]);
        assert!(v["proxies"][0].get("interface-name").is_none());
        assert_eq!(v["proxies"][0]["cipher"], "aes-128-gcm");
        assert!(v["listeners"].as_sequence().unwrap().is_empty());
        assert!(v["proxy-groups"].as_sequence().unwrap().is_empty());
        assert_eq!(v["external-controller"], "127.0.0.1:19097");
    }

    #[test]
    fn select_groups_and_fetch_listeners() {
        let mut m = base();
        m.exits[1].kind = ExitKind::Group {
            strategy: GroupStrategy::Select,
            members: [nref("HK 01"), nref("JP 01")].map(ExitMember::Node).into(),
            selected: Some(nref("JP 01")),
        };
        let fetch = [(ExitId("eb".into()), 9100), (ExitId("zz".into()), 9101)];
        let g = gen_with(&m, &nics(), &fetch);
        assert_eq!(g.selects, vec![("出口B".to_string(), "出口B/机场/JP 01".to_string())]);
        let v = parse(&g.yaml);
        assert_eq!(v["proxy-groups"][0]["type"], "select");
        let ls = v["listeners"].as_sequence().unwrap();
        assert_eq!(ls.len(), 4);
        let last = ls.last().unwrap();
        assert_eq!(last["name"].as_str().unwrap(), "__fetch__eb");
        assert_eq!(last["listen"], "127.0.0.1");
        assert_eq!(last["proxy"], "出口B");
        assert_eq!(g.plan.listeners.len(), 3);
    }

    fn mref(id: &str) -> NodeRef {
        NodeRef::Manual {
            manual_id: ManualNodeId(id.into()),
        }
    }
    fn proxy_manual(id: &str, name: &str, groups: &[&str]) -> ManualNode {
        ManualNode {
            id: ManualNodeId(id.into()),
            name: name.into(),
            groups: groups.iter().map(|g| NodeGroupId((*g).into())).collect(),
            kind: ManualNodeKind::Proxy {
                raw: json!({"name":"orig","type":"socks5","server":"10.0.0.9","port":1080}),
            },
        }
    }
    fn chain_model() -> Model {
        let mut m = base();
        m.manual_nodes.push(proxy_manual("last", "落地", &[]));
        m.manual_nodes.push(ManualNode {
            id: ManualNodeId("chain".into()),
            name: "两跳".into(),
            groups: vec![],
            kind: ManualNodeKind::Chain(ProxyChain { hops: vec![nref("HK 01"), mref("last")] }),
        });
        m.exits[0].kind = ExitKind::Node { node: mref("chain") };
        m
    }

    #[test]
    fn chain_copies_hops_in_order_and_only_binds_the_first_to_the_interface() {
        let mut m = chain_model();
        m.subscriptions[0].nodes[0].raw["DIALER-PROXY"] = json!("untrusted");
        m.subscriptions[0].nodes[0].raw["interface-name"] = json!("untrusted");
        m.subscriptions[0].nodes[0].raw["interface_name"] = json!("untrusted");
        m.subscriptions[0].nodes[0].raw["dialer_proxy"] = json!("DIRECT");
        m.subscriptions[0].nodes[0].raw["Routing_Mark"] = json!(99);
        // Unrelated option spellings, credentials and nested header names
        // are not touched by the protected-key filter.
        m.subscriptions[0].nodes[0].raw["IP_VERSION"] = json!("dual");
        let ManualNodeKind::Proxy { raw } = &mut m.manual_nodes[0].kind else { panic!("test fixture") };
        raw["dialer-proxy"] = json!("untrusted");
        raw["NAME"] = json!("untrusted");
        raw["UDP"] = json!(true);
        raw["udp-over-tcp"] = json!(true);
        raw["UDP_Over_TCP"] = json!(true);
        let original = m.clone();

        let g = gen_with(&m, &nics(), &[(ExitId("ea".into()), 9095)]);
        let y = parse(&g.yaml);
        let base = find(&y, "proxies", "手动/两跳").unwrap();
        let route = find(&y, "proxies", "出口A").unwrap();
        let locate_first = |tail: &Value| find(&y, "proxies", tail["dialer-proxy"].as_str().unwrap()).unwrap();
        let base_first = locate_first(base);
        let route_first = locate_first(route);
        assert_ne!(base_first["name"], route_first["name"]);
        for first in [base_first, route_first] {
            assert_eq!(first["server"], "1.1.1.1");
            assert_eq!(first["IP_VERSION"], "dual");
            for protected in ["dialer-proxy", "DIALER-PROXY", "dialer_proxy", "routing-mark", "Routing_Mark", "interface_name"] {
                assert!(first.get(protected).is_none(), "{protected}");
            }
        }
        assert!(base_first.get("interface-name").is_none());
        assert_eq!(route_first["interface-name"], "以太网");
        for tail in [base, route] {
            assert_eq!(tail["server"], "10.0.0.9");
            assert_eq!(tail["udp"].as_bool(), Some(false));
            for protected in ["interface-name", "NAME", "UDP", "udp-over-tcp", "UDP_Over_TCP"] {
                assert!(tail.get(protected).is_none(), "{protected}");
            }
        }
        for name in ["入口A", "__fetch__ea"] {
            let port = find(&y, "listeners", name).unwrap();
            assert_eq!(port["proxy"], "出口A");
            assert_eq!(port["udp"].as_bool(), Some(false));
        }
        assert_eq!(m, original, "generation cannot mutate originals");

        let n = nics();
        let previous = delay_fingerprints(&m, &evaluate(&m, &n), &n);
        m.subscriptions[0].nodes[0].raw["server"] = json!("192.0.2.5");
        let latest = delay_fingerprints(&m, &evaluate(&m, &n), &n);
        assert_ne!(previous["手动/两跳"], latest["手动/两跳"]);
        assert_ne!(previous["出口A"], latest["出口A"]);
    }

    #[test]
    fn ordered_chain_copies_and_hashes_every_hop_in_each_scope() {
        let mut m = chain_model();
        // Exercise the upper bound, combining imported and manual nodes. IDs
        // (not display names) scope private copies of the same physical hops.
        let mut hops = vec![nref("HK 01")];
        for i in 2..MAX_CHAIN_HOPS {
            let id = format!("mid-{i}");
            let mut node = proxy_manual(&id, &id, &[]);
            let ManualNodeKind::Proxy { raw } = &mut node.kind else { unreachable!() };
            raw["port"] = json!(8000 + i);
            raw["dialer_proxy"] = json!("DIRECT");
            raw["DIALER-PROXY"] = json!("DIRECT");
            raw["interface_name"] = json!("not this NIC");
            raw["UDP_OVER_TCP"] = json!(true);
            m.manual_nodes.push(node);
            hops.push(mref(&id));
        }
        hops.push(mref("last"));
        m.manual_nodes[1].kind = ManualNodeKind::Chain(ProxyChain { hops: hops.clone() });
        m.listeners[0].routing = Some(ListenerRouting {
            unmatched: RuleAction::Direct,
            rules: vec![PortRule { matcher: RuleMatch::Domain, value: "local.test".into(),
                action: target_action(ExitMember::Node(mref("chain")), RuleUnavailable::Reject) }],
        });
        assert!(crate::model::validate(&m).is_ok());
        let n = nics();
        let before = m.clone();
        let generated = gen(&m);
        let y = parse(&generated.yaml);
        assert_eq!(m, before);
        let mut private_names = BTreeSet::new();
        for (target, nic) in [("手动/两跳", None), ("出口A", Some("以太网")), ("__rule_target_la_0", Some("以太网"))] {
            let mut p = find(&y, "proxies", target).unwrap();
            for i in (0..MAX_CHAIN_HOPS).rev() {
                if i < MAX_CHAIN_HOPS - 1 {
                    let name = p["name"].as_str().unwrap();
                    assert!(name.starts_with("__chain_hop"));
                    assert!(private_names.insert(name.to_owned()), "scope collision: {name}");
                }
                let expected_hop = resolve_chain_hop(&m, &hops[i]).unwrap();
                let route_id = p["name"].as_str().unwrap();
                let Some(RouteName::Node { name, path }) = generated.route_names.get(route_id) else {
                    panic!("missing exact display metadata for {route_id}")
                };
                assert_eq!(name, expected_hop.name);
                if i + 1 == MAX_CHAIN_HOPS {
                    let expected_path = hops.iter().map(|hop| resolve_chain_hop(&m, hop).unwrap().name)
                        .collect::<Vec<_>>().join(" → ");
                    assert_eq!(path.as_deref(), Some(format!("两跳 · 代理链：{expected_path}").as_str()));
                } else {
                    assert!(path.is_none());
                }
                let expected = expected_hop.raw;
                assert_eq!(p["server"].as_str(), expected["server"].as_str());
                assert_eq!(p["port"].as_u64(), expected["port"].as_u64());
                assert_eq!(p["interface-name"].as_str(), if i == 0 { nic } else { None });
                assert_eq!(p["udp"].as_bool(), Some(false));
                for key in ["dialer_proxy", "DIALER-PROXY", "interface_name", "UDP_OVER_TCP"] {
                    assert!(p.get(key).is_none(), "unsanitized {key} at hop {i}");
                }
                if i > 0 {
                    p = find(&y, "proxies", p["dialer-proxy"].as_str().unwrap()).unwrap();
                } else {
                    assert!(p.get("dialer-proxy").is_none());
                }
            }
        }
        let delay_hashes = |model: &Model| delay_fingerprints(model, &evaluate(model, &n), &n);
        let hashes = delay_hashes(&m);
        let plan = &generated.plan.listeners["入口A"];
        for hop in &hops {
            let mut changed = m.clone();
            let raw = match hop {
                NodeRef::Manual { manual_id } => {
                    let n = changed.manual_nodes.iter_mut().find(|n| &n.id == manual_id).unwrap();
                    let ManualNodeKind::Proxy { raw } = &mut n.kind else { unreachable!() };
                    raw
                }
                NodeRef::Subscription { name, .. } => {
                    &mut changed.subscriptions[0].nodes.iter_mut().find(|n| &n.name == name).unwrap().raw
                }
            };
            raw["server"] = json!("changed.test");
            let fresh = delay_hashes(&changed);
            assert_ne!(fresh["手动/两跳"], hashes["手动/两跳"]);
            assert_ne!(fresh["出口A"], hashes["出口A"]);
            let regenerated = gen(&changed);
            let other = &regenerated.plan.listeners["入口A"];
            assert_ne!(other.exit_fingerprint, plan.exit_fingerprint);
            assert_ne!(other.listener_fingerprint, plan.listener_fingerprint);
        }
        // Every invalid shape fails closed at resolution even before validation.
        let mut invalids = vec![vec![], vec![hops[0].clone()], {
            let mut v = hops.clone();
            v.push(nref("JP 01")); v
        }];
        let mut repeat = hops.clone(); repeat[3] = repeat[1].clone(); invalids.push(repeat);
        let mut nested = hops; nested[3] = mref("chain"); invalids.push(nested);
        for invalid in invalids {
            m.manual_nodes[1].kind = ManualNodeKind::Chain(ProxyChain { hops: invalid });
            assert!(crate::model::validate(&m).is_err());
            assert!(resolve(&m, &mref("chain")).is_none());
            assert!(!gen(&m).plan.listeners.contains_key("入口A"));
        }
    }

    #[test]
    fn chain_udp_rules_preserve_precedence_but_replace_proxy_actions_with_reject() {
        let mut m = chain_model();
        m.listeners[0].routing = Some(ListenerRouting {
            unmatched: RuleAction::Proxy,
            rules: vec![
                PortRule { matcher: RuleMatch::Domain, value: "direct.example".into(), action: RuleAction::Direct },
                PortRule { matcher: RuleMatch::DomainSuffix, value: "example".into(), action: RuleAction::Proxy },
                PortRule { matcher: RuleMatch::Domain, value: "shadow.example".into(), action: RuleAction::Direct },
            ],
        });
        let y = parse(&gen(&m).yaml);
        assert_eq!(y["sub-rules"]["__port_la"], seq(&[
            "SUB-RULE,(NETWORK,udp),__udp_port_la",
            "DOMAIN,direct.example,__direct_la",
            "DOMAIN-SUFFIX,example,__target_la",
            "DOMAIN,shadow.example,__direct_la",
            "MATCH,__target_la",
        ]));
        assert_eq!(y["sub-rules"]["__udp_port_la"], seq(&[
            "DOMAIN,direct.example,__direct_la",
            "DOMAIN-SUFFIX,example,REJECT",
            "DOMAIN,shadow.example,__direct_la",
            "MATCH,REJECT",
        ]));

        let n = nics();
        let h = evaluate(&m, &n);
        let capture = generate_for_capture(&GenInput { model: &m, health: &h, secret: "sekret", fetch_listeners: &[], nics: &n }, Some(&m.exits[0].id));
        assert_eq!(parse(&capture.yaml)["rules"], y["sub-rules"]["__port_la"]);
    }

    #[test]
    fn explicit_chain_rule_rejects_only_its_udp_and_preserves_auxiliary_scope() {
        let mut m = chain_model();
        m.manual_nodes.push(proxy_manual("first", "手动前置", &[]));
        m.manual_nodes[1].kind = ManualNodeKind::Chain(ProxyChain {
            hops: vec![mref("first"), nref("HK 01"), mref("last")],
        });
        m.exits[0].kind = ExitKind::Direct;
        let process = r"C:\Program Files (x86)\Browser\app.exe";
        m.listeners[0].routing = Some(ListenerRouting {
            unmatched: RuleAction::Direct,
            rules: vec![
                PortRule { matcher: RuleMatch::ProcessPath, value: process.into(), action: target_action(ExitMember::Node(mref("chain")), RuleUnavailable::Reject) },
                PortRule { matcher: RuleMatch::Domain, value: "unrelated.example".into(), action: RuleAction::Direct },
            ],
        });
        let n = nics();
        let h = evaluate(&m, &n);
        let fetch = [(m.exits[0].id.clone(), 9095)];
        let y = parse(&generate_for_capture(&GenInput { model: &m, health: &h, secret: "test", fetch_listeners: &fetch, nics: &n }, Some(&m.exits[0].id)).yaml);
        assert_eq!(y["sub-rules"]["__port_la"][0], "SUB-RULE,(NETWORK,udp),__udp_port_la");
        assert_eq!(y["sub-rules"]["__port_la"][1], format!("PROCESS-PATH,{process},__rule_target_la_0").as_str());
        assert_eq!(y["sub-rules"]["__udp_port_la"], seq(&[
            &format!("PROCESS-PATH,{process},REJECT"),
            "DOMAIN,unrelated.example,__direct_la",
            "MATCH,__direct_la",
        ]));
        let tail = find(&y, "proxies", "__rule_target_la_0").unwrap();
        let middle = find(&y, "proxies", tail["dialer-proxy"].as_str().unwrap()).unwrap();
        let first = find(&y, "proxies", middle["dialer-proxy"].as_str().unwrap()).unwrap();
        assert!(middle.get("interface-name").is_none());
        assert_eq!(first["interface-name"], "以太网");
        assert_eq!(find(&y, "listeners", "__fetch__ea").unwrap()["rule"], "__aux_la");
        assert_eq!(y["rules"], seq(&["DOMAIN,unrelated.example,__direct_la", "MATCH,__direct_la"]));
        assert_eq!(find(&y, "listeners", "入口B").unwrap()["proxy"], "出口B");

        m.subscriptions[0].nodes.remove(0);
        let blocked = parse(&gen(&m).yaml);
        assert_eq!(blocked["sub-rules"]["__port_la"][0], format!("PROCESS-PATH,{process},REJECT").as_str());
        assert!(find(&blocked, "proxies", "__rule_target_la_0").is_none());
        let action = &mut m.listeners[0].routing.as_mut().unwrap().rules[0].action;
        let RuleAction::Target { unavailable, .. } = action else { panic!("test fixture") };
        *unavailable = RuleUnavailable::Direct;
        let direct = parse(&gen(&m).yaml);
        assert_eq!(direct["sub-rules"]["__port_la"][0], format!("PROCESS-PATH,{process},__direct_la").as_str());
    }

    #[test]
    fn chain_as_port_default_remains_tcp_only_in_auxiliary_routing() {
        let mut m = chain_model();
        m.listeners[0].routing = Some(ListenerRouting {
            unmatched: RuleAction::Proxy,
            rules: vec![PortRule { matcher: RuleMatch::DomainKeyword, value: "port-only".into(), action: RuleAction::Direct }],
        });
        let n = nics();
        let h = evaluate(&m, &n);
        let fetch = [(m.exits[0].id.clone(), 9095)];
        let y = parse(&generate_for_capture(&GenInput { model: &m, health: &h, secret: "test", fetch_listeners: &fetch, nics: &n }, Some(&m.exits[0].id)).yaml);
        assert_eq!(y["rules"], seq(&["SUB-RULE,(NETWORK,udp),__udp_aux_la", "MATCH,__target_la"]));
        assert_eq!(y["sub-rules"]["__udp_aux_la"], seq(&["MATCH,REJECT"]));
        assert_eq!(find(&y, "listeners", "__fetch__ea").unwrap()["rule"], "__aux_la");
    }

    #[test]
    fn chain_fails_closed_when_original_subscription_hop_disappears() {
        let mut m = chain_model();
        assert!(crate::model::validate(&m).is_ok());
        m.subscriptions[0].nodes.remove(0);
        assert!(crate::model::validate(&m).is_ok(), "an external refresh can remove the hop");
        let h = evaluate(&m, &nics());
        assert_eq!(h.exits[&ExitId("ea".into())].status, ExitStatus::NodeMissing);
        let g = gen(&m);
        assert!(!g.plan.listeners.contains_key("入口A"));
        let y = parse(&g.yaml);
        assert!(find(&y, "proxies", "手动/两跳").is_none());
        assert!(find(&y, "proxies", "出口A").is_none());
        assert!(find(&y, "proxies", "机场/JP 01").is_some(), "do not replace the missing hop with this node");
    }

    #[test]
    fn chain_rejects_duplicate_nested_and_non_tcp_hops_and_groups() {
        let mut m = chain_model();
        let duplicate = ManualNodeKind::Chain(ProxyChain { hops: vec![mref("last"), mref("last")] });
        let nested = ManualNodeKind::Chain(ProxyChain { hops: vec![mref("chain"), mref("last")] });
        for kind in [duplicate, nested] {
            m.manual_nodes[1].kind = kind;
            assert!(resolve(&m, &mref("chain")).is_none());
            assert!(crate::model::validate(&m).is_err());
        }
        let mut m = chain_model();
        let ManualNodeKind::Proxy { raw } = &mut m.manual_nodes[0].kind else { panic!("test fixture") };
        raw["type"] = json!("hysteria2");
        assert!(resolve(&m, &mref("chain")).is_none());
        assert!(crate::model::validate(&m).is_err());
        let mut m = chain_model();
        m.exits[0].kind = group_kind(vec![ExitMember::Node(mref("chain"))]);
        assert!(crate::model::validate(&m).is_err());
    }

    fn ts_manual(id: &str, name: &str, groups: &[&str], iface: Option<&str>) -> ManualNode {
        let mut opts = TailscaleOpts::defaults_for(name);
        opts.exit_node = "100.64.0.9".into();
        opts.interface = iface.map(|g| InterfaceGuid(g.into()));
        ManualNode {
            id: ManualNodeId(id.into()),
            name: name.into(),
            groups: groups.iter().map(|g| NodeGroupId((*g).into())).collect(),
            kind: ManualNodeKind::Tailscale(opts),
        }
    }
    fn custom(gid: &str) -> ExitMember {
        ExitMember::Group {
            group: GroupRef::Custom(NodeGroupId(gid.into())),
        }
    }
    fn group_kind(members: Vec<ExitMember>) -> ExitKind {
        ExitKind::Group {
            strategy: GroupStrategy::Fallback,
            members,
            selected: None,
        }
    }
    fn find<'v>(v: &'v serde_yaml_ng::Value, key: &str, name: &str) -> Option<&'v serde_yaml_ng::Value> {
        v[key]
            .as_sequence()
            .unwrap()
            .iter()
            .find(|p| p["name"].as_str() == Some(name))
    }
    fn seq(xs: &[&str]) -> serde_yaml_ng::Value {
        serde_yaml_ng::to_value(xs).unwrap()
    }
    fn keys(p: &serde_yaml_ng::Value) -> Vec<String> {
        p.as_mapping()
            .unwrap()
            .keys()
            .map(|k| k.as_str().unwrap().to_string())
            .collect()
    }
    /// 出口B (Group, G2) holds custom group g1.
    fn with_group_exit(nodes: Vec<ManualNode>) -> Model {
        let mut m = base();
        m.manual_nodes = nodes;
        m.node_groups = vec![NodeGroup {
            members: vec![],
            id: NodeGroupId("g1".into()),
            name: "组".into(),
        }];
        m.exits[1].kind = group_kind(vec![custom("g1")]);
        m
    }

    #[test]
    fn manual_proxy_emitted_with_prefix() {
        let m = with_group_exit(vec![proxy_manual("m1", "a", &["g1"])]);
        let v = parse(&gen(&m).yaml);
        let ps = names(&v, "proxies");
        assert!(ps.contains(&"手动/a".to_string()), "{ps:?}");
        assert!(ps.contains(&"出口B/手动/a".to_string()), "{ps:?}");
        assert!(find(&v, "proxies", "手动/a").unwrap().get("interface-name").is_none());
        assert_eq!(find(&v, "proxies", "出口B/手动/a").unwrap()["interface-name"], "WLAN");
        assert_eq!(
            find(&v, "proxy-groups", "出口B").unwrap()["proxies"],
            seq(&["出口B/手动/a"])
        );
    }

    #[test]
    fn manual_proxy_defaults_to_dual_ip_version() {
        let mut keep = proxy_manual("m2", "b", &["g1"]);
        if let ManualNodeKind::Proxy { raw } = &mut keep.kind { raw["ip-version"] = json!("ipv4"); }
        let m = with_group_exit(vec![proxy_manual("m1", "a", &["g1"]), keep]);
        let v = parse(&gen(&m).yaml);
        assert_eq!(find(&v, "proxies", "手动/a").unwrap()["ip-version"], "dual");
        assert_eq!(find(&v, "proxies", "手动/b").unwrap()["ip-version"], "ipv4");
        assert_eq!(find(&v, "proxies", "出口B/手动/a").unwrap()["ip-version"], "dual");
        assert_eq!(find(&v, "proxies", "出口B/手动/b").unwrap()["ip-version"], "ipv4");
        assert!(find(&v, "proxies", "机场/HK 01").unwrap().get("ip-version").is_none());
    }

    #[test]
    fn renamed_manual_node_follows() {
        let mut m = with_group_exit(vec![proxy_manual("m1", "a", &["g1"])]);
        m.manual_nodes[0].name = "b".into();
        let ps = names(&parse(&gen(&m).yaml), "proxies");
        assert!(
            ps.contains(&"手动/b".to_string()) && ps.contains(&"出口B/手动/b".to_string()),
            "{ps:?}"
        );
        assert!(!ps.iter().any(|p| p.ends_with("手动/a")), "{ps:?}");
    }

    #[test]
    fn tailscale_emitted_once_and_referenced() {
        let mut m = with_group_exit(vec![ts_manual("t1", "ts", &["g1"], None)]);
        m.exits[1].interface = None;
        m.exits.push(Exit {
            id: ExitId("ed".into()),
            name: "出口D".into(),
            kind: group_kind(vec![ExitMember::Node(mref("t1"))]),
            interface: None,
            hidden: false,
        });
        let v = parse(&gen(&m).yaml);
        let ts: Vec<_> = v["proxies"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter(|p| p["type"] == "tailscale")
            .collect();
        assert_eq!(ts.len(), 1);
        assert_eq!(ts[0]["name"], "手动/ts");
        assert_eq!(ts[0]["state-dir"], "tailscale/t1");
        assert_eq!(ts[0]["hostname"], "mihomo-ts");
        assert_eq!(ts[0]["exit-node"], "100.64.0.9");
        assert_eq!(ts[0]["udp"], true);
        assert_eq!(ts[0]["ephemeral"], false);
        assert_eq!(
            keys(ts[0]),
            ["name", "type", "hostname", "state-dir", "ephemeral", "udp", "exit-node", "ip-version"]
        );
        assert_eq!(ts[0]["ip-version"], "dual");
        for g in ["出口B", "出口D"] {
            assert_eq!(
                find(&v, "proxy-groups", g).unwrap()["proxies"],
                seq(&["手动/ts"]),
                "{g}"
            );
        }
    }

    #[test]
    fn tailscale_without_exit_node_omits_the_key() {
        let mut m = base();
        let mut t = ts_manual("t1", "ts", &[], None);
        if let ManualNodeKind::Tailscale(o) = &mut t.kind {
            o.exit_node = "  ".into();
        }
        m.manual_nodes = vec![t];
        let v = parse(&gen(&m).yaml);
        let p = find(&v, "proxies", "手动/ts").unwrap();
        assert!(p.get("exit-node").is_none(), "{p:?}");
    }

    #[test]
    fn tailscale_node_exit_wraps_select() {
        let mut m = base();
        m.manual_nodes = vec![ts_manual("t1", "ts", &[], None)];
        m.exits[0].kind = ExitKind::Node { node: mref("t1") };
        m.exits[0].interface = None;
        let v = parse(&gen(&m).yaml);
        let g = find(&v, "proxy-groups", "出口A").expect("wrapper group");
        assert_eq!(g["type"], "select");
        assert_eq!(g["proxies"], seq(&["手动/ts"]));
        assert!(find(&v, "proxies", "出口A").is_none());
        assert_eq!(find(&v, "listeners", "入口A").unwrap()["proxy"], "出口A");
    }

    #[test]
    fn tailscale_interface_written() {
        let mut m = base();
        let mut t = ts_manual("t1", "ts", &[], Some("{G1}"));
        if let ManualNodeKind::Tailscale(o) = &mut t.kind {
            o.auth_key = Some("tskey-test".into());
        }
        m.manual_nodes = vec![t];
        m.exits[0].kind = ExitKind::Node { node: mref("t1") };
        let mut n = nics();
        n[0].mihomo_name = "以太网 3".into();
        let v = parse(&gen_with(&m, &n, &[]).yaml);
        let p = find(&v, "proxies", "手动/ts").unwrap();
        assert_eq!(p["interface-name"], "以太网 3");
        assert_eq!(p["auth-key"], "tskey-test");
        assert_eq!(&keys(p)[7..], ["auth-key", "interface-name", "ip-version"]);
    }

    #[test]
    fn tailscale_with_missing_nic_not_emitted() {
        let mut m = base();
        m.manual_nodes = vec![ts_manual("t1", "ts", &[], Some("{GONE}"))];
        m.exits[0].kind = ExitKind::Node { node: mref("t1") };
        m.exits[0].interface = Some(InterfaceGuid("{GONE}".into()));
        let h = evaluate(&m, &nics());
        assert_eq!(h.exits[&ExitId("ea".into())].status, ExitStatus::InterfaceUnavailable);
        let g = gen(&m);
        let v = parse(&g.yaml);
        assert!(!v["proxies"]
            .as_sequence()
            .unwrap()
            .iter()
            .any(|p| p["type"] == "tailscale"));
        assert!(find(&v, "proxy-groups", "出口A").is_none());
        assert!(find(&v, "listeners", "入口A").is_none());
        assert!(!g.plan.listeners.contains_key("入口A"));

        // A down NIC is not usable either.
        let mut m = base();
        m.manual_nodes = vec![ts_manual("t1", "ts", &[], Some("{G1}"))];
        let mut n = nics();
        n[0].is_up = false;
        let v = parse(&gen_with(&m, &n, &[]).yaml);
        assert!(find(&v, "proxies", "手动/ts").is_none());
    }

    #[test]
    fn tailscale_group_member_without_nic_is_skipped() {
        // Defense in depth: even when health says Ok, a group never references
        // an instance whose definition was not written.
        let mut m = with_group_exit(vec![
            ts_manual("t1", "ts", &["g1"], Some("{GONE}")),
            proxy_manual("m1", "a", &["g1"]),
        ]);
        m.exits[1].interface = None;
        let v = parse(&gen(&m).yaml);
        assert_eq!(
            find(&v, "proxy-groups", "出口B").unwrap()["proxies"],
            seq(&["出口B/手动/a"])
        );
        // Only the missing instance: the exit is not emitted at all.
        let mut m = with_group_exit(vec![ts_manual("t1", "ts", &["g1"], Some("{GONE}"))]);
        m.exits[1].interface = None;
        let g = gen(&m);
        let v = parse(&g.yaml);
        assert!(find(&v, "proxy-groups", "出口B").is_none());
        assert!(!g.plan.listeners.contains_key("入口B"));
    }

    #[test]
    fn group_dedupes_node_selected_twice() {
        let mut m = base();
        m.exits[1].kind = group_kind(vec![
            ExitMember::Node(nref("HK 01")),
            ExitMember::Group {
                group: GroupRef::Subscription(SubscriptionId("s1".into())),
            },
        ]);
        let v = parse(&gen(&m).yaml);
        assert_eq!(
            find(&v, "proxy-groups", "出口B").unwrap()["proxies"],
            seq(&["出口B/机场/HK 01", "出口B/机场/JP 01"])
        );
        let ps = names(&v, "proxies");
        assert_eq!(ps.iter().filter(|p| *p == "出口B/机场/HK 01").count(), 1);
    }

    #[test]
    fn fingerprint_changes_when_tailscale_changes() {
        let mk = |exit_node: &str| {
            let mut m = with_group_exit(vec![ts_manual("t1", "ts", &["g1"], None)]);
            m.exits[1].interface = None;
            if let ManualNodeKind::Tailscale(o) = &mut m.manual_nodes[0].kind {
                o.exit_node = exit_node.into();
            }
            m.manual_nodes.push(ts_manual("t2", "ts2", &[], None));
            m.exits[0].kind = ExitKind::Node { node: mref("t2") };
            m.exits[0].interface = None;
            gen(&m).plan
        };
        let (a, b) = (mk("auto:any"), mk("100.64.0.1"));
        let fp = |p: &EffectivePlan, l: &str| p.listeners[l].exit_fingerprint;
        assert_ne!(fp(&a, "入口B"), fp(&b, "入口B"));
        assert_eq!(fp(&a, "入口A"), fp(&b, "入口A"), "other instance unaffected");
    }

    #[test]
    fn select_tailscale_member_uses_shared_name() {
        let mut m = with_group_exit(vec![
            ts_manual("t1", "ts", &["g1"], None),
            proxy_manual("m1", "a", &["g1"]),
        ]);
        m.exits[1].interface = None;
        m.exits[1].kind = ExitKind::Group {
            strategy: GroupStrategy::Select,
            members: vec![custom("g1")],
            selected: Some(mref("t1")),
        };
        assert_eq!(gen(&m).selects, vec![("出口B".to_string(), "手动/ts".to_string())]);
        if let ExitKind::Group { selected, .. } = &mut m.exits[1].kind {
            *selected = Some(mref("m1"));
        }
        assert_eq!(gen(&m).selects, vec![("出口B".to_string(), "出口B/手动/a".to_string())]);
    }
}
