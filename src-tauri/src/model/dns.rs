//! The only allowed inputs for ordinary-mode DNS. Never pass arbitrary
//! nameserver URIs (fragments are *routing directives* in mihomo) to the core.
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

use super::{resolve, resolve_chain_hop, DnsProtection, Exit, ExitKind, Model, Resolved};

/// A stable internal name because unknown DNS fragments may dial directly.
pub(crate) const DNS_EGRESS_ALIAS: &str = "__routa_dns__";

fn usable_ip(ip: IpAddr) -> bool {
    !ip.is_unspecified() && !ip.is_multicast()
}

fn ip_port(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok_and(usable_ip)
        || s.parse::<SocketAddr>().is_ok_and(|a| a.port() > 0 && usable_ip(a.ip()) && !s.contains('%'))
}

/// Strict, literal authority rather than URL-normalized host (reject ambiguous
/// integer/hex IPv4 spellings). No URL credentials, query, percent encodings,
/// fragments, whitespace, or controls. Port omission means standard HTTPS.
fn doh(s: &str) -> bool {
    let Some((authority, path)) = s.strip_prefix("https://").and_then(|v| v.split_once('/')) else {
        return false;
    };
    if s.len() > 1024 || path.is_empty() || !path.bytes().all(|b|
        b.is_ascii_alphanumeric() || b"/-._~".contains(&b))
    {
        return false;
    }
    let literal = authority.strip_prefix('[').and_then(|h| h.strip_suffix(']'));
    if literal.is_some_and(|h| h.parse::<std::net::Ipv6Addr>().is_ok_and(|ip| usable_ip(ip.into()))) {
        return true;
    }
    authority.parse::<std::net::Ipv4Addr>().is_ok_and(|ip| usable_ip(ip.into()))
        || authority.parse::<SocketAddr>().is_ok_and(|a| a.port() > 0 && usable_ip(a.ip()) && !authority.contains('%'))
}

pub(crate) fn valid_suffix(s: &str) -> bool {
    !s.is_empty() && s.len() <= 253 && s.parse::<IpAddr>().is_err() &&
        s.split('.').all(|label| !label.is_empty() && label.len() <= 63 &&
            !label.starts_with('-') && !label.ends_with('-') &&
            label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
}

impl DnsProtection {
    pub fn problem(&self) -> Option<&'static str> {
        if !self.enabled { return None; }
        if self.proxy_exit.as_ref().is_none_or(|id| id.0.trim().is_empty()) {
            return Some("请选择代理 DNS 使用的固定节点或代理链出口");
        }
        if !doh(&self.proxy_doh) {
            return Some("代理 DoH 必须使用 HTTPS、IP 地址和路径，不支持域名、参数或片段");
        }
        if !ip_port(&self.direct_dns) && !doh(&self.direct_dns) {
            return Some("直连 DNS 必须使用 IP 地址、IP:端口或 IP 地址的 HTTPS DoH");
        }
        if !ip_port(&self.bootstrap_dns) && !doh(&self.bootstrap_dns) {
            return Some("节点解析 DNS 必须使用 IP 地址、IP:端口或 IP 地址的 HTTPS DoH");
        }
        if self.direct_suffixes.len() > 256 {
            return Some("直连域名后缀最多 256 个");
        }
        let mut seen = HashSet::new();
        for s in &self.direct_suffixes {
            if !valid_suffix(s) { return Some("直连后缀请填写域名（国际化域名使用 Punycode），不要填写通配符、IP 或规则"); }
            if !seen.insert(s.to_ascii_lowercase()) { return Some("直连域名后缀重复"); }
        }
        None
    }
}

pub fn eligible_exit(model: &Model, exit: &Exit) -> bool {
    let ExitKind::Node { node } = &exit.kind else { return false };
    !exit.hidden && !exit.name.starts_with("__") &&
        (resolve_chain_hop(model, node).is_some() || matches!(resolve(model, node), Some(Resolved::Chain { .. })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_have_no_implicit_bootstrap_or_mihomo_options() {
        for ok in ["https://1.1.1.1/dns-query", "https://[2001:db8::1]:443/dns-query", "https://[::1]/dns-query"] {
            assert!(doh(ok), "{ok}");
        }
        for bad in ["http://1.1.1.1/dns-query", "https://dns.example/dns-query", "https://1.1.1.1/dns-query#DIRECT",
            "https://1.1.1.1/dns-query#skip-cert-verify=true", "https://1.1.1.1/dns-query?", "https://u@1.1.1.1/dns-query",
            "https://1.1.1.1/d%23", "https://127.1/dns-query", "https://::1/dns-query", "https://0.0.0.0/dns-query",
            "https://1.1.1.1:0/dns-query", "https://[fe80::1%1]/dns-query", "https://1.1.1.1/dns-query\n"] {
            assert!(!doh(bad), "{bad}");
        }
        for ok in ["::1", "127.0.0.1", "127.0.0.1:53", "[::1]:5353"] { assert!(ip_port(ok), "{ok}"); }
        for bad in ["dhcp://system", "system", "8.8.8.8#RULES", "dns.local:53", "0.0.0.0", "224.0.0.1", "1.2.3.4:0"] {
            assert!(!ip_port(bad), "{bad}");
        }
        for bad in ["", "*", "*.cn", "+.cn", "1.1.1.1", "cn#DIRECT", "geosite:cn", ".cn", "cn.", "-bad", "a..b"] {
            assert!(!valid_suffix(bad), "{bad}");
        }
        let mut p = DnsProtection { enabled: true, proxy_exit: Some(super::super::ExitId("n".into())), ..Default::default() };
        assert_eq!(p.problem(), None);
        p.direct_suffixes = vec!["cn".into(), "CN".into()];
        assert!(p.problem().is_some());
    }
}
