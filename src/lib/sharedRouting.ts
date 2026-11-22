import type { RuleAction, RuleMatch, RuleProviderBehavior, RuleProviderFormat, SharedRule } from "../bindings";

export const RULE_MATCHERS = [
  ["DomainSuffix", "域名后缀"],
  ["Domain", "完整域名"],
  ["Ipv4Cidr", "IPv4 CIDR"],
  ["Geosite", "GEOSITE"],
  ["Geoip", "GEOIP"],
  ["RuleSet", "RULE-SET"],
] as const satisfies readonly (readonly [RuleMatch, string])[];

export const RULE_ACTIONS = [
  ["Proxy", "代理"],
  ["Direct", "直连"],
  ["Reject", "阻断"],
] as const satisfies readonly (readonly [RuleAction, string])[];

export const MATCH_LABELS: Record<RuleMatch, string> = {
  Domain: "完整域名",
  DomainSuffix: "域名后缀",
  Ipv4Cidr: "IPv4 CIDR",
  Geosite: "GEOSITE",
  Geoip: "GEOIP",
  RuleSet: "RULE-SET",
};

export const ACTION_LABELS: Record<RuleAction, string> = { Proxy: "代理", Direct: "直连", Reject: "阻断" };

export const RULE_VALUE_EXAMPLES: Record<RuleMatch, string> = {
  Domain: "www.example.com",
  DomainSuffix: "example.com",
  Ipv4Cidr: "192.0.2.0/24",
  Geosite: "cn",
  Geoip: "CN",
  RuleSet: "规则集名称",
};

export const PROVIDER_BEHAVIORS: Record<RuleProviderBehavior, string> = {
  Domain: "域名",
  IpCidr: "IP 网段",
  Classical: "经典规则",
};

export const PROVIDER_FORMATS: Record<RuleProviderFormat, string> = {
  Yaml: "YAML",
  Text: "纯文本",
  Mrs: "MRS",
};

export const MAINLAND_DIRECT: readonly SharedRule[] = [
  { enabled: true, matcher: "Geosite", value: "cn", action: "Direct" },
  { enabled: true, matcher: "Geoip", value: "CN", action: "Direct" },
];
