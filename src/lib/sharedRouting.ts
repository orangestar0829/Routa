import type { ExitMember, Model, RuleAction, RuleMatch, RuleProviderBehavior, RuleProviderFormat, RuleUnavailable, SharedRule } from "../bindings";
import { isGroupMember, memberKey, nodeLabel } from "./refs";

export type BaseRuleAction = Extract<RuleAction, string>;
export type DraftRuleAction = BaseRuleAction | { Target: { target: ExitMember | null; unavailable?: RuleUnavailable } };
export type RuleActionKind = BaseRuleAction | "Target";

export const MATCH_LABELS: Record<RuleMatch, string> = {
  DomainSuffix: "域名后缀",
  Domain: "完整域名",
  DomainKeyword: "域名关键字",
  Ipv4Cidr: "IPv4 CIDR",
  Ipv6Cidr: "IPv6 CIDR",
  Geosite: "GEOSITE",
  Geoip: "GEOIP",
  ProcessName: "进程名",
  ProcessPath: "进程路径",
  RuleSet: "RULE-SET",
};

export const RULE_MATCHERS = Object.entries(MATCH_LABELS) as [RuleMatch, string][];

export const ACTION_LABELS: Record<BaseRuleAction, string> = { Proxy: "代理", Direct: "直连", Reject: "阻断" };
export const RULE_ACTIONS = Object.entries(ACTION_LABELS) as [BaseRuleAction, string][];

export const RULE_VALUE_EXAMPLES: Record<RuleMatch, string> = {
  Domain: "www.example.com",
  DomainSuffix: "example.com",
  DomainKeyword: "example",
  Ipv4Cidr: "192.0.2.0/24",
  Ipv6Cidr: "2001:db8::/32",
  Geosite: "cn",
  Geoip: "CN",
  ProcessName: "Example.exe",
  ProcessPath: "C:\\Program Files\\Example\\Example.exe",
  RuleSet: "规则集名称",
};

export function ruleMatcherHint(matcher: RuleMatch): string | undefined {
  if (matcher === "ProcessName") return "填写 .exe 文件名。仅匹配内核能识别本机进程的连接。";
  if (matcher === "ProcessPath") return "填写本机 .exe 的完整路径。仅匹配内核能识别本机进程的连接。";
}

export function completeRuleAction(action: DraftRuleAction): action is RuleAction {
  return typeof action === "string" || action.Target.target !== null;
}

export function ruleActionKind(action: DraftRuleAction): RuleActionKind {
  return typeof action === "string" ? action : "Target";
}

export const targetUnavailable = (action: Extract<DraftRuleAction, object>): RuleUnavailable =>
  action.Target.unavailable ?? "Reject";

export function ruleActionLabel(action: DraftRuleAction, model: Model | undefined): string {
  if (typeof action === "string") return ACTION_LABELS[action];
  const member = action.Target.target;
  if (!member) return "未选择出口";
  if (!model) return "指定节点或组";
  if (!isGroupMember(member)) return nodeLabel(model, member);
  if ("Subscription" in member.group) {
    const id = member.group.Subscription;
    const source = model.subscriptions.find((s) => s.id === id);
    return source ? `${source.name}（订阅组）` : "（已删除的订阅组）";
  }
  const id = member.group.Custom;
  const group = model.node_groups.find((g) => g.id === id);
  return group ? `${group.name}（自建组）` : "（已删除的自建组）";
}

export function sameRuleAction(a: RuleAction, b: RuleAction): boolean {
  if (typeof a === "string" || typeof b === "string") return a === b;
  return memberKey(a.Target.target) === memberKey(b.Target.target) && targetUnavailable(a) === targetUnavailable(b);
}

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
