import type { JsonValue, ManualNodeKind, Model, NodeRef } from "../bindings";
import { isSubRef, nodeKey } from "./refs";

export type ChainHops = Extract<ManualNodeKind, { Chain: unknown }>["Chain"];

const CHAIN_PROTOCOLS = new Set(["http", "socks5", "ss", "vmess", "vless", "trojan"]);
const CHAIN_TRANSPORTS = new Set(["", "tcp", "ws", "grpc", "http", "h2", "httpupgrade"]);
const CHECKED_KEYS = new Set(["type", "server", "port", "network", "plugin"]);

function eligibleRaw(raw: JsonValue | undefined): boolean {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return false;
  // Mirror the canonical option boundary. mihomo's decoder can read aliases
  // that an exact JavaScript property lookup would silently ignore.
  if (Object.keys(raw).some((key) => /[^\x00-\x7f]/.test(key) || key === "<<"
    || (!CHECKED_KEYS.has(key) && CHECKED_KEYS.has(key.toLowerCase())))) return false;
  const type = typeof raw.type === "string" ? raw.type : "";
  const port = typeof raw.port === "number" ? raw.port
    : typeof raw.port === "string" && /^[0-9]+$/.test(raw.port) ? Number(raw.port) : NaN;
  return CHAIN_PROTOCOLS.has(type)
    && typeof raw.server === "string" && !!raw.server.trim()
    && Number.isInteger(port) && port >= 1 && port <= 65535
    && (raw.network === undefined || (typeof raw.network === "string" && CHAIN_TRANSPORTS.has(raw.network)))
    && (raw.plugin === undefined || raw.plugin === "");
}

export function isProxyChain(model: Model, ref: NodeRef): boolean {
  return !isSubRef(ref) && model.manual_nodes.some((node) =>
    node.id === ref.manual_id && "Chain" in node.kind);
}

/** Match the backend's fixed, nonrecursive TCP hop allow-list. */
export function canBeChainHop(model: Model, ref: NodeRef): boolean {
  if (isSubRef(ref)) {
    const node = model.subscriptions.find((s) => s.id === ref.subscription_id)?.nodes
      .find((n) => n.name === ref.name);
    return eligibleRaw(node?.raw);
  }
  const node = model.manual_nodes.find((n) => n.id === ref.manual_id);
  return !!node && "Proxy" in node.kind && eligibleRaw(node.kind.Proxy.raw);
}

export function chainProblem(model: Model, hops: ChainHops): string | undefined {
  const entry = canBeChainHop(model, hops.entry);
  const exit = canBeChainHop(model, hops.exit);
  if (!entry && !exit) return "两跳均不可用";
  if (!entry) return "前置节点不可用";
  if (!exit) return "落地节点不可用";
  if (nodeKey(hops.entry) === nodeKey(hops.exit)) return "两跳不能相同";
}
