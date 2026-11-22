import { ListenerNodeDialog } from "./ListenerNodeDialog";
import { fieldErrors, type FieldErrors } from "../lib/validation";
import { HIDDEN_PORT_MAX, HIDDEN_PORT_MIN } from "../lib/hidden";
import {
  Alert,
  Box,
  Button,
  Checkbox,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  MenuItem,
  Stack,
  Switch,
  TextField,
  ToggleButton,
  ToggleButtonGroup,
  Tooltip,
  Typography,
} from "@mui/material";
import { useState } from "react";
import {
  errorMessage,
  isValidationError,
  useModel,
  useSaveProxy,
} from "../api/client";
import type {
  Exit,
  ExitKind,
  GroupStrategy,
  Listener,
  ListenerType,
  NodeRef,
  PortRule,
  RuleAction,
} from "../bindings";
import { expandMembers, nodeKey, nodeLabel } from "../lib/refs";
import { FormDialog } from "../components/FormDialog";
import { InterfacePicker } from "../components/InterfacePicker";
import { MemberPicker } from "../components/MemberPicker";
import { NodePicker } from "../components/NodePicker";
import { ACTION_LABELS, MATCH_LABELS, RULE_ACTIONS, RULE_MATCHERS } from "../lib/sharedRouting";

// `existing` must only contain visible listeners; candidates skip the hidden port range.
function proposePort(existing: Listener[]) {
  if (!existing.length) return 7881;
  const max = Math.max(...existing.map((l) => l.port));
  const used = new Set(existing.map((l) => l.port));
  const inHidden = (p: number) => p >= HIDDEN_PORT_MIN && p <= HIDDEN_PORT_MAX;
  if (max < 65535) {
    const c = max + 1;
    return inHidden(c) ? HIDDEN_PORT_MAX + 1 : c;
  }
  for (let p = 1024; p <= 65535; p++) if (!used.has(p) && !inHidden(p)) return p;
  return 7881;
}
export function newListener(existing: Listener[]): Listener {
  return {
    id: crypto.randomUUID(),
    name: "",
    listener_type: "Mixed",
    listen: "127.0.0.1",
    port: proposePort(existing),
    auth: null,
    exit: null,
    user_enabled: true,
  };
}
export function ListenerDialog({
  listener,
  onClose,
  onSaved,
  initialNode,
}: {
  listener: Listener;
  onClose: () => void;
  onSaved?: (l: Listener) => void;
  initialNode?: NodeRef;
}) {
  const model = useModel();
  const [errs, setErrs] = useState<FieldErrors>({ form: [] });
  const [showPw, setShowPw] = useState(false);
  const save = useSaveProxy();
  const m = model.data;
  const [l, setL] = useState(listener);
  const [port, setPort] = useState(String(l.port));
  const ipv6Listen = l.listen.includes(":");
  const allowLan = !["127.0.0.1", "::1", "[::1]", "localhost"].includes(
    l.listen,
  );
  const [error, setError] = useState("");
  const [target, setTarget] = useState<Exit>(
    () =>
      m?.exits.find((e) => e.id === l.exit) ?? {
        id: `proxy-${l.id}`,
        name: `代理-${l.id}`,
        interface: null,
        kind: initialNode ? { Node: { node: initialNode } } : "Direct",
      },
  );
  const [mode, setMode] = useState(
    l.routing ? "rules" : target.kind === "Direct" ? "direct" : "forward",
  );
  const [kind, setKind] = useState<"Node" | "Group">(
    typeof target.kind === "object" && "Group" in target.kind
      ? "Group"
      : "Node",
  );
  const [node, setNode] = useState<NodeRef | null>(
    typeof target.kind === "object" && "Node" in target.kind
      ? target.kind.Node.node
      : (initialNode ?? null),
  );
  const [group, setGroup] = useState(
    typeof target.kind === "object" && "Group" in target.kind
      ? target.kind.Group
      : { strategy: "UrlTest" as GroupStrategy, members: [], selected: null },
  );
  const [rules, setRules] = useState<PortRule[]>(l.routing?.rules ?? []);
  const shared = m?.shared_rules?.filter((r) => r.enabled) ?? [];
  const providers = m?.shared_rule_providers ?? [];
  const inherits = !!l.inherit_shared_rules;
  const [unmatched, setUnmatched] = useState<RuleAction>(
    l.routing?.unmatched ?? "Proxy",
  );
  const [choosingNode, setChoosingNode] = useState(false);
  const [probe, setProbe] = useState("");
  const [probeResult, setProbeResult] = useState("");
  const submit = async () => {
    if (!l.name.trim()) {
      setErrs({ form: [], name: "名称不能为空" });
      return;
    }
    const p = Number(port);
    if (!Number.isInteger(p) || p < 1 || p > 65535) {
      setError("端口需在 1–65535 之间");
      return;
    }
    let destination: ExitKind = "Direct";
    if (mode !== "direct") {
      if (kind === "Node") {
        if (!node) {
          setError("请选择节点");
          return;
        }
        destination = { Node: { node } };
      } else {
        if (!group.members.length) {
          setError("请选择策略成员");
          return;
        }
        if (
          group.strategy === "Select" &&
          group.selected &&
          m &&
          !expandMembers(m, group.members).some(
            (r) => nodeKey(r) === nodeKey(group.selected!),
          )
        ) {
          setError("当前节点需属于策略组成员");
          return;
        }
        destination = { Group: group };
      }
    }
    const next = {
      ...l,
      name: l.name.trim(),
      listen: allowLan
        ? ipv6Listen
          ? "::"
          : "0.0.0.0"
        : ipv6Listen
          ? "::1"
          : "127.0.0.1",
      port: p,
      routing: mode === "rules" ? { rules, unmatched } : null,
      inherit_shared_rules: inherits,
    };
    try {
      await save.mutateAsync(next, { ...target, kind: destination });
      onSaved?.({ ...next, exit: `proxy-${l.id}` });
      onClose();
    } catch (e) {
      if (isValidationError(e)) setErrs(fieldErrors(e.errors));
      else setError(errorMessage(e));
    }
  };
  const verify = () => {
    const input = probe.trim().toLowerCase();
    if (!input) {
      setProbeResult("请输入域名或 IPv4 地址");
      return;
    }
    const ordered = [
      ...rules.map((rule) => ({ rule, source: "端口规则" })),
      ...(inherits ? shared.map((rule) => ({ rule, source: "共享规则" })) : []),
    ];
    const ipv4 = (value: string) => {
      if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) return null;
      const octets = value.split(".").map(Number);
      return octets.some((part) => part > 255)
        ? null : octets.reduce((a, b) => (a * 256 + b) >>> 0, 0);
    };
    for (const { rule, source } of ordered) {
      const v = rule.value.toLowerCase();
      let hit: boolean;
      if (rule.matcher === "Domain") hit = input === v;
      else if (rule.matcher === "DomainSuffix") hit = input === v || input.endsWith(`.${v}`);
      else if (rule.matcher === "Ipv4Cidr") {
        const inputIp = ipv4(input);
        if (inputIp === null) {
          setProbeResult(`${source}的 IPv4 CIDR 需要内核解析目标的 IP，此处无法离线验证。`);
          return;
        }
        const [ip, prefix] = v.split("/");
        const network = ipv4(ip), bits = Number(prefix);
        hit = network !== null && !!prefix && Number.isInteger(bits) && bits >= 0 && bits <= 32
          && (bits === 0 || inputIp >>> (32 - bits) === network >>> (32 - bits));
      } else {
        setProbeResult(`${source}的 ${MATCH_LABELS[rule.matcher]} 由内核匹配，此处无法离线验证。`);
        return;
      }
      if (hit) {
        setProbeResult(`匹配 ${source}：${rule.value} → ${ACTION_LABELS[rule.action]}`);
        return;
      }
    }
    setProbeResult(inherits && !m ? "正在读取共享规则，无法验证未匹配去向。"
      : `未匹配规则 → ${ACTION_LABELS[unmatched]}`);
  };
  return (
    <>
      <FormDialog onClose={onClose} fullWidth maxWidth="sm">
        <DialogTitle>
          {m?.listeners.some((x) => x.id === l.id) ? "编辑代理" : "新增代理"}
        </DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 1 }}>
            {error && <Alert severity="error">{error}</Alert>}
            {errs.form.map((msg) => (
              <Alert severity="error" key={msg}>
                {msg}
              </Alert>
            ))}
            <TextField
              label="名称"
              value={l.name}
              error={!!errs.name}
              helperText={errs.name}
              onChange={(e) => {
                setL({ ...l, name: e.target.value });
                setErrs({ ...errs, name: undefined });
              }}
            />
            <TextField
              label="端口"
              type="number"
              value={port}
              error={!!errs.port}
              helperText={errs.port}
              onChange={(e) => {
                setPort(e.target.value);
                setErrs({ ...errs, port: undefined });
                setError("");
              }}
            />
            <TextField
              select
              label="协议"
              value={l.listener_type}
              onChange={(e) =>
                setL({ ...l, listener_type: e.target.value as ListenerType })
              }
            >
              {[
                ["Mixed", "Mixed（HTTP + SOCKS5）"],
                ["Http", "HTTP"],
                ["Socks", "SOCKS5"],
              ].map(([v, t]) => (
                <MenuItem key={v} value={v}>
                  {t}
                </MenuItem>
              ))}
            </TextField>
            <Box>
              <Typography variant="body2" sx={{ mb: 1 }}>
                流量处理
              </Typography>
              <ToggleButtonGroup
                exclusive
                fullWidth
                value={mode}
                onChange={(_, v) => v && setMode(v)}
              >
                {[
                  ["rules", "规则分流"],
                  ["forward", "统一转发"],
                  ["direct", "直连"],
                ].map(([v, t]) => (
                  <ToggleButton key={v} value={v}>
                    {t}
                  </ToggleButton>
                ))}
              </ToggleButtonGroup>
            </Box>
            <Box>
              <FormControlLabel label="继承共享规则" control={
                <Checkbox checked={inherits} onChange={(_, inherit_shared_rules) => {
                  setL({ ...l, inherit_shared_rules });
                  setProbeResult("");
                }} />
              } />
              {inherits && (
                <Tooltip title={mode === "direct" ? "共享规则中的「代理」使用此端口现有的直连出口。" : ""}>
                  <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                    {mode === "rules"
                      ? "匹配顺序：端口规则 → 共享规则 → 未匹配去向"
                      : mode === "direct"
                        ? "匹配顺序：共享规则 → 直连"
                        : "匹配顺序：共享规则 → 统一转发"}
                    {m && !shared.length ? "（暂无启用的共享规则）" : ""}
                  </Typography>
                </Tooltip>
              )}
            </Box>
            {mode !== "direct" && (
              <>
                <TextField
                  select
                  label="去向"
                  value={kind}
                  onChange={(e) => setKind(e.target.value as "Node" | "Group")}
                >
                  <MenuItem value="Node">单个节点</MenuItem>
                  <MenuItem value="Group">策略组</MenuItem>
                </TextField>
                {kind === "Node" ? (
                  <NodePicker value={node} onChange={setNode} />
                ) : (
                  <>
                    <TextField
                      select
                      label="策略"
                      value={group.strategy}
                      onChange={(e) =>
                        setGroup({
                          ...group,
                          strategy: e.target.value as GroupStrategy,
                        })
                      }
                    >
                      {[
                        ["UrlTest", "自动测速"],
                        ["Fallback", "故障转移"],
                        ["LoadBalance", "负载均衡"],
                        ["Select", "手动选择"],
                      ].map(([v, t]) => (
                        <MenuItem key={v} value={v}>
                          {t}
                        </MenuItem>
                      ))}
                    </TextField>
                    <MemberPicker
                      value={group.members}
                      onChange={(members) => setGroup({ ...group, members })}
                    />
                    {group.strategy === "Select" && (
                      <Box>
                        <Typography variant="body2" sx={{ mb: 1 }}>
                          已选节点
                        </Typography>
                        <Button
                          variant="outlined"
                          fullWidth
                          onClick={() => setChoosingNode(true)}
                        >
                          {group.selected && m
                            ? nodeLabel(m, group.selected)
                            : "选择节点"}
                        </Button>
                      </Box>
                    )}
                  </>
                )}
              </>
            )}
            {mode === "rules" && (
              <>
                <Typography variant="subtitle2">端口规则（按顺序匹配）</Typography>
                {rules.map((r, i) => (
                  <Box
                    key={i}
                    sx={{
                      p: 1.5,
                      border: 1,
                      borderColor: "divider",
                      borderRadius: 1,
                    }}
                  >
                    <Stack spacing={1}>
                      <TextField
                        select
                        label="匹配类型"
                        value={r.matcher}
                        onChange={(e) =>
                          setRules(
                            rules.map((x, j) =>
                              j === i
                                ? {
                                    ...x,
                                    matcher: e.target.value as PortRule["matcher"],
                                    value: e.target.value === "RuleSet" || x.matcher === "RuleSet" ? "" : x.value,
                                  }
                                : x,
                            ),
                          )
                        }
                      >
                        {RULE_MATCHERS.map(([v, t]) => (
                          <MenuItem key={v} value={v}>
                            {t}
                          </MenuItem>
                        ))}
                      </TextField>
                      {r.matcher === "RuleSet" ? (
                        <TextField select label="匹配内容" value={r.value}
                          helperText={!providers.length ? "先在「共享规则」中导入规则集" : undefined}
                          onChange={(e) => setRules(rules.map((x, j) => j === i ? { ...x, value: e.target.value } : x))}>
                          <MenuItem value="" disabled>选择规则集</MenuItem>
                          {r.value && !providers.some((p) => p.name === r.value) && <MenuItem value={r.value} disabled>{r.value}（未导入）</MenuItem>}
                          {providers.map((p) => <MenuItem key={p.name} value={p.name}>{p.name}</MenuItem>)}
                        </TextField>
                      ) : (
                        <TextField label="匹配内容" value={r.value}
                          onChange={(e) => setRules(rules.map((x, j) => j === i ? { ...x, value: e.target.value.trim() } : x))} />
                      )}
                      <TextField
                        select
                        label="处理方式"
                        value={r.action}
                        onChange={(e) =>
                          setRules(
                            rules.map((x, j) =>
                              j === i
                                ? { ...x, action: e.target.value as RuleAction }
                                : x,
                            ),
                          )
                        }
                      >
                        {RULE_ACTIONS.map(([v, t]) => (
                          <MenuItem key={v} value={v}>
                            {t}
                          </MenuItem>
                        ))}
                      </TextField>
                      <Button
                        color="error"
                        onClick={() =>
                          setRules(rules.filter((_, j) => j !== i))
                        }
                      >
                        移除规则
                      </Button>
                    </Stack>
                  </Box>
                ))}
                <Button
                  onClick={() =>
                    setRules([
                      ...rules,
                      { matcher: "DomainSuffix", value: "", action: "Proxy" },
                    ])
                  }
                >
                  添加规则
                </Button>
                <TextField
                  select
                  label="未匹配去向"
                  value={unmatched}
                  onChange={(e) => setUnmatched(e.target.value as RuleAction)}
                >
                  {RULE_ACTIONS.map(([v, t]) => (
                    <MenuItem key={v} value={v}>
                      {t}
                    </MenuItem>
                  ))}
                </TextField>
                <Box component="details">
                  <summary>验证规则</summary>
                  <Stack spacing={1} sx={{ mt: 1 }}>
                    <TextField
                      label="域名或 IPv4 地址"
                      value={probe}
                      onChange={(e) => setProbe(e.target.value)}
                    />
                    <Button onClick={verify}>验证</Button>
                    {rules.some((r) => r.matcher === "Ipv4Cidr") && (
                      <Typography variant="caption" color="text.secondary">
                        域名解析后的 IP 规则请使用解析地址验证。
                      </Typography>
                    )}
                    <Typography>{probeResult}</Typography>
                  </Stack>
                </Box>
              </>
            )}
            <Box component="details">
              <summary>高级选项</summary>
              <Stack spacing={2} sx={{ mt: 2 }}>
                <FormControlLabel
                  label="启用代理"
                  control={
                    <Switch
                      checked={l.user_enabled}
                      onChange={(_, v) => setL({ ...l, user_enabled: v })}
                    />
                  }
                />
                <FormControlLabel
                  label="允许局域网"
                  control={
                    <Switch
                      checked={allowLan}
                      onChange={(_, v) =>
                        setL({
                          ...l,
                          listen: v
                            ? ipv6Listen
                              ? "::"
                              : "0.0.0.0"
                            : ipv6Listen
                              ? "::1"
                              : "127.0.0.1",
                        })
                      }
                    />
                  }
                />
                <InterfacePicker
                  label="出站网卡"
                  value={target.interface}
                  onChange={(value) =>
                    setTarget({ ...target, interface: value })
                  }
                />
                <FormControlLabel
                  label="启用认证"
                  control={
                    <Switch
                      checked={!!l.auth}
                      onChange={(_, v) =>
                        setL({
                          ...l,
                          auth: v ? { username: "", password: "" } : null,
                        })
                      }
                    />
                  }
                />
                {l.auth && (
                  <>
                    <TextField
                      label="用户名"
                      value={l.auth.username}
                      onChange={(e) =>
                        setL({
                          ...l,
                          auth: { ...l.auth!, username: e.target.value },
                        })
                      }
                    />
                    <TextField
                      label="密码"
                      type={showPw ? "text" : "password"}
                      slotProps={{
                        input: {
                          endAdornment: (
                            <Button
                              size="small"
                              onClick={() => setShowPw(!showPw)}
                            >
                              {showPw ? "隐藏" : "显示"}
                            </Button>
                          ),
                        },
                      }}
                      value={l.auth.password}
                      onChange={(e) =>
                        setL({
                          ...l,
                          auth: { ...l.auth!, password: e.target.value },
                        })
                      }
                    />
                  </>
                )}
              </Stack>
            </Box>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={onClose}>取消</Button>
          <Button
            variant="contained"
            disabled={save.isPending}
            onClick={() => void submit()}
          >
            保存
          </Button>
        </DialogActions>
      </FormDialog>
      {choosingNode && (
        <ListenerNodeDialog
          exitId={target.id}
          listenerName={l.name || "新代理"}
          draft={{ members: group.members, selected: group.selected }}
          onSelect={(selected, members) => setGroup({ ...group, members, selected })}
          onClose={() => setChoosingNode(false)}
        />
      )}
    </>
  );
}
