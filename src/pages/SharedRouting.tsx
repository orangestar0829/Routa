import Add from "@mui/icons-material/Add";
import ArrowDownward from "@mui/icons-material/ArrowDownward";
import ArrowUpward from "@mui/icons-material/ArrowUpward";
import DeleteOutline from "@mui/icons-material/DeleteOutlined";
import EditOutlined from "@mui/icons-material/EditOutlined";
import HelpOutline from "@mui/icons-material/HelpOutlineOutlined";
import ListAltOutlined from "@mui/icons-material/ListAltOutlined";
import {
  Alert, Box, Button, Checkbox, Chip, CircularProgress, DialogActions, DialogContent,
  DialogTitle, Divider, FormControlLabel, IconButton, MenuItem, Paper, Stack, Switch,
  Tab, Table, TableBody, TableCell, TableHead, TableRow, Tabs, TextField, Tooltip, Typography,
} from "@mui/material";
import { useMemo, useRef, useState, type ReactNode } from "react";
import { errorMessage, isValidationError, useModel, useSaveSharedRouting, validationText } from "../api/client";
import type { RuleAction, RuleMatch, SharedRule, SharedRuleProvider } from "../bindings";
import { EmptyState } from "../components/EmptyState";
import { FormDialog } from "../components/FormDialog";
import { useApplyResult } from "../components/ApplyResultSnackbar";
import { applyOutcomeMessages } from "../lib/format";
import { visibleListeners } from "../lib/hidden";
import {
  ACTION_LABELS, MAINLAND_DIRECT, MATCH_LABELS, PROVIDER_BEHAVIORS, PROVIDER_FORMATS,
  RULE_ACTIONS, RULE_MATCHERS, RULE_VALUE_EXAMPLES,
} from "../lib/sharedRouting";

type RuleRow = { id: number; rule: SharedRule };
type Draft = { rules: RuleRow[]; providers: SharedRuleProvider[] };

const TEMPLATE: SharedRule = { enabled: true, matcher: "DomainSuffix", value: "", action: "Proxy" };
const PROVIDER_TEMPLATE: SharedRuleProvider = {
  name: "", url: "", behavior: "Classical", format: "Yaml", interval: 86400,
};
const actionColor = { Direct: "success", Proxy: "primary", Reject: "error" } as const;
const panelHeight = { height: "clamp(280px, calc(100dvh - 252px), 640px)", overflow: "auto", scrollbarGutter: "stable" };

function Info({ text }: { text: string }) {
  return <Tooltip title={text}><IconButton size="small" aria-label={text}>
    <HelpOutline fontSize="small" />
  </IconButton></Tooltip>;
}

function RowButton({ label, children, onClick, disabled }: {
  label: string; children: ReactNode; onClick: () => void; disabled?: boolean;
}) {
  return <Tooltip title={label}><span>
    <IconButton size="small" aria-label={label} onClick={onClick} disabled={disabled}>{children}</IconButton>
  </span></Tooltip>;
}

function RuleEditor({ existing, providers, onSave, onClose }: {
  existing?: SharedRule; providers: SharedRuleProvider[]; onSave: (rule: SharedRule) => void; onClose: () => void;
}) {
  const [rule, setRule] = useState(existing ?? TEMPLATE);
  const [err, setErr] = useState<string>();
  const missingProvider = rule.matcher === "RuleSet" && !providers.some((p) => p.name === rule.value);
  const save = () => {
    const value = rule.value.trim();
    if (!value && rule.matcher !== "RuleSet") {
      setErr("请输入匹配内容");
      return;
    }
    if (rule.matcher === "RuleSet" && missingProvider && (rule.enabled || !value)) {
      setErr("请选择已导入的规则集");
      return;
    }
    onSave({ ...rule, value });
  };

  return <FormDialog fullWidth maxWidth="xs" onClose={onClose} aria-labelledby="shared-rule-title">
    <DialogTitle id="shared-rule-title">{existing ? "编辑共享规则" : "新增共享规则"}</DialogTitle>
    <DialogContent>
      <Stack spacing={2} sx={{ pt: 0.5 }}>
        <TextField select label="匹配类型" value={rule.matcher} onChange={(e) => {
          const matcher = e.target.value as RuleMatch;
          setRule({ ...rule, matcher, value: matcher === "RuleSet" || rule.matcher === "RuleSet" ? "" : rule.value });
          setErr(undefined);
        }}>
          {RULE_MATCHERS.map(([value, label]) => <MenuItem key={value} value={value}>{label}</MenuItem>)}
        </TextField>
        {rule.matcher === "RuleSet" ? (
          <TextField select label="匹配内容" value={rule.value} error={!!err}
            helperText={err ?? (providers.length === 0 ? "先在「规则集」中导入来源" : undefined)}
            onChange={(e) => { setRule({ ...rule, value: e.target.value }); setErr(undefined); }}>
            <MenuItem value="" disabled>选择规则集</MenuItem>
            {rule.value && missingProvider && <MenuItem value={rule.value} disabled>{rule.value}（未导入）</MenuItem>}
            {providers.map((p) => <MenuItem key={p.name} value={p.name}>{p.name}</MenuItem>)}
          </TextField>
        ) : (
          <TextField label="匹配内容" value={rule.value} placeholder={RULE_VALUE_EXAMPLES[rule.matcher]}
            error={!!err} helperText={err} onChange={(e) => { setRule({ ...rule, value: e.target.value }); setErr(undefined); }} />
        )}
        <TextField select label="处理方式" value={rule.action}
          onChange={(e) => setRule({ ...rule, action: e.target.value as RuleAction })}>
          {RULE_ACTIONS.map(([value, label]) => <MenuItem key={value} value={value}>{label}</MenuItem>)}
        </TextField>
        <FormControlLabel label="启用规则" control={<Switch checked={rule.enabled}
          onChange={(_, enabled) => setRule({ ...rule, enabled })} />} />
      </Stack>
    </DialogContent>
    <DialogActions>
      <Button onClick={onClose}>取消</Button>
      <Button variant="contained" onClick={save}>保存</Button>
    </DialogActions>
  </FormDialog>;
}

function ProviderEditor({ existing, providers, onSave, onClose }: {
  existing?: SharedRuleProvider; providers: SharedRuleProvider[];
  onSave: (provider: SharedRuleProvider, action?: RuleAction) => void; onClose: () => void;
}) {
  const [provider, setProvider] = useState(existing ?? PROVIDER_TEMPLATE);
  const [interval, setInterval] = useState(String(provider.interval));
  const [attach, setAttach] = useState(!existing);
  const [action, setAction] = useState<RuleAction>("Proxy");
  const [errs, setErrs] = useState<{ name?: string; url?: string; interval?: string }>({});
  const invalidFormat = provider.format === "Mrs" && provider.behavior === "Classical";
  const submit = () => {
    const name = provider.name.trim(), url = provider.url.trim(), seconds = Number(interval);
    const next: typeof errs = {};
    if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(name)) next.name = "1–64 位字母、数字、点、下划线或连字符，须以字母或数字开头";
    else if (!existing && providers.some((p) => p.name === name)) next.name = "规则集名称已存在";
    try {
      const address = new URL(url);
      if (!["https:", "http:"].includes(address.protocol) || !address.hostname || address.username || address.password || url.includes("#")) throw new Error();
    } catch { next.url = "输入不含凭据或片段的 HTTP(S) 地址"; }
    if (!interval.trim() || !Number.isInteger(seconds) || seconds < 60 || seconds > 31536000) next.interval = "刷新间隔须为 60–31536000 秒";
    setErrs(next);
    if (Object.keys(next).length || invalidFormat) return;
    onSave({ ...provider, name, url, interval: seconds }, attach ? action : undefined);
  };

  return <FormDialog fullWidth maxWidth="xs" onClose={onClose} aria-labelledby="shared-provider-title">
    <DialogTitle id="shared-provider-title">{existing ? "编辑规则集" : "导入规则集"}</DialogTitle>
    <DialogContent>
      <Stack spacing={2} sx={{ pt: 0.5 }}>
        <TextField label="规则集名称" value={provider.name} disabled={!!existing}
          error={!!errs.name} helperText={errs.name} placeholder="my-rules"
          onChange={(e) => { setProvider({ ...provider, name: e.target.value }); setErrs({ ...errs, name: undefined }); }} />
        <TextField label="远程地址" value={provider.url} placeholder="https://example.com/rules.yaml"
          error={!!errs.url} helperText={errs.url ?? (/^http:\/\//i.test(provider.url) ? "来源走直连；HTTP 未加密，建议使用 HTTPS" : "更新规则集时直连来源，不走代理端口")}
          onChange={(e) => { setProvider({ ...provider, url: e.target.value }); setErrs({ ...errs, url: undefined }); }} />
        <TextField select label="规则类型" value={provider.behavior}
          onChange={(e) => setProvider({ ...provider, behavior: e.target.value as SharedRuleProvider["behavior"] })}>
          {Object.entries(PROVIDER_BEHAVIORS).map(([value, label]) => <MenuItem key={value} value={value}>{label}</MenuItem>)}
        </TextField>
        <TextField select label="文件格式" value={provider.format} error={invalidFormat}
          helperText={invalidFormat ? "MRS 仅适用于域名或 IP 网段" : undefined}
          onChange={(e) => setProvider({ ...provider, format: e.target.value as SharedRuleProvider["format"] })}>
          {Object.entries(PROVIDER_FORMATS).map(([value, label]) => <MenuItem key={value} value={value}>{label}</MenuItem>)}
        </TextField>
        <TextField label="刷新间隔（秒）" type="number" value={interval} error={!!errs.interval}
          helperText={errs.interval} slotProps={{ htmlInput: { min: 60, max: 31536000 } }}
          onChange={(e) => { setInterval(e.target.value); setErrs({ ...errs, interval: undefined }); }} />
        {!existing && <>
          <FormControlLabel label="同时添加共享规则" control={<Checkbox checked={attach}
            onChange={(_, checked) => setAttach(checked)} />} />
          <TextField select label="处理方式" value={action} disabled={!attach}
            onChange={(e) => setAction(e.target.value as RuleAction)}>
            {RULE_ACTIONS.map(([value, label]) => <MenuItem key={value} value={value}>{label}</MenuItem>)}
          </TextField>
        </>}
      </Stack>
    </DialogContent>
    <DialogActions>
      <Button onClick={onClose}>取消</Button>
      <Button variant="contained" onClick={submit}>{existing ? "保存" : "导入"}</Button>
    </DialogActions>
  </FormDialog>;
}

function sourceHost(url: string) {
  try { return new URL(url).host; } catch { return "—"; }
}

function sameConfig(rules: SharedRule[], providers: SharedRuleProvider[], savedRules: SharedRule[], savedProviders: SharedRuleProvider[]) {
  return rules.length === savedRules.length && providers.length === savedProviders.length
    && rules.every((r, i) => {
      const saved = savedRules[i];
      return r.matcher === saved.matcher && r.value === saved.value && r.action === saved.action && r.enabled === saved.enabled;
    })
    && providers.every((p, i) => {
      const saved = savedProviders[i];
      return p.name === saved.name && p.url === saved.url && p.behavior === saved.behavior
        && p.format === saved.format && p.interval === saved.interval;
    });
}

export function SharedRoutingPage() {
  const model = useModel();
  const save = useSaveSharedRouting({ errorFeedback: "local" });
  const feedback = useApplyResult();
  const [tab, setTab] = useState<"rules" | "providers">("rules");
  const [draft, setDraft] = useState<Draft | null>(null);
  const [editor, setEditor] = useState<{ type: "rule"; id?: number } | { type: "provider"; name?: string } | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [note, setNote] = useState("");
  const nextId = useRef(-1);
  const current = useMemo<Draft>(() => ({
    rules: model.data?.shared_rules?.map((rule, id) => ({ id, rule })) ?? [],
    providers: model.data?.shared_rule_providers ?? [],
  }), [model.data?.shared_rules, model.data?.shared_rule_providers]);
  const { rules, providers } = draft ?? current;
  const watchers = model.data ? visibleListeners(model.data).filter((l) => l.inherit_shared_rules).length : 0;
  const locked = saving || !model.data;
  const update = (next: Draft) => { setDraft(next); setError(""); setNote(""); };
  const add = (rule: SharedRule): RuleRow => ({ id: nextId.current--, rule });
  const move = (idx: number, delta: number) => {
    const reordered = [...rules];
    [reordered[idx], reordered[idx + delta]] = [reordered[idx + delta], reordered[idx]];
    update({ providers, rules: reordered });
  };
  const preset = () => {
    const existing = (rule: SharedRule) => rules.find(({ rule: r }) =>
      r.matcher === rule.matcher && r.value.toLowerCase() === rule.value.toLowerCase());
    const added = MAINLAND_DIRECT.filter((rule) => !existing(rule)).map(add);
    if (added.length) update({ providers, rules: [...rules, ...added] });
    if (MAINLAND_DIRECT.some((rule) => {
      const before = existing(rule)?.rule;
      return before && (before.action !== "Direct" || !before.enabled);
    })) setNote("保留了已有的同类规则；如需直连，请检查这些规则的状态和去向。");
    else if (!added.length) setNote("中国大陆直连规则已存在。");
  };
  const apply = async () => {
    if (!draft || locked) return;
    setSaving(true);
    setError("");
    try {
      const submitted = rules.map(({ rule }) => rule);
      const result = await save.mutateAsync(submitted, providers);
      const refreshed = await model.refetch({ cancelRefetch: false });
      if (refreshed.isError) {
        setError("保存后未能读取配置，请重试加载。");
      } else if ("FailedCoreStopped" in result && !sameConfig(
        submitted, providers, refreshed.data?.shared_rules ?? [], refreshed.data?.shared_rule_providers ?? [],
      )) {
        setError("内核已停止，未能确认共享规则已保存。");
      } else {
        setDraft(null);
        setNote("");
        if ("Reloaded" in result && applyOutcomeMessages(result).length === 0) {
          feedback.showMessage("共享规则已保存并应用", "success");
        }
      }
    } catch (e) {
      setError(isValidationError(e)
        ? e.errors.map((item) => "InvalidProxy" in item
          ? `${item.InvalidProxy.name}：${item.InvalidProxy.reason}` : validationText([item])).join("\n")
        : errorMessage(e));
    } finally {
      setSaving(false);
    }
  };
  const referenced = (provider: string) => rules.some(({ rule }) => rule.matcher === "RuleSet" && rule.value === provider)
    || !!model.data?.listeners.some((l) => l.routing?.rules.some((r) => r.matcher === "RuleSet" && r.value === provider));

  return <Stack spacing={2}>
    <Stack direction="row" sx={{ alignItems: "center", justifyContent: "space-between", gap: 2, flexWrap: "wrap" }}>
      <Stack direction="row" spacing={0.75} sx={{ alignItems: "center" }}>
        <Typography variant="h5" component="h1">共享规则</Typography>
        <Info text="对主动继承的代理生效：端口规则 → 共享规则 → 未匹配去向。每组规则从上到下，命中即停止。" />
      </Stack>
      <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
        <Button disabled={!draft || locked} onClick={() => { setDraft(null); setNote(""); setError(""); }}>还原更改</Button>
        <Button variant="contained" loading={saving} disabled={!draft || locked} onClick={() => void apply()}>保存并应用</Button>
      </Stack>
    </Stack>
    <Paper sx={{ minWidth: 0 }}>
      <Stack direction="row" sx={{ px: 2, alignItems: "center", justifyContent: "space-between", gap: 1, flexWrap: "wrap" }}>
        <Tabs value={tab} onChange={(_, value: typeof tab) => setTab(value)} aria-label="共享规则分类" sx={{ minHeight: 48 }}>
          <Tab value="rules" label="规则" id="shared-tab-rules" aria-controls="shared-panel-rules" />
          <Tab value="providers" label="规则集" id="shared-tab-providers" aria-controls="shared-panel-providers" />
        </Tabs>
        <Typography variant="caption" color="text.secondary">{watchers} 个代理继承</Typography>
      </Stack>
      <Divider />
      <Box id={`shared-panel-${tab}`} role="tabpanel" aria-labelledby={`shared-tab-${tab}`}>
        <Stack direction="row" sx={{ px: 2, py: 1, minHeight: 52, gap: 1, alignItems: "center", justifyContent: "space-between", flexWrap: "wrap" }}>
          <Typography variant="subtitle2">{tab === "rules" ? "按顺序匹配" : "远程规则集"}</Typography>
          {tab === "rules" ? <Stack direction="row" spacing={1}>
            <Button size="small" variant="outlined" disabled={locked} onClick={preset}>中国大陆直连</Button>
            <Button size="small" variant="contained" startIcon={<Add />} disabled={locked} onClick={() => setEditor({ type: "rule" })}>新增规则</Button>
          </Stack> : <Button size="small" variant="contained" startIcon={<Add />} disabled={locked} onClick={() => setEditor({ type: "provider" })}>导入规则集</Button>}
        </Stack>
        <Divider />
        <Box sx={panelHeight}>
          {error && <Alert severity="error" sx={{ mx: 2, mt: 1, whiteSpace: "pre-line" }}>{error}</Alert>}
          {note && <Alert severity="info" sx={{ mx: 2, mt: 1 }} onClose={() => setNote("")}>{note}</Alert>}
          {!model.data ? <Box sx={{ p: 4, textAlign: "center" }}>
            {model.isError
              ? <Alert severity="error" action={<Button onClick={() => void model.refetch()}>重试</Button>}>{errorMessage(model.error)}</Alert>
              : <CircularProgress size={24} aria-label="正在读取共享规则" />}
          </Box> : tab === "rules" ? (
            rules.length ? <Table size="small" stickyHeader aria-label="共享规则列表">
              <TableHead><TableRow>
                <TableCell sx={{ width: 48 }}>顺序</TableCell><TableCell>匹配条件</TableCell>
                <TableCell sx={{ width: 72 }}>去向</TableCell><TableCell sx={{ width: 56 }}>启用</TableCell>
                <TableCell align="right" sx={{ width: 148 }}>操作</TableCell>
              </TableRow></TableHead>
              <TableBody>{rules.map(({ rule, id }, index) => {
                const label = `第 ${index + 1} 条规则`;
                return <TableRow key={id} hover>
                  <TableCell sx={{ color: "text.secondary" }}>{index + 1}</TableCell>
                  <TableCell sx={{ overflowWrap: "anywhere" }}>
                    <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>{MATCH_LABELS[rule.matcher]}</Typography>
                    <Typography variant="body2" data-selectable="true">{rule.value || "—"}</Typography>
                  </TableCell>
                  <TableCell><Chip size="small" variant="outlined" color={actionColor[rule.action]} label={ACTION_LABELS[rule.action]} /></TableCell>
                  <TableCell><Switch size="small" checked={rule.enabled} disabled={locked}
                    slotProps={{ input: { "aria-label": `启用${label}` } }}
                    onChange={(_, enabled) => update({ providers, rules: rules.map((r) => r.id === id ? { id, rule: { ...rule, enabled } } : r) })} /></TableCell>
                  <TableCell align="right" sx={{ whiteSpace: "nowrap" }}>
                    <RowButton label={`上移${label}`} disabled={locked || index === 0} onClick={() => move(index, -1)}><ArrowUpward fontSize="small" /></RowButton>
                    <RowButton label={`下移${label}`} disabled={locked || index === rules.length - 1} onClick={() => move(index, 1)}><ArrowDownward fontSize="small" /></RowButton>
                    <RowButton label={`编辑${label}`} disabled={locked} onClick={() => setEditor({ type: "rule", id })}><EditOutlined fontSize="small" /></RowButton>
                    <RowButton label={`删除${label}`} disabled={locked} onClick={() => update({ providers, rules: rules.filter((r) => r.id !== id) })}><DeleteOutline fontSize="small" /></RowButton>
                  </TableCell>
                </TableRow>;
              })}</TableBody>
            </Table> : <EmptyState icon={<ListAltOutlined />} title="还没有共享规则"
              description="在「代理」中为各端口开启继承后，才会使用这些规则。" />
          ) : (
            providers.length ? <Table size="small" stickyHeader aria-label="远程规则集列表">
              <TableHead><TableRow><TableCell>名称 / 来源</TableCell><TableCell>类型</TableCell><TableCell>格式</TableCell>
                <TableCell align="right">刷新间隔</TableCell><TableCell align="right">操作</TableCell></TableRow></TableHead>
              <TableBody>{providers.map((p) => <TableRow key={p.name} hover>
                <TableCell sx={{ overflowWrap: "anywhere" }}>
                  <Typography variant="body2" data-selectable="true">{p.name}</Typography>
                  <Typography variant="caption" color="text.secondary">{sourceHost(p.url)}</Typography>
                </TableCell>
                <TableCell>{PROVIDER_BEHAVIORS[p.behavior]}</TableCell><TableCell>{PROVIDER_FORMATS[p.format]}</TableCell>
                <TableCell align="right" sx={{ whiteSpace: "nowrap" }}>{p.interval} 秒</TableCell>
                <TableCell align="right" sx={{ whiteSpace: "nowrap" }}>
                  <RowButton label={`编辑规则集 ${p.name}`} disabled={locked} onClick={() => setEditor({ type: "provider", name: p.name })}><EditOutlined fontSize="small" /></RowButton>
                  <RowButton label={referenced(p.name) ? `规则集 ${p.name} 仍被引用` : `删除规则集 ${p.name}`}
                    disabled={locked || referenced(p.name)} onClick={() => update({ rules, providers: providers.filter((source) => source.name !== p.name) })}><DeleteOutline fontSize="small" /></RowButton>
                </TableCell>
              </TableRow>)}</TableBody>
            </Table> : <EmptyState icon={<ListAltOutlined />} title="还没有远程规则集"
              description="可导入远程 RULE-SET，由内核按间隔更新。" />
          )}
        </Box>
      </Box>
      <Divider />
      <Typography component="div" variant="caption" color="text.secondary" sx={{ px: 2, py: 1.25, minHeight: 38 }}>
        {draft ? "尚未保存" : tab === "rules" ? `${rules.filter(({ rule }) => rule.enabled).length} / ${rules.length} 条已启用` : `${providers.length} 个规则集`}
      </Typography>
    </Paper>
    {editor?.type === "rule" && <RuleEditor existing={rules.find((item) => item.id === editor.id)?.rule}
      providers={providers} onClose={() => setEditor(null)} onSave={(rule) => {
        update({ providers, rules: editor.id === undefined ? [...rules, add(rule)] : rules.map((item) => item.id === editor.id ? { ...item, rule } : item) });
        setEditor(null);
      }} />}
    {editor?.type === "provider" && <ProviderEditor existing={providers.find((item) => item.name === editor.name)}
      providers={providers} onClose={() => setEditor(null)} onSave={(provider, action) => {
        update({
          providers: editor.name ? providers.map((p) => p.name === editor.name ? provider : p) : [...providers, provider],
          rules: action ? [...rules, add({ enabled: true, matcher: "RuleSet", value: provider.name, action })] : rules,
        });
        setEditor(null);
      }} />}
  </Stack>;
}
