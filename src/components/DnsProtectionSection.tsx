import Tune from "@mui/icons-material/Tune";
import {
  Alert, Box, Button, Checkbox, Chip, DialogActions, DialogContent, DialogTitle,
  FormControlLabel, MenuItem, Stack, Switch, TextField, Typography,
} from "@mui/material";
import { useId, useRef, useState, type FormEvent } from "react";
import { isValidationError, useStatus, validationText } from "../api/client";
import { useDesktopState } from "../api/desktop";
import { settingsSaveMessage, useSettingsSave } from "../api/settings";
import type { ApplyOutcome, DnsProtection, Model, RuntimeStatus } from "../bindings";
import { applyOutcomeMessages } from "../lib/format";
import { canBeChainHop, chainProblem } from "../lib/proxyChain";
import { nodeLabel } from "../lib/refs";
import { visibleExits, visibleListeners } from "../lib/hidden";
import { BusyLabel } from "./BusyLabel";
import { FormDialog } from "./FormDialog";
import { Row, Section } from "./SettingsSection";

const DOH_PRESETS = [
  { label: "Cloudflare", url: "https://1.1.1.1/dns-query" },
  { label: "Google", url: "https://8.8.8.8/dns-query" },
];

const DEFAULT_DNS: DnsProtection = {
  enabled: false,
  proxy_exit: null,
  direct_dns: "223.5.5.5",
  proxy_doh: DOH_PRESETS[0].url,
  bootstrap_dns: "https://223.5.5.5/dns-query",
  direct_suffixes: [],
  direct_geosite_cn: false,
};

type ExitOption = { id: string; label: string };

function eligibleExits(model: Model): ExitOption[] {
  const listeners = visibleListeners(model);
  return visibleExits(model).flatMap(({ kind, id, name }) => {
    if (name.startsWith("__") || kind === "Direct" || !("Node" in kind)) return [];
    const ref = kind.Node.node;
    const manual = "manual_id" in ref && model.manual_nodes.find(({ id }) => id === ref.manual_id);
    const supported = manual && "Chain" in manual.kind
      ? !chainProblem(model, manual.kind.Chain)
      : canBeChainHop(model, ref);
    if (!supported) return [];
    const owner = listeners.find(({ exit }) => exit === id);
    return [{ id, label: owner ? `${owner.name} · ${nodeLabel(model, ref)}` : name }];
  });
}

type Field = "proxy_exit" | "proxy_doh" | "direct_dns" | "bootstrap_dns" | "direct_suffixes";
type Problems = Partial<Record<Field | "form", string>>;

function DnsProtectionDialog({ initial, exits, onClose, onSaved, tun }: {
  initial: DnsProtection;
  exits: ExitOption[];
  onClose: () => void;
  onSaved: (outcome: ApplyOutcome) => void;
  tun: boolean;
}) {
  const save = useSettingsSave();
  const presetId = useId();
  const [draft, setDraft] = useState(initial);
  const [suffixes, setSuffixes] = useState(initial.direct_suffixes.join("\n"));
  const [errors, setErrors] = useState<Problems>({});
  const pending = useRef(false);
  const fieldsDisabled = save.isPending || !draft.enabled;
  const available = exits.some(({ id }) => id === draft.proxy_exit);
  const unknownExit = !!draft.proxy_exit && !available;

  const update = <K extends Field | "enabled" | "direct_geosite_cn">(key: K, value: DnsProtection[K]) => {
    setDraft((current) => ({ ...current, [key]: value }));
    setErrors((current) => ({ ...current, [key]: undefined, form: undefined }));
  };

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (pending.current) return;
    if (draft.enabled && !available) {
      setErrors({ proxy_exit: exits.length ? "请选择代理 DNS 使用的出口" : "请先为普通代理端口配置支持的节点或代理链" });
      return;
    }
    setErrors({});
    pending.current = true;
    try {
      const outcome = await save.mutateAsync({ dns_protection: {
        ...draft,
        proxy_doh: draft.proxy_doh.trim(),
        direct_dns: draft.direct_dns.trim(),
        bootstrap_dns: draft.bootstrap_dns.trim(),
        direct_suffixes: Array.from(new Set(suffixes.split(/[\s,，]+/).filter(Boolean))),
      } });
      onSaved(outcome);
      onClose();
    } catch (error) {
      setErrors({ form: isValidationError(error)
        ? (error.errors.map((item) => "InvalidProxy" in item && item.InvalidProxy.name === "DNS 分流"
          ? item.InvalidProxy.reason
          : validationText([item])).join("；") || "设置未能应用，请检查配置")
        : settingsSaveMessage(error) });
    } finally {
      pending.current = false;
    }
  }

  return (
    <FormDialog fullWidth maxWidth="sm" busy={save.isPending} onClose={onClose}
      aria-labelledby="dns-protection-title" sx={{ "& .MuiDialog-paper": { height: 680 } }}>
      <DialogTitle id="dns-protection-title">DNS 分流</DialogTitle>
      <Box component="form" noValidate onSubmit={(event) => void submit(event)}
        sx={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
        <DialogContent sx={{ pt: "4px !important" }}>
          <Stack spacing={1.5}>
            <Box sx={{ px: 1.5, py: 0.75, borderRadius: 1, bgcolor: "action.hover", display: "flex", alignItems: "center", justifyContent: "space-between", gap: 1 }}>
              <Box>
                <Typography variant="body2" sx={{ fontWeight: 600 }}>启用 DNS 分流</Typography>
                <Typography variant="caption" color="text.secondary">
                  {tun ? "TUN 正在使用原有 DNS，退出 TUN 后应用此配置。" : "全部普通代理端口共用，不接管系统 DNS。"}
                </Typography>
              </Box>
              <Switch checked={draft.enabled} disabled={save.isPending}
                onChange={(_, checked) => update("enabled", checked)}
                slotProps={{ input: { "aria-label": "启用 DNS 分流" } }} />
            </Box>
            {errors.form && <Alert severity="error">{errors.form}</Alert>}
            <TextField select size="small" label="代理 DNS 出口" value={draft.proxy_exit ?? ""}
              disabled={fieldsDisabled} error={!!errors.proxy_exit}
              helperText={errors.proxy_exit ?? (exits.length ? undefined : "暂无支持的节点或代理链出口")}
              slotProps={{ select: { displayEmpty: true } }}
              onChange={(event) => update("proxy_exit", event.target.value || null)}>
              <MenuItem value="" disabled>请选择</MenuItem>
              {unknownExit && <MenuItem value={draft.proxy_exit!} disabled>上次选择的出口不可用</MenuItem>}
              {exits.map(({ id, label }) => <MenuItem key={id} value={id}>{label}</MenuItem>)}
            </TextField>
            <TextField size="small" label="代理 DNS（DoH）" value={draft.proxy_doh}
              disabled={fieldsDisabled} error={!!errors.proxy_doh}
              helperText={errors.proxy_doh ?? "使用 IP 地址的 HTTPS URL。失败时不切换到直连或系统 DNS。"}
              slotProps={{ htmlInput: { list: presetId } }}
              onChange={(event) => update("proxy_doh", event.target.value)} />
            <datalist id={presetId}>
              {DOH_PRESETS.map(({ url, label }) => <option key={url} value={url} label={label} />)}
            </datalist>
            <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", sm: "1fr 1fr" }, columnGap: 1.5, rowGap: 1.5 }}>
              <TextField size="small" label="直连 DNS" value={draft.direct_dns}
                disabled={fieldsDisabled} error={!!errors.direct_dns}
                helperText={errors.direct_dns ?? "用于下方明确选中的域名"}
                onChange={(event) => update("direct_dns", event.target.value)} />
              <TextField size="small" label="节点引导 DNS" value={draft.bootstrap_dns}
                disabled={fieldsDisabled} error={!!errors.bootstrap_dns}
                helperText={errors.bootstrap_dns ?? "用于解析代理服务器域名"}
                onChange={(event) => update("bootstrap_dns", event.target.value)} />
            </Box>
            <Box>
              <FormControlLabel sx={{ m: 0 }} label="中国大陆域名（GEOSITE:cn）"
                control={<Checkbox size="small" checked={draft.direct_geosite_cn} disabled={fieldsDisabled}
                  onChange={(_, checked) => update("direct_geosite_cn", checked)} />} />
            </Box>
            <TextField multiline rows={2} size="small" label="直连 DNS 后缀" value={suffixes}
              disabled={fieldsDisabled} error={!!errors.direct_suffixes}
              placeholder={"example.cn\ninternal.example"}
              helperText={errors.direct_suffixes ?? "每行一个，匹配域名及子域名；其余域名走代理 DNS。"}
              onChange={(event) => {
                setSuffixes(event.target.value);
                setErrors((current) => ({ ...current, direct_suffixes: undefined, form: undefined }));
              }} />
            <Typography component="div" variant="caption" color="text.secondary"
              sx={{ "& summary": { cursor: "pointer", width: "fit-content" } }}>
              <details>
                <summary>作用范围</summary>
                仅影响 Routa 内核执行的解析（含直连与内核内部流量）；不接管应用或远端代理自行解析，不读取端口规则来选 DNS。首次使用中国大陆域名分类可能需要下载数据；不是按目标 IP 判定。直连和引导 DNS 走默认网络，可填写 IP（UDP，可带端口）或含 IP 地址的 HTTPS URL。DoH 按正常 TLS 规则校验证书，证书必须覆盖 URL 中的 IP。多跳时，后续节点可由前一跳完成解析。
              </details>
            </Typography>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Typography variant="caption" color="text.secondary" sx={{ mr: "auto", pr: 1 }}>
            {tun ? "退出 TUN 后生效" : "应用变更可能中断现有连接"}
          </Typography>
          <Button disabled={save.isPending} onClick={onClose}>取消</Button>
          <Button type="submit" disabled={save.isPending} variant="contained">
            <BusyLabel busy={save.isPending} idle="保存并应用" pending="保存中…" />
          </Button>
        </DialogActions>
      </Box>
    </FormDialog>
  );
}

export function DnsProtectionSection({ model, otherSavePending }: { model: Model; otherSavePending: boolean }) {
  const [editing, setEditing] = useState(false);
  const [notice, setNotice] = useState<{
    warning: boolean;
    failed: boolean;
    text: string;
    previousStatus: RuntimeStatus | undefined;
  }>();
  const tun = useDesktopState().data?.connection === "Tun";
  const status = useStatus().data;
  const config = model.settings.dns_protection ?? DEFAULT_DNS;
  const exits = eligibleExits(model);
  const exit = exits.find(({ id }) => id === config.proxy_exit);
  const exitStatus = exit && status?.health?.exits?.[exit.id]?.status;
  const unavailable = !exit || (exitStatus != null && exitStatus !== "Ok");
  const applyFailed = !!status?.last_apply && !("Reloaded" in status.last_apply);
  const notApplied = !tun && (
    (notice?.failed && (notice.previousStatus === status || applyFailed))
    || (config.enabled && !!status && (status.core !== "Running" || applyFailed))
  );
  const description = notApplied ? "已保存的 DNS 配置未确认生效，请检查内核状态"
    : !config.enabled ? "为普通代理端口配置内核的 DNS 去向"
    : tun ? "当前沿用 TUN 原有的 DNS 设置"
    : unavailable ? "所选出口不可用，代理 DNS 不会改走直连"
    : `代理 DNS 出口：${exit.label}`;

  return <>
    <Section title="DNS">
      {[
        <Row key="dns" label="DNS 分流" description={description}
          below={notice && (notice.warning || !notApplied) && (
            <Alert severity={notice.warning ? "warning" : "info"}>{notice.text}</Alert>
          )}>
          <Chip size="small"
            color={notApplied || (config.enabled && !tun && unavailable) ? "warning" : "default"}
            label={notApplied ? "未应用" : !config.enabled ? "已关闭" : tun ? "TUN 中暂停" : unavailable ? "出口不可用" : "已配置"} />
          <Button variant="outlined" startIcon={<Tune fontSize="small" />} onClick={() => setEditing(true)}
            disabled={otherSavePending}>配置 DNS 分流</Button>
        </Row>,
      ]}
    </Section>
    {editing && <DnsProtectionDialog initial={config} exits={exits} tun={tun}
      onSaved={(outcome) => {
        const message = applyOutcomeMessages(outcome).join("；");
        setNotice({
          warning: !!message,
          failed: !("Reloaded" in outcome),
          text: message || (tun ? "DNS 配置已保存，退出 TUN 后应用" : "DNS 分流设置已保存"),
          previousStatus: status,
        });
      }}
      onClose={() => setEditing(false)} />}
  </>;
}
