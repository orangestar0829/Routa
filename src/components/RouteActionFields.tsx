import HelpOutline from "@mui/icons-material/HelpOutlineOutlined";
import { Box, MenuItem, TextField, Tooltip } from "@mui/material";
import type { RuleUnavailable } from "../bindings";
import { RULE_ACTIONS, ruleActionKind, targetUnavailable, type DraftRuleAction, type RuleActionKind } from "../lib/sharedRouting";
import { MemberPicker } from "./MemberPicker";

export function RouteActionFields({ action, onChange, disabled, error }: {
  action: DraftRuleAction;
  onChange: (action: DraftRuleAction) => void;
  disabled?: boolean;
  error?: string;
}) {
  const target = typeof action === "object" ? action : null;
  const unavailable = target ? targetUnavailable(target) : undefined;
  return <>
    <TextField select label="处理方式" value={ruleActionKind(action)} disabled={disabled}
      onChange={(e) => {
        const selected = e.target.value as RuleActionKind;
        onChange(selected === "Target" ? target ?? { Target: { target: null, unavailable: "Reject" } } : selected);
      }}>
      {RULE_ACTIONS.map(([value, label]) => <MenuItem key={value} value={value}>{label}</MenuItem>)}
      <MenuItem value="Target">指定节点或组</MenuItem>
    </TextField>
    {target && <>
      <MemberPicker multiple={false} label="所选出口" value={target.Target.target} disabled={disabled} error={error}
        onChange={(member) => onChange({ Target: { ...target.Target, target: member } })} />
      <Box sx={{ display: "flex", alignItems: "flex-start", gap: 0.75 }}>
        <TextField select fullWidth label="所选出口不可用时" value={unavailable} disabled={disabled}
          helperText={unavailable === "Direct" ? "选定出口不可用时，流量会绕过代理。" : undefined}
          onChange={(e) => onChange({ Target: { ...target.Target, unavailable: e.target.value as RuleUnavailable } })}>
          <MenuItem value="Reject">阻断</MenuItem>
          <MenuItem value="Direct">直连</MenuItem>
        </TextField>
        <Tooltip title="仅在节点已删除、组为空或网卡等已知状态不可用时生效，不会在每次连接超时后自动切换。">
          <Box tabIndex={0} aria-label="不可用条件说明" sx={{ display: "inline-flex", mt: 0.75, color: "text.secondary" }}>
            <HelpOutline fontSize="small" />
          </Box>
        </Tooltip>
      </Box>
    </>}
  </>;
}
