import {
  Alert, Box, Button, DialogActions, DialogContent, DialogTitle,
  Stack, TextField,
} from "@mui/material";
import { useState, type FormEvent } from "react";
import { errorMessage, isValidationError, useModel, useSaveManualNode } from "../api/client";
import type { ManualNode, NodeRef } from "../bindings";
import { FormDialog } from "../components/FormDialog";
import { NodePicker } from "../components/NodePicker";
import { canBeChainHop } from "../lib/proxyChain";
import { nodeKey } from "../lib/refs";
import { fieldErrors, type FieldErrors } from "../lib/validation";

export function ProxyChainDialog({ id, node, onClose }: {
  id: string;
  node?: ManualNode;
  onClose: () => void;
}) {
  const model = useModel();
  const save = useSaveManualNode();
  const initial = node && "Chain" in node.kind ? node.kind.Chain : undefined;
  const [name, setName] = useState(node?.name ?? "");
  const [entry, setEntry] = useState<NodeRef | null>(initial?.entry ?? null);
  const [exit, setExit] = useState<NodeRef | null>(initial?.exit ?? null);
  const [errors, setErrors] = useState<FieldErrors>({ form: [] });
  const m = model.data;
  const entryUnavailable = !!(m && entry && !canBeChainHop(m, entry));
  const exitUnavailable = !!(m && exit && !canBeChainHop(m, exit));
  const duplicate = !!(entry && exit && nodeKey(entry) === nodeKey(exit));
  const canSave = !!(m && name.trim() && entry && exit && !entryUnavailable && !exitUnavailable && !duplicate);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!canSave || !entry || !exit || save.isPending) return;
    setErrors({ form: [] });
    try {
      await save.mutateAsync({ id, name: name.trim(), groups: [], kind: { Chain: { entry, exit } } });
      onClose();
    } catch (e) {
      setErrors(isValidationError(e) ? fieldErrors(e.errors) : { form: [errorMessage(e)] });
    }
  }

  return (
    <FormDialog
      busy={save.isPending}
      onClose={onClose}
      fullWidth
      maxWidth="xs"
      sx={{ "& .MuiDialog-paper": { height: 510 } }}
    >
      <DialogTitle>{node ? "编辑代理链" : "新增代理链"}</DialogTitle>
      <Box component="form" onSubmit={(e) => void submit(e)}
        sx={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 1 }}>
            <Alert severity="info">
              流量依次经过前置和落地节点。仅支持 TCP，匹配此代理链的 UDP 会被阻断；任一跳不可用时不会自动直连。
              两跳都只可选择支持的普通节点，不支持代理链嵌套或 Tailscale。
            </Alert>
            {errors.form.length > 0 && <Alert severity="error">{errors.form.join("；")}</Alert>}
            <TextField
              label="名称"
              required
              size="small"
              autoFocus
              value={name}
              error={!!errors.name}
              helperText={errors.name}
              onChange={(e) => {
                setName(e.target.value);
                setErrors((old) => ({ ...old, name: undefined }));
              }}
            />
            <NodePicker label="前置节点（第 1 跳）" value={entry} onChange={setEntry}
              accepts={canBeChainHop} disabled={save.isPending}
              error={entryUnavailable ? "前置节点已不存在或无法作为链路节点，请重新选择。" : undefined} />
            <NodePicker label="落地节点（第 2 跳）" value={exit} onChange={setExit}
              accepts={canBeChainHop} disabled={save.isPending}
              error={exitUnavailable ? "落地节点已不存在或无法作为链路节点，请重新选择。" : duplicate ? "前置和落地节点不能相同。" : undefined} />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button disabled={save.isPending} onClick={onClose}>取消</Button>
          <Button type="submit" variant="contained" disabled={!canSave || save.isPending}>保存</Button>
        </DialogActions>
      </Box>
    </FormDialog>
  );
}
