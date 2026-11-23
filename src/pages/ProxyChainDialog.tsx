import Add from "@mui/icons-material/Add";
import ArrowDownward from "@mui/icons-material/ArrowDownward";
import ArrowUpward from "@mui/icons-material/ArrowUpward";
import DeleteOutline from "@mui/icons-material/DeleteOutlined";
import {
  Alert, Box, Button, DialogActions, DialogContent, DialogTitle,
  IconButton, Stack, TextField, Typography,
} from "@mui/material";
import { useRef, useState, type FormEvent } from "react";
import { errorMessage, isValidationError, useModel, useSaveManualNode } from "../api/client";
import type { ManualNode, NodeRef } from "../bindings";
import { FormDialog } from "../components/FormDialog";
import { NodePicker } from "../components/NodePicker";
import { canBeChainHop, hopRole, MAX_CHAIN_HOPS, MIN_CHAIN_HOPS } from "../lib/proxyChain";
import { nodeKey, nodeLabel } from "../lib/refs";
import { fieldErrors, type FieldErrors } from "../lib/validation";

type Row = { key: number; ref: NodeRef | null };

export function ProxyChainDialog({ id, node, onClose }: {
  id: string;
  node?: ManualNode;
  onClose: () => void;
}) {
  const model = useModel();
  const save = useSaveManualNode();
  const [name, setName] = useState(node?.name ?? "");
  const [rows, setRows] = useState<Row[]>(() => {
    const refs = node && "Chain" in node.kind ? node.kind.Chain.hops : [null, null];
    return refs.map((ref, key) => ({ ref, key }));
  });
  const nextKey = useRef(rows.length);
  const [errors, setErrors] = useState<FieldErrors>({ form: [] });
  const m = model.data;
  const hops = rows.map(({ ref }) => ref).filter((ref): ref is NodeRef => ref !== null);
  const seen = new Map<string, number>();
  const problems = rows.map(({ ref }, i) => {
    if (!ref || !m) return;
    if (!canBeChainHop(m, ref)) return `${hopRole(i, rows.length)}已不存在或无法作为链路节点，请重新选择。`;
    const key = nodeKey(ref);
    const prior = seen.get(key);
    if (prior !== undefined) return `与第 ${prior + 1} 跳重复，请选择不同的节点。`;
    seen.set(key, i);
  });
  const canSave = !!m && !!name.trim() && rows.length >= MIN_CHAIN_HOPS && rows.length <= MAX_CHAIN_HOPS
    && rows.length === hops.length && !problems.some(Boolean);
  const preview = rows.map(({ ref }, i) => ref && m ? nodeLabel(m, ref) : `待选第 ${i + 1} 跳`).join(" → ");

  function move(at: number, delta: -1 | 1) {
    setRows((current) => {
      const to = at + delta;
      if (to < 0 || to >= current.length) return current;
      const next = [...current];
      [next[at], next[to]] = [next[to], next[at]];
      return next;
    });
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!canSave || save.isPending) return;
    setErrors({ form: [] });
    try {
      await save.mutateAsync({ id, name: name.trim(), groups: [], kind: { Chain: { hops } } });
      onClose();
    } catch (e) {
      setErrors(isValidationError(e) ? fieldErrors(e.errors) : { form: [errorMessage(e)] });
    }
  }

  return (
    <FormDialog busy={save.isPending} onClose={onClose} fullWidth maxWidth="sm"
      sx={{ "& .MuiDialog-paper": { height: 630 } }}>
      <DialogTitle>{node ? "编辑代理链" : "新增代理链"}</DialogTitle>
      <Box component="form" onSubmit={(e) => void submit(e)}
        sx={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
        <DialogContent>
          <Stack spacing={1.5}>
            <Alert severity="info">
              仅支持 TCP，匹配此代理链的 UDP 会被阻断。任一跳连接失败时，不会跳过节点，也不会自动直连。
            </Alert>
            {errors.form.length > 0 && <Alert severity="error">{errors.form.join("；")}</Alert>}
            <TextField label="名称" required size="small" autoFocus value={name} disabled={save.isPending}
              error={!!errors.name} helperText={errors.name}
              onChange={(e) => {
                setName(e.target.value);
                setErrors((old) => ({ ...old, name: undefined }));
              }} />
            <Box sx={{ bgcolor: "action.hover", borderRadius: 1, px: 1.5, py: 1 }}>
              <Typography variant="caption" color="text.secondary">链路预览 · {rows.length} 跳，最后一跳为出口</Typography>
              <Typography aria-label="链路预览" aria-live="polite" variant="body2" sx={{ overflowWrap: "anywhere" }}>
                {preview}
              </Typography>
            </Box>
            {rows.map((row, i) => {
              const number = i + 1;
              return (
                <Box key={row.key} sx={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) auto", gap: 1, alignItems: "start" }}>
                  <NodePicker label={`${hopRole(i, rows.length)}（第 ${number} 跳）`}
                    value={row.ref} accepts={canBeChainHop} error={problems[i]} disabled={save.isPending}
                    onChange={(ref) => setRows((old) => old.map((r) => r.key === row.key ? { ...r, ref } : r))} />
                  <Box sx={{ display: "flex", pt: 3.4 }}>
                    <IconButton size="small" title="上移" aria-label={`上移第 ${number} 跳`}
                      disabled={save.isPending || i === 0} onClick={() => move(i, -1)}><ArrowUpward fontSize="small" /></IconButton>
                    <IconButton size="small" title="下移" aria-label={`下移第 ${number} 跳`}
                      disabled={save.isPending || number === rows.length} onClick={() => move(i, 1)}><ArrowDownward fontSize="small" /></IconButton>
                    <IconButton size="small" title="删除" aria-label={`删除第 ${number} 跳`}
                      disabled={save.isPending || rows.length <= MIN_CHAIN_HOPS}
                      onClick={() => setRows((old) => old.filter((r) => r.key !== row.key))}><DeleteOutline fontSize="small" /></IconButton>
                  </Box>
                </Box>
              );
            })}
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap" }}>
              <Button startIcon={<Add />} size="small" variant="outlined"
                disabled={save.isPending || rows.length >= MAX_CHAIN_HOPS} onClick={() => {
                  const key = nextKey.current++;
                  setRows((old) => [...old, { key, ref: null }]);
                }}>添加一跳</Button>
              <Typography variant="caption" color="text.secondary">
                2–8 跳，仅可选择普通代理节点，不支持嵌套或 Tailscale。
              </Typography>
            </Box>
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
