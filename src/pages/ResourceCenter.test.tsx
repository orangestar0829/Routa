import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  fireEvent,
  render,
  screen,
  within,
  waitFor,
} from "@testing-library/react";
import { act } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { ApplyResultProvider } from "../components/ApplyResultSnackbar";
import { clearMonitorFocus, setMonitorFocus } from "../api/monitorFocus";
import { canBeChainHop } from "../lib/proxyChain";
const mode = vi.hoisted(() => ({ value: "Full" }));
vi.mock("../components/InterfaceProvider", () => ({
  useInterface: () => ({ state: { preferences: { mode: mode.value } } }),
}));
import { ResourceCenter } from "./ResourceCenter";
import type { JsonValue, Model, MonitorTarget, NodeRef, RuntimeStatus } from "../bindings";
vi.mock("../bindings", () => ({
  commands: { getModel: vi.fn(), getStatus: vi.fn(), saveManualNode: vi.fn(), testDelays: vi.fn(), saveSettings: vi.fn(), monitorInUseNodes: vi.fn() },
}));
import { commands } from "../bindings";
const model: Model = {
  subscriptions: [
    {
      id: "s1",
      name: "来源甲",
      url: "https://example.test/sub",
      update_interval_mins: 60,
      fallback_exit: null,
      last_updated: null,
      last_result: null,
      nodes: [{ name: "订阅节点", proxy_type: "ss", server: "test", raw: {} }],
    },
  ],
  manual_nodes: [
    {
      id: "m1",
      name: "手动节点甲",
      groups: ["g1"],
      kind: { Proxy: { raw: { type: "socks5" } } },
    },
    {
      id: "m2",
      name: "游离节点",
      groups: [],
      kind: { Proxy: { raw: { type: "http" } } },
    },
  ],
  node_groups: [
    {
      id: "g1",
      name: "跨来源组",
      members: [{ subscription_id: "s1", name: "订阅节点" }],
    },
  ],
  listeners: [],
  exits: [],
  settings: {
    autostart: false,
    core_path: null,
    controller_port: 19097,
    delay_test_interval_mins: 10,
    delay_test_url: "u",
    node_monitor: { enabled: false, members: [], interval_secs: 300, fail_threshold: 2, latency_limit_ms: 1000, notify_recovery: true },
  },
  process_routing: { rules: [], exit_prompt: true },
};
function setup(
  subscriptionsOnly = false,
  path = "/nodes",
  data: Model = model,
  monitorTargets: MonitorTarget[] = [],
) {
  vi.mocked(commands.getModel).mockResolvedValue(data);
  vi.mocked(commands.getStatus).mockResolvedValue({
    delays: {},
    interfaces: [],
    monitor: { last_run: null, next_run: null, probing: false, paused_reason: null, network_down: false, targets: monitorTargets },
  } as unknown as RuntimeStatus);
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <ApplyResultProvider>
        <MemoryRouter initialEntries={[path]}>
          <ResourceCenter subscriptionsOnly={subscriptionsOnly} />
        </MemoryRouter>
      </ApplyResultProvider>
    </QueryClientProvider>,
  );
}
it("groups nodes across sources and puts only unassigned nodes in 未分组", async () => {
  setup();
  const g = await screen.findByRole("button", { name: "▾ 跨来源组 · 2" });
  const section = g.closest(".MuiPaper-root")! as HTMLElement;
  expect(within(section).getByText("订阅节点")).toBeInTheDocument();
  expect(within(section).getByText("手动节点甲")).toBeInTheDocument();
  expect(within(section).queryByText("游离节点")).not.toBeInTheDocument();
  expect(screen.queryByRole("tab")).not.toBeInTheDocument();
});
it("searches collapsed groups and restores collapse when cleared", async () => {
  setup();
  fireEvent.click(await screen.findByRole("button", { name: "全部折叠" }));
  expect(screen.queryByText("订阅节点")).not.toBeInTheDocument();
  const search = screen.getByLabelText("搜索名称、来源、协议或分组");
  fireEvent.change(search, { target: { value: "订阅节点" } });
  expect(screen.getByText("订阅节点")).toBeInTheDocument();
  fireEvent.change(search, { target: { value: "" } });
  expect(screen.queryByText("订阅节点")).not.toBeInTheDocument();
});
it("renders standalone subscription cards with a source-filtered node link", async () => {
  setup(true, "/subscriptions");
  expect(await screen.findByRole("link", { name: "查看节点" })).toHaveAttribute(
    "href",
    "/nodes?source=s1",
  );
  expect(screen.queryByRole("table")).not.toBeInTheDocument();
  expect(screen.getByText("example.test")).toBeInTheDocument();
  expect(screen.queryByText("https://example.test/sub")).not.toBeInTheDocument();
});
it("filters a subscription source across groups", async () => {
  setup(false, "/nodes?source=s1");
  expect(await screen.findByText("订阅节点")).toBeInTheDocument();
  expect(screen.queryByText("手动节点甲")).not.toBeInTheDocument();
  expect(screen.queryByText("游离节点")).not.toBeInTheDocument();
});

it("shows subscription nodes under their source instead of 未分组 when no custom group is assigned", async () => {
  setup(false, "/nodes", { ...model, node_groups: [] });
  fireEvent.click(await screen.findByRole("button", { name: "▸ 来源甲 · 1" }));
  const source = screen.getByRole("button", { name: "▾ 来源甲 · 1" });
  const section = source.closest(".MuiPaper-root") as HTMLElement;
  expect(
    within(section).getByRole("article", { name: "订阅节点" }),
  ).toBeInTheDocument();
  const ungrouped = screen
    .getByRole("button", { name: "▾ 未分组 · 2" })
    .closest(".MuiPaper-root") as HTMLElement;
  expect(within(ungrouped).queryByText("订阅节点")).not.toBeInTheDocument();
  expect(
    within(ungrouped).getByRole("article", { name: "游离节点" }),
  ).toBeInTheDocument();
  expect(screen.queryByRole("table")).not.toBeInTheDocument();
});
it("does not duplicate a custom-grouped subscription node in its source section", async () => {
  setup();
  expect(
    await screen.findByRole("button", { name: "▾ 跨来源组 · 2" }),
  ).toBeInTheDocument();
  expect(
    screen.queryByRole("button", { name: /▾ 来源甲/ }),
  ).not.toBeInTheDocument();
  expect(screen.getAllByRole("article", { name: "订阅节点" })).toHaveLength(1);
});
it("keeps nodes with the same name in different subscription sections", async () => {
  const second = { ...model.subscriptions[0], id: "s2", name: "来源乙" };
  setup(false, "/nodes", {
    ...model,
    node_groups: [],
    manual_nodes: [],
    subscriptions: [...model.subscriptions, second],
  });
  fireEvent.click(await screen.findByRole("button", { name: "全部展开" }));
  const first = screen.getByRole("button", { name: "▾ 来源甲 · 1" });
  const other = screen.getByRole("button", { name: "▾ 来源乙 · 1" });
  for (const button of [first, other])
    expect(
      within(button.closest(".MuiPaper-root") as HTMLElement).getByRole(
        "article",
        { name: "订阅节点" },
      ),
    ).toBeInTheDocument();
  expect(
    screen.queryByRole("button", { name: /未分组/ }),
  ).not.toBeInTheDocument();
});
it("searches collapsed subscription sections and restores collapse on clear", async () => {
  setup(false, "/nodes", { ...model, node_groups: [] });
  expect(await screen.findByRole("button", { name: "▸ 来源甲 · 1" })).toBeInTheDocument();
  expect(
    screen.queryByRole("article", { name: "订阅节点" }),
  ).not.toBeInTheDocument();
  const search = screen.getByLabelText("搜索名称、来源、协议或分组");
  fireEvent.change(search, { target: { value: "来源甲" } });
  expect(screen.getByRole("article", { name: "订阅节点" })).toBeInTheDocument();
  expect(
    screen.queryByRole("article", { name: "游离节点" }),
  ).not.toBeInTheDocument();
  fireEvent.change(search, { target: { value: "" } });
  expect(
    screen.queryByRole("article", { name: "订阅节点" }),
  ).not.toBeInTheDocument();
});
it("filters source fallback sections without including other sources or manual nodes", async () => {
  setup(false, "/nodes?source=s1", {
    ...model,
    node_groups: [],
    subscriptions: [
      ...model.subscriptions,
      {
        ...model.subscriptions[0],
        id: "s2",
        name: "来源乙",
        nodes: [{ ...model.subscriptions[0].nodes[0], name: "其他订阅节点" }],
      },
    ],
  });
  expect(
    await screen.findByRole("article", { name: "订阅节点" }),
  ).toBeInTheDocument();
  expect(
    screen.queryByRole("article", { name: "其他订阅节点" }),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByRole("article", { name: "游离节点" }),
  ).not.toBeInTheDocument();
});

it("collapses subscription sections by default and keeps groups and 未分组 open", async () => {
  setup(false, "/nodes", {
    ...model,
    subscriptions: [
      ...model.subscriptions,
      { ...model.subscriptions[0], id: "s2", name: "来源乙", nodes: [{ ...model.subscriptions[0].nodes[0], name: "乙节点" }] },
    ],
  });
  expect(await screen.findByRole("button", { name: "▸ 来源乙 · 1" })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "▾ 跨来源组 · 2" })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "▾ 未分组 · 1" })).toBeInTheDocument();
  expect(screen.queryByRole("article", { name: "乙节点" })).not.toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "全部展开" }));
  expect(screen.getByRole("article", { name: "乙节点" })).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "全部折叠" }));
  expect(screen.getByRole("button", { name: "▸ 跨来源组 · 2" })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "▸ 未分组 · 1" })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "全部展开" })).toBeInTheDocument();
});

it("collapses search results visibly and restores the pre-search state on clear", async () => {
  setup();
  const search = await screen.findByLabelText("搜索名称、来源、协议或分组");
  fireEvent.change(search, { target: { value: "节点" } });
  fireEvent.click(screen.getByRole("button", { name: "全部折叠" }));
  expect(screen.getByRole("button", { name: "▸ 跨来源组 · 2" })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "▸ 未分组 · 1" })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "全部展开" })).toBeInTheDocument();
  fireEvent.change(search, { target: { value: "" } });
  expect(screen.getByRole("button", { name: "▾ 跨来源组 · 2" })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "▾ 未分组 · 1" })).toBeInTheDocument();
});

it("toggles a section header during search without touching the pre-search state", async () => {
  setup();
  const search = await screen.findByLabelText("搜索名称、来源、协议或分组");
  fireEvent.change(search, { target: { value: "游离" } });
  fireEvent.click(screen.getByRole("button", { name: "▾ 未分组 · 1" }));
  expect(screen.queryByRole("article", { name: "游离节点" })).not.toBeInTheDocument();
  fireEvent.change(search, { target: { value: "游离节" } });
  expect(screen.getByRole("article", { name: "游离节点" })).toBeInTheDocument();
  fireEvent.change(search, { target: { value: "" } });
  expect(screen.getByRole("button", { name: "▾ 未分组 · 1" })).toBeInTheDocument();
});

it("opens the subscription section when arriving from 查看节点", async () => {
  setup(false, "/nodes?source=s1", { ...model, node_groups: [] });
  expect(await screen.findByRole("button", { name: "▾ 来源甲 · 1" })).toBeInTheDocument();
});

it("groups every creation action under one 新增 menu", async () => {
  setup();
  for (const name of ["新建分组", "新增 Tailscale", "导入 YAML", "新增节点", "新增代理链"])
    expect(screen.queryByRole("button", { name })).not.toBeInTheDocument();
  fireEvent.click(await screen.findByRole("button", { name: "新增" }));
  const items = screen.getAllByRole("menuitem").map((i) => i.textContent);
  expect(items).toEqual(["新增节点", "新增代理链", "新增 Tailscale", "导入 YAML", "新建分组"]);
});

it("toggles delay sorting as a pressed icon button", async () => {
  setup();
  const sort = await screen.findByRole("button", { name: "按延迟排序" });
  expect(sort).toHaveAttribute("aria-pressed", "false");
  fireEvent.click(sort);
  expect(sort).toHaveAttribute("aria-pressed", "true");
});

it("moves node actions into the right-click menu and tests the selected node", async () => {
  vi.mocked(commands.testDelays).mockResolvedValue({ status: "ok", data: [] });
  setup();
  const card = await screen.findByRole("article", { name: "订阅节点" });
  expect(
    within(card).queryByRole("button", { name: "用于新代理" }),
  ).not.toBeInTheDocument();
  fireEvent.contextMenu(card, { clientX: 120, clientY: 150 });
  expect(
    await screen.findByRole("menuitem", { name: "用于新代理 订阅节点" }),
  ).toBeInTheDocument();
  fireEvent.click(screen.getByRole("menuitem", { name: "测延迟 订阅节点" }));
  await waitFor(() =>
    expect(commands.testDelays).toHaveBeenCalledWith(["来源甲/订阅节点"]),
  );
});

it("opens proxy creation from the node context menu without submitting it", async () => {
  setup();
  fireEvent.contextMenu(
    await screen.findByRole("article", { name: "订阅节点" }),
    { clientX: 120, clientY: 150 },
  );
  fireEvent.click(
    await screen.findByRole("menuitem", { name: "用于新代理 订阅节点" }),
  );
  expect(
    await screen.findByRole("dialog", { name: "新增代理" }),
  ).toBeInTheDocument();
  expect(screen.getByLabelText("名称")).toHaveValue("订阅节点");
});

const subRef: NodeRef = { subscription_id: "s1", name: "订阅节点" };
const target = (over: Partial<MonitorTarget> = {}): MonitorTarget => ({
  proxy: "来源甲/订阅节点", node: subRef, label: "订阅节点", used_by: ["工作代理 :7890"],
  fails: 0, down: false, down_since: null, last_ms: 48, last_failure: null, probed: true, not_applied: false,
  ...over,
});

describe("node monitor on cards", () => {
  beforeEach(() => {
    mode.value = "Full";
    clearMonitorFocus();
    vi.mocked(commands.saveSettings).mockResolvedValue({ status: "ok", data: { Reloaded: { cut: 0, uncut: 0, failed_listeners: [] } } });
    vi.mocked(commands.monitorInUseNodes).mockResolvedValue({ status: "ok", data: { nodes: [], auto_exits: [] } });
  });

  it("monitored node shows mark", async () => {
    setup(false, "/nodes", model, [target()]);
    const card = await screen.findByRole("article", { name: "订阅节点" });
    expect(within(card).getByLabelText("监测中")).toBeInTheDocument();
    expect(within(screen.getByRole("article", { name: "手动节点甲" })).queryByLabelText("监测中")).not.toBeInTheDocument();
  });

  it("unmonitored card reserves no mark area", async () => {
    setup(false, "/nodes", model, [target()]);
    const monitored = await screen.findByRole("article", { name: "订阅节点" });
    expect(monitored.querySelector("[data-card-mark]")).not.toBeNull();
    const plain = screen.getByRole("article", { name: "手动节点甲" });
    expect(within(plain).queryByLabelText(/^监测/)).not.toBeInTheDocument();
    expect(plain.querySelector("[data-card-mark]")).toBeNull();
  });

  it("keeps the Tailscale mark while the node is up", async () => {
    const ts = { id: "t1", name: "TS", groups: [], kind: { Tailscale: { exit: null } } };
    const data = { ...model, manual_nodes: [...model.manual_nodes, ts] } as unknown as Model;
    setup(false, "/nodes", data, [target({ proxy: "手动/TS", node: { manual_id: "t1" }, label: "TS" })]);
    const card = await screen.findByRole("article", { name: "TS" });
    expect(within(card).queryByLabelText("监测中")).not.toBeInTheDocument();
  });

  it("shows the down mark over the Tailscale mark", async () => {
    const ts = { id: "t1", name: "TS", groups: [], kind: { Tailscale: { exit: null } } };
    const data = { ...model, manual_nodes: [...model.manual_nodes, ts] } as unknown as Model;
    setup(false, "/nodes", data, [target({ proxy: "手动/TS", node: { manual_id: "t1" }, label: "TS", down: true, fails: 2 })]);
    const card = await screen.findByRole("article", { name: "TS" });
    expect(within(card).getByLabelText("监测：不可用")).toBeInTheDocument();
  });

  it("menu turns monitoring on with the in-use nodes plus this one", async () => {
    const used = { manual_id: "m9" };
    vi.mocked(commands.monitorInUseNodes).mockResolvedValue({ status: "ok", data: { nodes: [used], auto_exits: ["工作出口"] } });
    setup();
    fireEvent.click(await screen.findByRole("button", { name: "操作 订阅节点" }));
    fireEvent.click(await screen.findByRole("menuitem", { name: "加入监测 订阅节点" }));
    await waitFor(() => expect(commands.saveSettings).toHaveBeenCalled());
    expect(vi.mocked(commands.saveSettings).mock.calls[0][0].node_monitor).toEqual({
      ...model.settings.node_monitor, enabled: true, members: [used, subRef],
    });
    expect(await screen.findByText("自动选择的出口「工作出口」没有固定节点，未加入监测")).toBeInTheDocument();
  });

  it("menu adds to existing members without asking for in-use nodes", async () => {
    const other = { manual_id: "m9" };
    const data = { ...model, settings: { ...model.settings, node_monitor: { ...model.settings.node_monitor, enabled: true, members: [other] } } };
    setup(false, "/nodes", data);
    fireEvent.click(await screen.findByRole("button", { name: "操作 订阅节点" }));
    fireEvent.click(await screen.findByRole("menuitem", { name: "加入监测 订阅节点" }));
    await waitFor(() => expect(commands.saveSettings).toHaveBeenCalled());
    expect(vi.mocked(commands.saveSettings).mock.calls[0][0].node_monitor.members).toEqual([other, subRef]);
    expect(commands.monitorInUseNodes).not.toHaveBeenCalled();
  });

  it("menu removes only that node from the members", async () => {
    const other = { manual_id: "m9" };
    const nm = { ...model.settings.node_monitor, enabled: true, members: [subRef, other] };
    const data = { ...model, settings: { ...model.settings, node_monitor: nm } };
    setup(false, "/nodes", data, [target()]);
    fireEvent.click(await screen.findByRole("button", { name: "操作 订阅节点" }));
    fireEvent.click(await screen.findByRole("menuitem", { name: "移出监测 订阅节点" }));
    await waitFor(() => expect(commands.saveSettings).toHaveBeenCalled());
    expect(vi.mocked(commands.saveSettings).mock.calls[0][0].node_monitor.members).toEqual([other]);
  });

  it("simple mode has no monitor menu item", async () => {
    mode.value = "Simple";
    setup();
    fireEvent.click(await screen.findByRole("button", { name: "操作 订阅节点" }));
    await screen.findByRole("menuitem", { name: "使用此节点 订阅节点" });
    expect(screen.queryByRole("menuitem", { name: /监测/ })).not.toBeInTheDocument();
  });

  describe("toast focus", () => {
    const scrollIntoView = vi.fn();
    beforeEach(() => {
      scrollIntoView.mockClear();
      Element.prototype.scrollIntoView = scrollIntoView;
    });
    afterEach(() => vi.useRealTimers());

    it("monitor_focus_navigates_and_highlights_node", async () => {
      setup(false, "/nodes", { ...model, node_groups: [] });
      // 来源甲 starts collapsed.
      expect(await screen.findByRole("button", { name: "▸ 来源甲 · 1" })).toBeInTheDocument();
      vi.useFakeTimers();
      act(() => setMonitorFocus({ Node: subRef }));
      const card = screen.getByRole("article", { name: "订阅节点" });
      expect(card).toHaveAttribute("data-monitor-focus", "true");
      expect(scrollIntoView).toHaveBeenCalled();
      act(() => { vi.advanceTimersByTime(3100); });
      expect(screen.getByRole("article", { name: "订阅节点" })).not.toHaveAttribute("data-monitor-focus");
      // The section stays open after the outline is gone.
      expect(screen.getByRole("button", { name: "▾ 来源甲 · 1" })).toBeInTheDocument();
    });
  });
});

const entryRef: NodeRef = { subscription_id: "s1", name: "前置来源" };
const exitRef: NodeRef = { manual_id: "m1" };
const tcpChainModel: Model = {
  ...model,
  subscriptions: [{
    ...model.subscriptions[0],
    nodes: [{
      ...model.subscriptions[0].nodes[0], name: "前置来源",
      raw: { type: "vless", server: "entry.test", port: 443, network: "ws" },
    }, {
      ...model.subscriptions[0].nodes[0], name: "仅支持 UDP 传输",
      raw: { type: "hysteria2", server: "udp.test", port: 443 },
    }, {
      ...model.subscriptions[0].nodes[0], name: "网络大小写别名",
      raw: { type: "vless", server: "udp.test", port: 443, Network: "mkcp" },
    }],
  }],
  manual_nodes: [{
    ...model.manual_nodes[0], name: "落地候选",
    kind: { Proxy: { raw: { type: "socks5", server: "exit.test", port: "1080" } } },
  }, {
    id: "other-chain", name: "现有代理链", groups: [],
    kind: { Chain: { entry: entryRef, exit: exitRef } },
  }, {
    id: "plugin-alias", name: "插件大小写别名", groups: [],
    kind: { Proxy: { raw: { type: "ss", server: "udp.test", port: 443, Plugin: "kcptun" } } },
  }],
  node_groups: [],
};

it("applies the same canonical chain eligibility to subscription maps", () => {
  const base = { type: "vless", server: "entry.test", port: 443 };
  const candidates: [JsonValue, boolean][] = [
    [{ ...base, network: "ws", ws_opts: { headers: { "X-Client": "真实客户端" } }, IP_VERSION: "dual" }, true],
    [{ ...base, network: "tcp", NETWORK: "mkcp" }, false],
    [{ ...base, "networK": "mkcp" }, false],
    [{ ...base, "<<": { network: "mkcp" } }, false],
    [{ ...base, Server: "other.test" }, false],
    [{ ...base, network: "WS" }, false],
    [{ ...base, type: "ss", plugin: "" }, true],
    [{ ...base, type: "ss", plugin: "kcptun" }, false],
  ];
  for (const [raw, eligible] of candidates) {
    const sub = tcpChainModel.subscriptions[0];
    expect(canBeChainHop({ ...tcpChainModel, subscriptions: [{ ...sub, nodes: [{ ...sub.nodes[0], raw }] }] }, entryRef))
      .toBe(eligible);
  }
});

async function pickHop(label: RegExp, name: string) {
  fireEvent.keyDown(screen.getByRole("combobox", { name: label }), { key: "ArrowDown" });
  fireEvent.click(await screen.findByRole("option", { name }));
}

it("adds a chain with fixed, typed entry and exit without offering unsupported hops", async () => {
  vi.mocked(commands.saveManualNode).mockClear();
  vi.mocked(commands.saveManualNode).mockResolvedValue({ status: "ok", data: { Reloaded: { cut: 0, uncut: 0, failed_listeners: [] } } });
  setup(false, "/nodes", tcpChainModel);
  fireEvent.click(await screen.findByRole("button", { name: "新增" }));
  fireEvent.click(screen.getByRole("menuitem", { name: "新增代理链" }));
  expect(await screen.findByText(/仅支持 TCP.*不会自动直连/)).toBeInTheDocument();
  fireEvent.change(screen.getByRole("textbox", { name: /名称/ }), { target: { value: "双跳测试" } });
  fireEvent.keyDown(screen.getByRole("combobox", { name: /前置节点/ }), { key: "ArrowDown" });
  expect(await screen.findByRole("option", { name: "前置来源" })).toBeInTheDocument();
  expect(screen.getByRole("option", { name: "落地候选" })).toBeInTheDocument();
  expect(screen.queryByRole("option", { name: "现有代理链" })).not.toBeInTheDocument();
  expect(screen.queryByRole("option", { name: "仅支持 UDP 传输" })).not.toBeInTheDocument();
  expect(screen.queryByRole("option", { name: "网络大小写别名" })).not.toBeInTheDocument();
  expect(screen.queryByRole("option", { name: "插件大小写别名" })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("option", { name: "前置来源" }));
  await pickHop(/落地节点/, "前置来源");
  expect(screen.getByText("前置和落地节点不能相同。")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "保存" })).toBeDisabled();
  fireEvent.click(screen.getByRole("combobox", { name: /落地节点/ }));
  fireEvent.change(screen.getByRole("combobox", { name: /落地节点/ }), { target: { value: "" } });
  await pickHop(/落地节点/, "落地候选");
  fireEvent.click(screen.getByRole("button", { name: "保存" }));
  await waitFor(() => expect(commands.saveManualNode).toHaveBeenCalledWith({
    id: expect.any(String), name: "双跳测试", groups: [],
    kind: { Chain: { entry: entryRef, exit: exitRef } },
  }));
});

it("shows a missing subscription hop on its card and retains stable identity when repaired", async () => {
  vi.mocked(commands.saveManualNode).mockClear();
  vi.mocked(commands.saveManualNode).mockResolvedValue({ status: "ok", data: { Reloaded: { cut: 0, uncut: 0, failed_listeners: [] } } });
  const replacementRef: NodeRef = { subscription_id: "s1", name: "新订阅节点" };
  setup(false, "/nodes", {
    ...tcpChainModel,
    subscriptions: [{
      ...tcpChainModel.subscriptions[0],
      nodes: [{ ...tcpChainModel.subscriptions[0].nodes[0], name: replacementRef.name }],
    }],
  });
  const card = await screen.findByRole("article", { name: "现有代理链" });
  expect(within(card).getByText("前置节点不可用")).toBeInTheDocument();
  fireEvent.click(within(card).getByRole("button", { name: "操作 现有代理链" }));
  expect(screen.getByRole("menuitem", { name: "测延迟 现有代理链" })).toHaveAttribute("aria-disabled", "true");
  fireEvent.click(screen.getByRole("menuitem", { name: "编辑 现有代理链" }));
  expect(await screen.findByText(/前置节点已不存在/)).toBeInTheDocument();
  expect(screen.getByRole("combobox", { name: /前置节点/ })).toHaveValue("前置来源");
  expect(screen.getByRole("button", { name: "保存" })).toBeDisabled();
  fireEvent.change(screen.getByRole("combobox", { name: /前置节点/ }), { target: { value: "" } });
  await pickHop(/前置节点/, "新订阅节点");
  fireEvent.click(screen.getByRole("button", { name: "保存" }));
  await waitFor(() => expect(commands.saveManualNode).toHaveBeenCalledWith({
    id: "other-chain", name: "现有代理链", groups: [],
    kind: { Chain: { entry: replacementRef, exit: exitRef } },
  }));
});
