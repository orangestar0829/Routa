import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { commands, type Model, type SharedRule } from "../bindings";
import { SharedRoutingPage } from "./SharedRouting";

vi.mock("../bindings", () => ({
  commands: { getModel: vi.fn(), saveSharedRouting: vi.fn() },
}));

function setup(initial: Partial<Model> = {}) {
  let current = { listeners: [], ...initial } as Model;
  vi.mocked(commands.getModel).mockImplementation(async () => current);
  vi.mocked(commands.saveSharedRouting).mockImplementation(async (rules, providers) => {
    current = { ...current, shared_rules: rules, shared_rule_providers: providers };
    return { status: "ok", data: { NotRunning: { error: "mihomo 未运行，配置将在内核启动后生效" } } };
  });
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={queryClient}><SharedRoutingPage /></QueryClientProvider>);
}

function click(name: string, root = screen) {
  fireEvent.click(root.getByRole("button", { name }));
}

function choose(label: string, choice: string) {
  fireEvent.mouseDown(screen.getByRole("combobox", { name: label }));
  fireEvent.click(screen.getByRole("option", { name: choice }));
}

function input(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

beforeEach(() => vi.clearAllMocks());

it("starts empty; adds the China direct preset only when requested, with no duplicates", async () => {
  setup();
  await screen.findByText("还没有共享规则");
  expect(screen.getByRole("button", { name: "保存并应用" })).toBeDisabled();
  click("中国大陆直连");
  click("中国大陆直连");
  expect(screen.getByText("中国大陆直连规则已存在。")).toBeInTheDocument();
  expect(commands.saveSharedRouting).not.toHaveBeenCalled();
  expect(within(screen.getByRole("table", { name: "共享规则列表" })).getAllByRole("row")).toHaveLength(3);
  click("保存并应用");
  await waitFor(() => expect(commands.saveSharedRouting).toHaveBeenCalledWith([
    { matcher: "Geosite", value: "cn", action: "Direct", enabled: true },
    { matcher: "Geoip", value: "CN", action: "Direct", enabled: true },
  ], []));
  await waitFor(() => expect(screen.getByRole("button", { name: "保存并应用" })).toBeDisabled());
});

it("does not override existing definitions when adding the preset", async () => {
  const custom: SharedRule = { matcher: "Geosite", value: "CN", action: "Reject", enabled: true };
  setup({ shared_rules: [custom] });
  await screen.findByRole("table", { name: "共享规则列表" });
  click("中国大陆直连");
  expect(screen.getByText(/保留了已有的同类规则/)).toBeInTheDocument();
  click("保存并应用");
  await waitFor(() => expect(commands.saveSharedRouting).toHaveBeenCalledWith([
    custom, { matcher: "Geoip", value: "CN", action: "Direct", enabled: true },
  ], []));
});

it("adds, edits, toggles, reorders, and removes rules before committing in order", async () => {
  const initial: SharedRule = { matcher: "Domain", value: "one.example", action: "Proxy", enabled: true };
  setup({ shared_rules: [initial] });
  await screen.findByText("one.example");
  click("新增规则");
  expect(screen.getByRole("dialog", { name: "新增共享规则" })).toBeInTheDocument();
  click("保存");
  expect(screen.getByText("请输入匹配内容")).toBeInTheDocument();
  input("匹配内容", "two.example");
  choose("处理方式", "直连");
  click("保存");
  click("编辑第 2 条规则");
  input("匹配内容", "changed.example");
  click("保存");
  fireEvent.click(screen.getByRole("switch", { name: "启用第 2 条规则" }));
  click("上移第 2 条规则");
  const [, first] = within(screen.getByRole("table", { name: "共享规则列表" })).getAllByRole("row");
  expect(within(first).getByText("changed.example")).toBeInTheDocument();
  click("删除第 2 条规则");
  expect(screen.queryByText("one.example")).not.toBeInTheDocument();
  click("保存并应用");
  await waitFor(() => expect(commands.saveSharedRouting).toHaveBeenCalledWith([
    { matcher: "DomainSuffix", value: "changed.example", action: "Direct", enabled: false },
  ], []));
});

it("imports the remote source and attached RULE-SET draft together", async () => {
  setup();
  await screen.findByText("还没有共享规则");
  fireEvent.click(screen.getByRole("tab", { name: "规则集" }));
  expect(screen.getByText("还没有远程规则集")).toBeInTheDocument();
  click("导入规则集");
  input("规则集名称", "regional");
  input("远程地址", "not-a-url");
  click("导入");
  expect(screen.getByText("输入不含凭据或片段的 HTTP(S) 地址")).toBeInTheDocument();
  input("远程地址", "https://rules.example/regional.mrs");
  choose("文件格式", "MRS");
  expect(screen.getByText("MRS 仅适用于域名或 IP 网段")).toBeInTheDocument();
  choose("规则类型", "域名");
  choose("处理方式", "阻断");
  click("导入");
  expect(screen.getByText("rules.example")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "规则集 regional 仍被引用" })).toBeDisabled();
  fireEvent.click(screen.getByRole("tab", { name: "规则" }));
  expect(screen.getByText("RULE-SET")).toBeInTheDocument();
  expect(screen.getByText("regional")).toBeInTheDocument();
  click("保存并应用");
  await waitFor(() => expect(commands.saveSharedRouting).toHaveBeenCalledWith(
    [{ matcher: "RuleSet", value: "regional", action: "Reject", enabled: true }],
    [{ name: "regional", url: "https://rules.example/regional.mrs", behavior: "Domain", format: "Mrs", interval: 86400 }],
  ));
});

it("keeps the draft on backend validation failure", async () => {
  setup();
  vi.mocked(commands.saveSharedRouting).mockResolvedValue({
    status: "error", error: [{ InvalidProxy: { name: "规则 1", reason: "无效的类别" } }],
  });
  await screen.findByText("还没有共享规则");
  click("中国大陆直连");
  click("保存并应用");
  expect(await screen.findByText("规则 1：无效的类别")).toBeInTheDocument();
  expect(screen.getByText("尚未保存")).toBeInTheDocument();
  click("还原更改");
  expect(await screen.findByText("还没有共享规则")).toBeInTheDocument();
});
