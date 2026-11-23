import { filterCoreLogs, logTime, parseCoreLogs } from "./coreLogs";

it("parses the actual logrus format and decodes multiline errors without corrupting paths", () => {
  const raw = String.raw`time="2026-10-30T20:13:53.123456700+08:00" level=warning msg="[TCP] dial 机场 127.0.0.1:4001 --> example.com:443 error: i/o timeout\nretry failed\npath C:\\Apps\\core.exe says \"no\""`;
  const [entry] = parseCoreLogs(raw);
  expect(entry.timestamp).toBe("2026-10-30T20:13:53.123456700+08:00");
  expect(entry.level).toBe("warning");
  expect(entry.message).toBe('[TCP] dial 机场 127.0.0.1:4001 --> example.com:443 error: i/o timeout\nretry failed\npath C:\\Apps\\core.exe says "no"');
  expect(entry.raw).toBe(raw);
  expect(logTime(entry.timestamp)).toMatch(/^10-30 \d{2}:13:53$/);
});

it("accepts JSON, Go escapes, ANSI colors, plain messages, and unknown levels", () => {
  const entries = parseCoreLogs([
    JSON.stringify({ time: "2026-10-30T20:00:00+08:00", level: "error", msg: "JSON错误\n详情" }),
    '\x1b[32m[INFO] mihomo 已启动\x1b[0m',
    String.raw`level=debug msg="quote=\"ok\" tab=\t hex=\x41 unicode=\u4e2d wide=\U0001F600"`,
    'time="t" level=new msg="未来级别" field="extra"',
    "未识别的原始输出",
  ].join("\n"));
  expect(entries.map((entry) => entry.level)).toEqual(["error", "info", "debug", "unknown", "unknown"]);
  expect(entries[0].message).toBe("JSON错误\n详情");
  expect(entries[1].message).toBe("mihomo 已启动");
  expect(entries[2].message).toBe('quote="ok" tab=\t hex=A unicode=中 wide=😀');
  expect(entries[3].message).toContain("field=extra");
  expect(entries[4].message).toBe("未识别的原始输出");
});

it("keeps raw malformed records and attaches indented continuations without losing content", () => {
  const entries = parseCoreLogs('[INFO] 启动\n  后续详情\ntime="broken" level=error msg="未结束\n普通输出');
  expect(entries).toHaveLength(3);
  expect(entries[0].message).toBe("启动\n  后续详情");
  expect(entries[1].message).toContain('msg="未结束');
  expect(entries[1].level).toBe("unknown");
  expect(parseCoreLogs("")).toEqual([]);
  expect(parseCoreLogs("暂无内核日志")).toEqual([]);
});

it("has stable occurrence IDs and searches details as well as message summaries", () => {
  const text = '[INFO] old\n[WARN] warning\n[ERROR] failure\n[INFO] old';
  const before = parseCoreLogs(text);
  expect(new Set(before.map((entry) => entry.id)).size).toBe(4);
  expect(parseCoreLogs(text + '\n[INFO] new').slice(0, 4).map((entry) => entry.id)).toEqual(before.map((entry) => entry.id));
  expect(filterCoreLogs(before, "problems", "").map((entry) => entry.message)).toEqual(["warning", "failure"]);
  expect(filterCoreLogs(before, "error", "FAILURE")).toHaveLength(1);
  expect(filterCoreLogs(before, "warning", "failure")).toHaveLength(0);
  expect(logTime("")).toBe("时间未知");
  expect(logTime("invalid")).toBe("invalid");
});

const beforeApply = Date.parse("2026-10-30T20:00:00+08:00") / 1000;
const afterApply = "2026-10-30T20:00:01.123456700+08:00";

it("labels only the dial route and keeps source, matched rule, destination, error and raw content", () => {
  const key = "代理-a12";
  const rawMessage = `[TCP] dial ${key} (match Domain/${key}) [::1]:5000(chrome.exe, uid=1) --> ${key}.example:443 error: ${key} timed out\nfollow-up: ${key}`;
  const raw = JSON.stringify({ time: afterApply, level: "warning", msg: rawMessage });
  const [entry] = parseCoreLogs(raw, { [key]: "家宽/节点 [日本]", [key + "-long"]: "不能串线" }, beforeApply);
  expect(entry.message).toBe(rawMessage.replace(`dial ${key}`, "dial 家宽/节点 [日本]"));
  expect(entry.raw).toBe(raw);
  expect(filterCoreLogs([entry], "warning", "家宽/节点")).toEqual([entry]);
  expect(filterCoreLogs([entry], "warning", key)).toEqual([entry]);

  const unknown = JSON.stringify({ time: afterApply, level: "warning", msg: `[UDP] dial ${key}-unknown mihomo --> 127.0.0.1:53 error: no route` });
  expect(parseCoreLogs(unknown, { [key]: "家宽/节点" }, beforeApply)[0].message).toContain(`dial ${key}-unknown`);
});

it("shows the confirmed leaf rather than a group and refuses literal/group encoding collisions", () => {
  const leaf = "代理-123/机场/美国 [01]/家宽";
  const group = "自动 [节点] 组";
  const prefix = "[UDP] 127.0.0.1:49430(sClient.exe) --> dns.example.com:53 match Match using ";
  const encoded = `${group}[${leaf}]`;
  const raw = `time="${afterApply}" level=info msg="${prefix}${encoded}"`;
  const routes = { [group]: "端口 · 自动选择", [leaf]: "美国 [01]/家宽" };
  const leaves = { [leaf]: "美国 [01]/家宽" };
  expect(parseCoreLogs(raw, routes, beforeApply, leaves)[0].message).toBe(prefix + "美国 [01]/家宽");
  expect(parseCoreLogs(raw, { ...routes, [encoded]: "碰撞" }, beforeApply, leaves)[0].message).toBe(prefix + encoded);
  expect(parseCoreLogs(raw, { [group]: "端口 · 自动选择" }, beforeApply)[0].message).toBe(prefix + encoded);
  const onlyLeaf = `time="${afterApply}" level=info msg="${prefix}${leaf}"`;
  expect(parseCoreLogs(onlyLeaf, routes, beforeApply, leaves)[0].message).toBe(prefix + "美国 [01]/家宽");
});

it("does not apply current aliases to historical, same-second, malformed, or undated records", () => {
  const maliciousBody = "[TCP] dial 代理-123 mihomo --> example.com:443 error: fail";
  const text = ["2026-10-30T19:59:59+08:00", "2026-10-30T20:00:00.999999+08:00", "bad-date", ""]
    .map((time) => `time="${time}" level=warning msg="${maliciousBody}"`).join("\n");
  expect(parseCoreLogs(text, { "代理-123": "当前节点" }, beforeApply).map((entry) => entry.message))
    .toEqual([maliciousBody, maliciousBody, maliciousBody, maliciousBody]);
  const unstructured = `2026-10-30T20:00:01+08:00 [WARN] ${maliciousBody}`;
  expect(parseCoreLogs(unstructured, { "代理-123": "当前节点" }, beforeApply)[0].message)
    .toBe(maliciousBody.replace("代理-123", "当前节点"));
  expect(parseCoreLogs(unstructured, { "代理-123": "当前节点" }, null)[0].message).toBe(maliciousBody);
});

it("resolves confirmed direct/reject terminals in wrapped core routes without guessing a group member", () => {
  const prefix = "[TCP] 127.0.0.1:50720 --> example.test:443 using ";
  const raw = ["DIRECT", "REJECT", "__unconfirmed"].map((route) =>
    `time="${afterApply}" level=info msg="${prefix}__target_x[${route}]"`).join("\n");
  const routes = { __target_x: "测试 · 策略组", DIRECT: "直连", REJECT: "阻断" };
  const leaves = { DIRECT: "直连", REJECT: "阻断" };
  expect(parseCoreLogs(raw, routes, beforeApply, leaves).map((entry) => entry.message))
    .toEqual([prefix + "直连", prefix + "阻断", prefix + "__target_x[__unconfirmed]"]);
});
