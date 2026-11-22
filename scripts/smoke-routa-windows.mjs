// Drives the packaged Windows app's own WebView2, not a browser preview.
import { execFile, spawn } from "node:child_process";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const exec = promisify(execFile);
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));
const captureScript = fileURLToPath(new URL("./capture-routa-window.ps1", import.meta.url));
const [exePath, outputPath] = process.argv.slice(2);
if (process.platform !== "win32" || process.env.GITHUB_ACTIONS !== "true" ||
    process.env.RUNNER_ENVIRONMENT !== "github-hosted" || !process.env.RUNNER_TEMP) {
  throw new Error("Native Routa smoke is restricted to a fresh GitHub-hosted Windows runner.");
}
if (!exePath || !outputPath) throw new Error("Usage: node scripts/smoke-routa-windows.mjs <routa.exe> <output>");

const exe = resolve(exePath);
const output = resolve(outputPath);
const fixture = await mkdtemp(join(process.env.RUNNER_TEMP, "routa-smoke-"));
await mkdir(output, { recursive: true });
await mkdir(join(fixture, "Roaming"));
await mkdir(join(fixture, "Local"));
const report = { application: "Routa Preview / Windows WebView2", status: "failed", images: [] };
const port = await new Promise((done, reject) => {
  const server = createServer();
  server.on("error", reject).listen(0, "127.0.0.1", () => {
    const allocated = server.address().port;
    server.close((error) => error ? reject(error) : done(allocated));
  });
});
const app = spawn(exe, [], {
  cwd: dirname(exe),
  env: {
    ...process.env,
    APPDATA: join(fixture, "Roaming"),
    LOCALAPPDATA: join(fixture, "Local"),
    WEBVIEW2_USER_DATA_FOLDER: join(fixture, "webview"),
    WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS:
      `--remote-debugging-address=127.0.0.1 --remote-debugging-port=${port}`,
  },
  stdio: "ignore",
});
const appFailure = new Promise((_, reject) => {
  app.once("error", reject);
  app.once("exit", (code) => reject(new Error(`Routa exited early (${code})`)));
});
// The process lifetime is also checked during each timer and command.
appFailure.catch(() => {});

async function wait(label, probe, limit = 30_000) {
  const deadline = Date.now() + limit;
  let lastError;
  while (Date.now() < deadline) {
    if (app.exitCode !== null) throw new Error(`Routa exited while waiting for ${label}`);
    try {
      const result = await probe();
      if (result) return result;
    } catch (error) {
      lastError = error;
    }
    await sleep(200);
  }
  throw new Error(`Timed out waiting for ${label}${lastError ? `: ${lastError.message}` : ""}`);
}

let socket;
let call;
const evaluate = async (expression) => {
  const response = await call("Runtime.evaluate", {
    expression, returnByValue: true, awaitPromise: true,
  });
  if (response.exceptionDetails) throw new Error(response.exceptionDetails.text);
  return response.result.value;
};
const expression = (fn, ...args) => `(${fn.toString()})(...${JSON.stringify(args)})`;

function locate(selector, label, partial, input, operation) {
  const normalize = (value) => (value ?? "").replace(/\s+/g, " ").trim();
  for (const match of document.querySelectorAll(selector)) {
    const names = [match.innerText, match.textContent, match.getAttribute("aria-label")].map(normalize);
    if (label && !names.some((name) => partial ? name.includes(label) : name === label)) continue;
    const el = input ? (match.control || match.querySelector("input")) : match;
    if (!el || el.disabled || el.getAttribute("aria-disabled") === "true" ||
        el.getClientRects().length === 0) continue;
    el.scrollIntoView({ block: "center", inline: "nearest" });
    if (operation === "click") el.click();
    if (operation === "focus") el.focus();
    return { checked: el.checked ?? null, value: el.value ?? null,
      pressed: el.getAttribute("aria-pressed") === "true" };
  }
  return null;
}

async function find(selector, label, { partial = false, input = false, operation } = {}) {
  return wait(label || selector, () => evaluate(expression(locate, selector, label, partial, input, operation)));
}

async function click(selector, label, options = {}) {
  await find(selector, label, { ...options, operation: "click" });
}

async function navigate(path) {
  // Route anchors are not vulnerable to sidebar text/hit-testing differences.
  const route = "#/" + path;
  await click(`nav[aria-label="主导航"] a[href="${route}"]`);
  await wait(`navigation to ${route}`, () => evaluate(expression((target) =>
    location.hash === target, route)));
}

async function fill(label, value) {
  await find("label", label, { input: true, operation: "focus" });
  await evaluate("document.activeElement.select()");
  await call("Input.insertText", { text: value });
  await wait(label + " input", () => evaluate(expression((expected) =>
    document.activeElement?.value === expected, value)));
}

async function text(value) {
  await wait(value, () => evaluate(expression((expected) =>
    document.body.innerText.includes(expected), value)));
}

async function resize(width) {
  await exec("pwsh", ["-NoProfile", "-File", captureScript, "-ProcessId", String(app.pid),
    "-Width", String(width)], { timeout: 12_000, windowsHide: true });
}

async function capture(stem) {
  await sleep(240);
  const dimensions = call
    ? await evaluate("({width: innerWidth, height: innerHeight})").catch(() => ({}))
    : {};
  let filename = stem + ".png";
  let method;
  try {
    const { stdout } = await exec("pwsh", ["-NoProfile", "-File", captureScript,
      "-ProcessId", String(app.pid), "-Output", join(output, filename)],
    { timeout: 12_000, windowsHide: true });
    method = stdout.trim().split(/\r?\n/).at(-1);
    if (!["windows-desktop", "windows-printwindow"].includes(method)) throw new Error("Native window capture didn't finish");
  } catch (error) {
    if (!call) throw error;
    // Some hosted runners expose an off-screen desktop. This is still the
    // actual Windows app's rendered content, but omits the native title bar.
    console.warn(`Native frame capture unavailable for ${stem}; using real WebView2 surface: ${error.message}`);
    const { data } = await call("Page.captureScreenshot", {
      format: "png", fromSurface: true, captureBeyondViewport: false,
    });
    const png = Buffer.from(data, "base64");
    if (png.length < 1000 || png.subarray(1, 4).toString() !== "PNG") {
      throw new Error("WebView2 did not return a usable PNG");
    }
    filename = stem + "-webview.png";
    await writeFile(join(output, filename), png);
    method = "windows-webview2";
  }
  report.images.push({ filename, method, ...dimensions });
}

try {
  const target = await Promise.race([appFailure, wait("Routa WebView2 DevTools target", async () => {
    const res = await fetch(`http://127.0.0.1:${port}/json/list`, { signal: AbortSignal.timeout(1500) });
    if (!res.ok) return null;
    return (await res.json()).find((target) => target.type === "page" &&
      new URL(target.url).hostname === "tauri.localhost" && target.webSocketDebuggerUrl);
  }, 60_000)]);
  const debuggerUrl = new URL(target.webSocketDebuggerUrl);
  if (debuggerUrl.protocol !== "ws:" || debuggerUrl.hostname !== "127.0.0.1" ||
      Number(debuggerUrl.port) !== port) throw new Error("Unexpected WebView2 debugger endpoint");
  socket = new WebSocket(debuggerUrl);
  await Promise.race([appFailure, new Promise((done, reject) => {
    const timer = setTimeout(() => reject(new Error("WebView2 debugger connection timed out")), 8_000);
    socket.addEventListener("open", () => { clearTimeout(timer); done(); }, { once: true });
    socket.addEventListener("error", () => { clearTimeout(timer); reject(new Error("WebView2 debugger connection failed")); }, { once: true });
  })]);
  let id = 0;
  const pending = new Map();
  socket.addEventListener("message", ({ data }) => {
    const { id, result, error } = JSON.parse(data);
    const reply = pending.get(id);
    if (!reply) return;
    pending.delete(id);
    clearTimeout(reply.timer);
    if (error) reply.reject(new Error(error.message)); else reply.done(result);
  });
  call = (method, params) => new Promise((done, reject) => {
    const request = ++id;
    const timer = setTimeout(() => {
      pending.delete(request);
      reject(new Error(`WebView2 ${method} timed out`));
    }, 8_000);
    pending.set(request, { done, reject, timer });
    socket.send(JSON.stringify({ id: request, method, params }));
  });

  report.stage = "select full mode";
  const fullNavigation = 'nav[aria-label="主导航"]';
  if (!await evaluate(expression((selector) => !!document.querySelector(selector), fullNavigation))) {
    await click("button", "完整版", { partial: true });
    await wait("full-mode choice selected", async () => (await evaluate(expression(
      locate, "button", "完整版", true, false,
    )))?.pressed);
    await click("button", "开始使用");
    await wait("full-mode navigation after onboarding", () => evaluate(expression((selector) =>
      !!document.querySelector(selector), fullNavigation)));
  }

  report.stage = "proxy baseline";
  await navigate("listeners");
  await find("button", "新增代理");
  await resize(1120);
  await wait("wide native window", async () => await evaluate("innerWidth") >= 1050);
  await capture("00-proxies-baseline");

  report.stage = "shared rules empty";
  await navigate("shared-routing");
  await find("button", "新增规则");
  await text("还没有共享规则");
  await capture("01-shared-rules-empty");

  report.stage = "save a shared rule";
  await click("button", "新增规则");
  await text("新增共享规则");
  await fill("匹配内容", "windows-smoke.example");
  await click("[role=dialog] button", "保存");
  await click("button", "中国大陆直连");
  await click("button", "保存并应用");
  await wait("shared rules apply finished", () => evaluate(`Array.from(document.querySelectorAll("button")).some(
    (el) => el.innerText.trim() === "保存并应用" && el.disabled && el.querySelector("[role=progressbar]") === null
  )`));
  await text("windows-smoke.example");
  await text("GEOSITE");
  await text("GEOIP");
  await evaluate(`Array.from(document.querySelectorAll('[role="alert"]'))
    .find(el => el.textContent.includes("共享规则已保存并应用"))?.querySelector("button")?.click()`);
  await capture("02-shared-rules");

  report.stage = "verify port inheritance";
  await navigate("listeners");
  await click("button", "新增代理");
  await fill("名称", "Windows smoke");
  await click("[role=dialog] button", "直连");
  const inheritance = await find("[role=dialog] label", "继承共享规则", { input: true });
  if (!inheritance.checked) await click("[role=dialog] label", "继承共享规则", { input: true });
  await wait("inheritance checked", async () =>
    (await find("[role=dialog] label", "继承共享规则", { input: true })).checked);
  await capture("03-port-inherits-shared-rules");
  await click("[role=dialog] summary", "高级选项");
  const enabled = await find("[role=dialog] label", "启用代理", { input: true });
  if (enabled.checked) await click("[role=dialog] label", "启用代理", { input: true });
  await click("[role=dialog] button", "保存");
  await click("button", "编辑 Windows smoke");
  const reopened = await find("[role=dialog] label", "继承共享规则", { input: true });
  if (!reopened.checked) throw new Error("Saved port no longer inherits shared rules");
  await click("[role=dialog] button", "取消");
  report.stage = "narrow shared rules";
  await navigate("shared-routing");
  await text("windows-smoke.example");
  await text("1 个代理继承");

  const baselineWidth = await evaluate("innerWidth");
  await resize(940);
  await wait("actual narrower native window", async () => await evaluate("innerWidth") < baselineWidth - 20);
  await wait("single-line rule order header", () => evaluate(`Array.from(document.querySelectorAll("th"))
    .some(el => el.textContent.trim() === "顺序" && getComputedStyle(el).whiteSpace === "nowrap")`));
  await capture("04-shared-rules-narrow");
  report.stage = "complete";
  report.status = "passed";
} catch (error) {
  report.error = error.message;
  if (call) {
    try {
      report.page = await evaluate(expression(() => ({
        hash: location.hash,
        readyState: document.readyState,
        viewport: { width: innerWidth, height: innerHeight },
        navigation: [...document.querySelectorAll("nav")].map((nav) => nav.getAttribute("aria-label")),
        controls: [...document.querySelectorAll("h1,h2,nav a,button,[role=alert]")]
          .filter((el) => el.getClientRects().length > 0)
          .slice(0, 32)
          .map((el) => ({
            label: (el.getAttribute("aria-label") || el.innerText || "").trim().slice(0, 120),
            pressed: el.getAttribute("aria-pressed"),
            disabled: el.disabled ?? null,
          })),
      })));
      console.error("Routa smoke UI state:", JSON.stringify(report.page));
    } catch (diagnosticError) {
      report.diagnosticError = diagnosticError.message;
    }
  }
  if (app.pid && app.exitCode === null) {
    await capture("99-smoke-failure").catch((captureError) => {
      report.screenshotError = captureError.message;
    });
  }
  throw error;
} finally {
  socket?.close();
  if (app.pid && app.exitCode === null) {
    await exec("taskkill.exe", ["/PID", String(app.pid), "/T", "/F"], { timeout: 8_000, windowsHide: true })
      .catch((error) => console.warn("Could not stop the Routa smoke process:", error.message));
  }
  await writeFile(join(output, "windows-ui-smoke.json"), JSON.stringify(report, null, 2) + "\n");
}
