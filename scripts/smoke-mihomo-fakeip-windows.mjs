// Exercise A/AAAA against the actual Windows Mihomo binary without changing
// the runner's routes or DNS. The exact unmodified TUN fixture is separately
// validated with mihomo -t; here only a loopback test DNS socket is added and
// OS capture is removed.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { Resolver } from "node:dns/promises";
import { createSocket } from "node:dgram";
import { once } from "node:events";
import { copyFile, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

const [core, fixture, geosite] = process.argv.slice(2).map((path) => resolve(path));
assert.ok(core && fixture, "Usage: node smoke-mihomo-fakeip-windows.mjs <core> <fakeip.yaml> [GeoSite.dat]");
const source = (await readFile(fixture, "utf8")).replace(/\r\n/g, "\n");

async function freeLoopbackPort() {
  const socket = createSocket("udp4");
  socket.bind(0, "127.0.0.1");
  await once(socket, "listening");
  const { port } = socket.address();
  socket.close();
  await once(socket, "close");
  return port;
}

const port = await freeLoopbackPort();
assert.match(source, /^tun:\n[ ]+enable: true$/m);
assert.match(source, /^dns:\n/m);
const tun = /^tun:\n(?:[^\S\n][^\n]*\n)+/m;
const withoutTun = source.replace(tun, "");
assert.doesNotMatch(withoutTun, /^tun:/m);
const local = withoutTun.replace(/^dns:\n/m, `dns:\n  listen: 127.0.0.1:${port}\n`);

const home = await mkdtemp(join(tmpdir(), "routa-fakeip-core-"));
let child, exit;
let log = "";
try {
  if (geosite) await copyFile(geosite, join(home, "GeoSite.dat"));
  const path = join(home, "test.yaml");
  await writeFile(path, local, { flag: "wx" });
  child = spawn(core, ["-d", home, "-f", path], { windowsHide: true });
  exit = once(child, "exit");
  exit.catch(() => {});
  for (const stream of [child.stdout, child.stderr]) {
    stream.on("data", (chunk) => { log = (log + chunk.toString()).slice(-6_000); });
  }
  const resolver = new Resolver({ timeout: 300, tries: 1 });
  resolver.setServers([`127.0.0.1:${port}`]);
  const host = "routa-fakeip-probe.example.com";
  let result;
  for (let attempt = 0; attempt < 30; attempt++) {
    assert.equal(child.exitCode, null, "Windows Mihomo exited before serving DNS");
    try {
      result = await resolver.resolve4(host);
      break;
    } catch (error) {
      if (!["ECONNREFUSED", "ETIMEOUT"].includes(error.code)) throw error;
      await delay(150);
    }
  }
  assert.equal(result?.length, 1, "expected one synthetic A record");
  assert.match(result[0], /^198\.18\./, "answer must come from the Fake-IP pool");
  assert.deepEqual(await resolver.resolve4(host), result, "mapping must be stable for repeated queries");
  await assert.rejects(() => resolver.resolve6(host), { code: "ENODATA" });
  console.log("Pinned Windows Mihomo returned a stable Fake-IP A and no synthetic AAAA. No OS routes were changed.");
} catch (error) {
  console.error(log);
  throw error;
} finally {
  if (child && child.exitCode === null) child.kill();
  if (exit) await exit;
  await rm(home, { force: true, recursive: true, maxRetries: 3 });
}
