#!/usr/bin/env node
// Start the proxy, and say clearly what has to happen once for it to be useful.

import { createLocalCa } from "../lib/ca.ts";
import { createPinClient } from "../lib/pins.ts";
import { createProxy } from "../lib/proxy.ts";
import { loadConfig } from "../lib/config.ts";

const config = loadConfig();
const log = config.logging ? (line: string) => console.log(`[proxy] ${line}`) : () => {};

const ca = createLocalCa({ dir: `${config.dir}/ca`, tlds: config.tlds });
await ca.ensure();

const pins = createPinClient({
  base: config.registryBase,
  overrides: config.overrides,
  tofu: config.tofu,
});

const proxy = createProxy({
  pins,
  ca,
  gatewayHost: config.gatewayHost,
  gatewayPort: config.gatewayPort,
  listenHost: config.listenHost,
  listenPort: config.listenPort,
  tlds: config.tlds,
  tofu: config.tofu,
  log,
});

const port = await proxy.listen();

console.log(`[proxy] listening on ${config.listenHost}:${port}`);
console.log(`[proxy] gateway   ${config.gatewayHost}:${config.gatewayPort}`);
console.log(`[proxy] registry  ${config.registryBase}`);
console.log(`[proxy] namespace ${config.tlds.map((t) => `.${t}`).join(" ")}`);
if (Object.keys(config.overrides).length) {
  console.log(`[proxy] pin overrides for ${Object.keys(config.overrides).length} name(s)`);
}
if (config.tofu) {
  console.warn("[proxy] TOFU IS ON — the first key seen for a name is accepted unverified");
}
console.log(`[proxy] root CA   ${ca.rootCertPath()}`);
console.log(`[proxy]           ${await ca.fingerprint()}`);
console.log("[proxy] trust it once: see README, 'Trusting the local root'");

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    const s = proxy.stats();
    console.log(
      `\n[proxy] ${s.verified} verified, ${s.refusedNoPin} unpinned, ` +
      `${s.refusedBadPin} key mismatches, ${s.upstreamErrors} upstream errors`,
    );
    void proxy.close().then(() => process.exit(0));
  });
}
