#!/usr/bin/env node
// Start the proxy, and say clearly what has to happen once for it to be useful.

import { createLocalCa } from "../lib/ca.ts";
import { createPinClient } from "../lib/pins.ts";
import { createProxy } from "../lib/proxy.ts";
import { loadConfig } from "../lib/config.ts";
import { probeDetector, HYBRID_GROUP } from "../lib/pq.ts";

const config = loadConfig();
const log = config.logging ? (line: string) => console.log(`[proxy] ${line}`) : () => {};

// Prove the post-quantum detector before anything depends on it. Two loopback
// handshakes, once, at startup — cheap enough to be unconditional, and the
// alternative is enforcing a policy on a signal nobody checked.
const probe = await probeDetector();
const requirePq = config.requirePq && probe.usable;
if (config.requirePq && !probe.usable) {
  console.warn(`[proxy] MOSHPIT_PROXY_REQUIRE_PQ ignored — ${probe.detail}`);
}

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
  requirePq,
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
console.log(
  `[proxy] post-qm  ${probe.hybridAvailable ? `${HYBRID_GROUP} offered to every origin` : "UNAVAILABLE on this build"}` +
  `${requirePq ? ", required" : ", observed only"}`,
);
console.log(`[proxy]           ${probe.detail}`);
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
    console.log(
      `[proxy] ${s.pqSessions} post-quantum, ${s.classicalSessions} classical` +
      `${s.refusedClassical ? `, ${s.refusedClassical} refused for it` : ""}`,
    );
    void proxy.close().then(() => process.exit(0));
  });
}
