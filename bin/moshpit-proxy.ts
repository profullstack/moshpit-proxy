#!/usr/bin/env node
// Start the proxy, and say clearly what has to happen once for it to be useful.

import { createLocalCa } from "../lib/ca.ts";
import { createPinClient } from "../lib/pins.ts";
import { createProxy, namespaceTest } from "../lib/proxy.ts";
import { createHttpProxy } from "../lib/http.ts";
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

// Port 80 as well, unless the host needs it for something else. Proxy mode
// points Moshpit names at loopback, so a browser reaches 80 or 443 and nothing
// can be arranged in between; taking only 443 left every http:// Moshpit name
// answering with whatever web server the machine already ran.
//
// Never fatal. A machine that cannot bind 80 — no privilege, or nginx already
// there — still has a working https:// proxy, which is the half that needs this
// program at all.
const http = config.httpPort
  ? createHttpProxy({
    pins,
    gatewayHost: config.gatewayHost,
    listenHost: config.listenHost,
    listenPort: config.httpPort,
    inNamespace: namespaceTest(config.tlds),
    log,
  })
  : null;
let httpPort: number | null = null;
if (http) {
  try {
    httpPort = await http.listen();
  } catch (error) {
    console.warn(
      `[proxy] port ${config.httpPort} is not available — http:// on a Moshpit name will reach ` +
      `whatever else is listening there (${(error as Error)?.message ?? error})`,
    );
  }
}

console.log(`[proxy] listening on ${config.listenHost}:${port}`);
if (httpPort) console.log(`[proxy] http      ${config.listenHost}:${httpPort} — forwarded, not verified`);
console.log(`[proxy] gateway   ${config.gatewayHost}:${config.gatewayPort}`);
console.log(`[proxy] registry  ${config.registryBase}`);
console.log(config.tlds.length
  ? `[proxy] namespace ${config.tlds.map((t) => `.${t}`).join(" ")}`
  : "[proxy] namespace every Moshpit ending — anything IANA does not delegate");
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
    void Promise.all([proxy.close(), http?.close()]).then(() => process.exit(0));
  });
}
