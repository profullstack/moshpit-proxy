#!/usr/bin/env node
// The c0mpute edge: serves Moshpit names pointed at c0mpute sites over https.
// See lib/c0mpute-edge.ts for what it does and why, and the README's
// "c0mpute edge" section for how to run one.

import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { CertStore, GatewayPool, SiteLookup, startEdge } from "../lib/c0mpute-edge.ts";

/** `host:port` or `[v6]:port`, or null. */
export function hostPort(v: string | undefined): { host: string; port: number } | null {
  const m = String(v || "").trim().match(/^(?:\[([0-9a-fA-F:.]+)\]|([^:\s\[\]]+)):(\d{1,5})$/);
  if (!m) return null;
  const port = Number(m[3]);
  return port > 0 && port < 65536 ? { host: m[1] ?? m[2], port } : null;
}

export function edgeConfig(env: Record<string, string | undefined> = process.env) {
  const int = (v: string | undefined, d: number) => (v !== undefined && /^\d+$/.test(v) ? Number(v) : d);
  return {
    host: env.EDGE_HOST || "::",
    httpsPort: int(env.EDGE_HTTPS_PORT, 443),
    httpPort: int(env.EDGE_HTTP_PORT, 80),
    registryBase: env.MOSHPIT_REGISTRY_BASE || "https://pit.moshcode.sh",
    apiKey: env.MOSHPIT_API_KEY || "",
    certDir: env.EDGE_CERT_DIR || "/var/lib/moshpit/c0mpute-edge",
    seeds: (env.C0MPUTE_GATEWAYS || "").split(/[\s,]+/).filter(Boolean),
    // The public node list, for gateways that announce a URL. Empty disables
    // discovery and the edge uses the seeds alone.
    nodesUrl: env.C0MPUTE_NODES_URL === undefined ? "https://c0mpute.com/api/nodes" : env.C0MPUTE_NODES_URL || null,
    // Behind an SNI router (see the README): a PROXY protocol header on every
    // https connection, and where the names that are not c0mpute sites go.
    proxyProtocol: /^(1|true|yes|on)$/i.test(env.EDGE_PROXY_PROTOCOL || ""),
    fallback: hostPort(env.EDGE_FALLBACK),
    refreshMs: int(env.C0MPUTE_REFRESH_SECONDS, 60) * 1000,
  };
}

async function main() {
  const cfg = edgeConfig();
  const log = (line: string) => console.log(line);
  if (!cfg.apiKey) log("[edge] warning: MOSHPIT_API_KEY is not set; only certificates already on disk can be served");

  const gateways = new GatewayPool({ seeds: cfg.seeds, nodesUrl: cfg.nodesUrl });
  await gateways.refresh();
  if (!gateways.size) log("[edge] warning: no c0mpute gateways known yet (set C0MPUTE_GATEWAYS)");
  const timer = setInterval(() => { void gateways.refresh(); }, cfg.refreshMs);
  timer.unref();

  const sites = new SiteLookup({ registryBase: cfg.registryBase });
  const certs = new CertStore({ dir: cfg.certDir, registryBase: cfg.registryBase, apiKey: cfg.apiKey, log });
  await startEdge({ sites, gateways, certs, host: cfg.host, httpsPort: cfg.httpsPort, httpPort: cfg.httpPort,
    proxyProtocol: cfg.proxyProtocol, fallback: cfg.fallback, log });
  log(`[edge] serving c0mpute sites on https :${cfg.httpsPort}${cfg.httpPort ? ` and http :${cfg.httpPort}` : ""}; ${gateways.size} gateway(s) known${cfg.fallback ? `; other names to ${cfg.fallback.host}:${cfg.fallback.port}` : ""}`);
}

const invoked = (() => { try { return realpathSync(process.argv[1] ?? "") === fileURLToPath(import.meta.url); } catch { return false; } })();
if (invoked) {
  main().catch((e) => { console.error(`[edge] ${e.message}`); process.exit(1); });
}
