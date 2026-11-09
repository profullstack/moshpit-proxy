// The c0mpute edge: https://<moshpit name> for a site that lives on c0mpute.
//
// c0mpute keeps static sites alive peer to peer. Hosting nodes hold copies,
// and every c0mpute gateway serves any site at http://<gateway>:7777/s/<site>/,
// fetching chunks from whichever holder answers and checking each against its
// hash. What a gateway cannot do is answer https://blue.eggs: it speaks plain
// HTTP and holds no certificate for a Moshpit name.
//
// This is the piece that does. The registry resolves a name whose holder set
// `c0mpute=<site>` to this edge's hostname. The edge:
//
//   1. reads the SNI, asks the registry which site the name is, and presents a
//      leaf the Moshpit CA signs for the name (asked for on first use with the
//      edge's API key, which the registry honours only while the holder has the
//      name pointed at c0mpute);
//   2. maps https://blue.eggs/path to /s/<site>/path on a healthy c0mpute
//      gateway, fastest first, failing over to the next on a refused
//      connection, a timeout or a 5xx.
//
// Nothing on the c0mpute side is special about this: any gateway serves any
// site, so there is no c0mpute server on the path to lose. Gateways are
// discovered from seeds and from the public node list (nodes that announce a
// gateway URL), and the last good list is kept when discovery fails.

import { execFile } from "node:child_process";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { createServer as createHttpServer } from "node:http";
import type { IncomingMessage, Server as HttpServer, ServerResponse } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import type { Server as HttpsServer } from "node:https";
import { X509Certificate } from "node:crypto";
import { createSecureContext } from "node:tls";
import type { SecureContext, TLSSocket } from "node:tls";
import { join } from "node:path";
import type { Server as NetServer } from "node:net";
import { createSniFront } from "./sni-front.ts";
import { promisify } from "node:util";

const run = promisify(execFile);

/** A c0mpute site id: 20 lowercase hex. */
export const SITE_RE = /^[0-9a-f]{20}$/;

const NAME_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?\.[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;

/** `label.tld`, lowercased, or null. Only the shape the registry holds. */
export function normalizeHost(input: string | undefined | null): string | null {
  const raw = String(input ?? "").trim().toLowerCase().replace(/\.$/, "");
  const host = raw.replace(/:\d+$/, "");
  return NAME_RE.test(host) ? host : null;
}

/* ------------------------------------------------------------- gateways */

/** An http(s) origin with no path, or null. */
export function normalizeGateway(input: unknown): string | null {
  if (typeof input !== "string" || input.length > 300) return null;
  let url: URL;
  try { url = new URL(input.trim()); } catch { return null; }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  if (url.username || url.password) return null;
  return url.origin;
}

/**
 * Gateway origins out of a c0mpute node list (`/api/nodes` or an aggregator's
 * `/nodes`): every node that announces one in `gateway`.
 */
export function gatewaysFromNodes(payload: unknown): string[] {
  const nodes = (payload as { nodes?: unknown })?.nodes;
  if (!Array.isArray(nodes)) return [];
  const out = new Set<string>();
  for (const node of nodes) {
    const url = normalizeGateway((node as { gateway?: unknown })?.gateway);
    if (url) out.add(url);
  }
  return [...out];
}

type GatewayState = { url: string; healthy: boolean; rttMs: number; failures: number; downUntil: number };

export interface GatewayPoolOptions {
  seeds?: string[];
  /** A node list to discover gateways from; null disables discovery. */
  nodesUrl?: string | null;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  now?: () => number;
}

/**
 * The gateways worth sending a request to, best first.
 *
 * Health is checked (`/healthz`) on refresh and learned from real traffic in
 * between: a gateway that fails a request sits out for a while, longer each
 * time, and comes back on the next good answer. Among equally fast gateways
 * the order rotates, so one does not take all the load.
 */
export class GatewayPool {
  private states = new Map<string, GatewayState>();
  private seeds: string[];
  private nodesUrl: string | null;
  private fetchImpl: typeof fetch;
  private timeoutMs: number;
  private now: () => number;
  private turn = 0;

  constructor(opts: GatewayPoolOptions = {}) {
    this.seeds = (opts.seeds ?? []).map(normalizeGateway).filter((u): u is string => Boolean(u));
    this.nodesUrl = opts.nodesUrl ?? null;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.timeoutMs = opts.timeoutMs ?? 3000;
    this.now = opts.now ?? Date.now;
    for (const url of this.seeds) this.ensure(url);
  }

  private ensure(url: string): GatewayState {
    let s = this.states.get(url);
    if (!s) {
      s = { url, healthy: true, rttMs: Number.MAX_SAFE_INTEGER, failures: 0, downUntil: 0 };
      this.states.set(url, s);
    }
    return s;
  }

  get size(): number { return this.states.size; }

  /** Rediscover and re-check every gateway. Never throws; a failed discovery keeps the old list. */
  async refresh(): Promise<void> {
    if (this.nodesUrl) {
      try {
        const res = await this.fetchImpl(this.nodesUrl, { signal: AbortSignal.timeout(this.timeoutMs) });
        if (res.ok) for (const url of gatewaysFromNodes(await res.json())) this.ensure(url);
      } catch { /* keep what we had */ }
    }
    await Promise.all([...this.states.values()].map((s) => this.check(s)));
  }

  private async check(s: GatewayState): Promise<void> {
    const started = this.now();
    try {
      const res = await this.fetchImpl(`${s.url}/healthz`, { signal: AbortSignal.timeout(this.timeoutMs) });
      await res.body?.cancel();
      if (!res.ok) throw new Error(String(res.status));
      s.rttMs = Math.max(0, this.now() - started);
      this.succeeded(s.url);
    } catch {
      this.failed(s.url);
    }
  }

  succeeded(url: string): void {
    const s = this.states.get(url);
    if (!s) return;
    s.healthy = true;
    s.failures = 0;
    s.downUntil = 0;
  }

  failed(url: string): void {
    const s = this.states.get(url);
    if (!s) return;
    s.failures += 1;
    s.healthy = false;
    // 10 s, 20 s, 40 s ... capped at 5 minutes.
    s.downUntil = this.now() + Math.min(300_000, 10_000 * 2 ** (s.failures - 1));
  }

  /**
   * Up to `n` gateways to try, in order. Healthy ones first (fastest, rotating
   * within the same 50 ms band), then any that are sitting out, so a request
   * still has somewhere to go when every gateway has had a bad minute.
   */
  pick(n = 3): string[] {
    const now = this.now();
    const all = [...this.states.values()];
    const up = all.filter((s) => s.healthy || s.downUntil <= now);
    const down = all.filter((s) => !up.includes(s)).sort((a, b) => a.downUntil - b.downUntil);
    const band = (s: GatewayState) => Math.floor(Math.min(s.rttMs, 3_600_000) / 50);
    up.sort((a, b) => band(a) - band(b) || a.failures - b.failures);
    if (up.length > 1) {
      const lead = up.filter((s) => band(s) === band(up[0]));
      const k = this.turn++ % lead.length;
      up.splice(0, lead.length, ...lead.slice(k), ...lead.slice(0, k));
    }
    return [...up, ...down].slice(0, n).map((s) => s.url);
  }
}

/* ---------------------------------------------------------------- sites */

export interface SiteLookupOptions {
  registryBase?: string;
  fetchImpl?: typeof fetch;
  ttlMs?: number;
  missTtlMs?: number;
  now?: () => number;
}

/** Which c0mpute site a name is, from the registry, cached briefly. */
export class SiteLookup {
  private cache = new Map<string, { site: string | null; until: number }>();
  private registryBase: string;
  private fetchImpl: typeof fetch;
  private ttlMs: number;
  private missTtlMs: number;
  private now: () => number;

  constructor(opts: SiteLookupOptions = {}) {
    this.registryBase = (opts.registryBase ?? "https://pit.moshcode.sh").replace(/\/+$/, "");
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.ttlMs = opts.ttlMs ?? 60_000;
    this.missTtlMs = opts.missTtlMs ?? 30_000;
    this.now = opts.now ?? Date.now;
  }

  async site(name: string): Promise<string | null> {
    const host = normalizeHost(name);
    if (!host) return null;
    const hit = this.cache.get(host);
    if (hit && hit.until > this.now()) return hit.site;
    let site: string | null = null;
    try {
      const res = await this.fetchImpl(`${this.registryBase}/api/moshpit/resolve?name=${encodeURIComponent(host)}`,
        { signal: AbortSignal.timeout(4000) });
      if (res.ok) {
        const json = (await res.json()) as { c0mpute?: unknown };
        site = typeof json.c0mpute === "string" && SITE_RE.test(json.c0mpute) ? json.c0mpute : null;
      } else {
        await res.body?.cancel();
      }
    } catch {
      // A registry outage keeps serving what was known rather than dropping
      // every site at once.
      if (hit) return hit.site;
      return null;
    }
    this.cache.set(host, { site, until: this.now() + (site ? this.ttlMs : this.missTtlMs) });
    if (this.cache.size > 10_000) this.cache.delete(this.cache.keys().next().value as string);
    return site;
  }
}

/* --------------------------------------------------------- certificates */

export interface CertStoreOptions {
  dir: string;
  registryBase?: string;
  apiKey?: string;
  fetchImpl?: typeof fetch;
  /** Renew when fewer than this many ms remain. */
  renewBeforeMs?: number;
  now?: () => number;
  log?: (line: string) => void;
}

type Loaded = { context: SecureContext; notAfter: number };

/**
 * Leaves for the names this edge serves, kept on disk and asked of the
 * registry's CA on first use. One request in flight per name; a renewal runs
 * in the background while the current leaf keeps being served.
 */
export class CertStore {
  private mem = new Map<string, Loaded>();
  private pending = new Map<string, Promise<Loaded | null>>();
  private opts: Required<Omit<CertStoreOptions, "apiKey">> & { apiKey: string };

  constructor(opts: CertStoreOptions) {
    this.opts = {
      registryBase: "https://pit.moshcode.sh",
      fetchImpl: fetch,
      renewBeforeMs: 10 * 24 * 3600 * 1000,
      now: Date.now,
      log: () => {},
      apiKey: "",
      ...opts,
    };
    this.opts.registryBase = this.opts.registryBase.replace(/\/+$/, "");
  }

  private paths(name: string) {
    return { cert: join(this.opts.dir, `${name}.crt`), key: join(this.opts.dir, `${name}.key`) };
  }

  /** A context for `name`, issuing one if needed. Null when none can be had. */
  async context(name: string): Promise<SecureContext | null> {
    const now = this.opts.now();
    const have = this.mem.get(name) ?? (await this.fromDisk(name));
    if (have && have.notAfter > now) {
      if (have.notAfter - now < this.opts.renewBeforeMs) void this.issueOnce(name);
      return have.context;
    }
    return (await this.issueOnce(name))?.context ?? null;
  }

  private async fromDisk(name: string): Promise<Loaded | null> {
    const p = this.paths(name);
    try {
      const [cert, key] = await Promise.all([readFile(p.cert, "utf8"), readFile(p.key, "utf8")]);
      const loaded = { context: createSecureContext({ cert, key }), notAfter: Date.parse(new X509Certificate(cert).validTo) };
      this.mem.set(name, loaded);
      return loaded;
    } catch {
      return null;
    }
  }

  private issueOnce(name: string): Promise<Loaded | null> {
    let p = this.pending.get(name);
    if (!p) {
      p = this.issue(name).catch((e: Error) => { this.opts.log(`[edge] cert ${name}: ${e.message}`); return null; })
        .finally(() => this.pending.delete(name));
      this.pending.set(name, p);
    }
    return p;
  }

  private async issue(name: string): Promise<Loaded> {
    if (!this.opts.apiKey) throw new Error("no MOSHPIT_API_KEY to ask the registry with");
    await mkdir(this.opts.dir, { recursive: true, mode: 0o700 });
    const { key, csr } = await makeCsr(name);
    const [label, tld] = name.split(".");
    const res = await this.opts.fetchImpl(`${this.opts.registryBase}/api/moshpit/tlds/${encodeURIComponent(tld)}/certs`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${this.opts.apiKey}` },
      body: JSON.stringify({ label, csr }),
      signal: AbortSignal.timeout(15_000),
    });
    const body = (await res.json().catch(() => null)) as { chain?: string; error?: string } | null;
    if (res.status !== 201 || !body?.chain) throw new Error(`registry said ${res.status}${body?.error ? `: ${body.error}` : ""}`);
    const p = this.paths(name);
    // Key first, then the chain, each by rename, so a crash never leaves a
    // chain on disk next to a key it does not match.
    await writeFile(`${p.key}.tmp`, key, { mode: 0o600 });
    await writeFile(`${p.cert}.tmp`, body.chain, { mode: 0o644 });
    await rename(`${p.key}.tmp`, p.key);
    await rename(`${p.cert}.tmp`, p.cert);
    const loaded = { context: createSecureContext({ cert: body.chain, key }), notAfter: Date.parse(new X509Certificate(body.chain).validTo) };
    this.mem.set(name, loaded);
    this.opts.log(`[edge] issued ${name} until ${new Date(loaded.notAfter).toISOString()}`);
    return loaded;
  }
}

/** A fresh P-256 key and a CSR for `name`, by openssl (what setup-origin.sh uses). */
export async function makeCsr(name: string): Promise<{ key: string; csr: string }> {
  if (!normalizeHost(name)) throw new Error(`not a name: ${name}`);
  // Key and request both to stdout in one call: no temp file holding a
  // private key, and no /dev/stdin, which is not there for every process.
  const { stdout } = await run("openssl", ["req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
    "-nodes", "-keyout", "-", "-out", "-", "-subj", `/CN=${name}`]);
  const key = stdout.match(/-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----\n?/)?.[0];
  const csr = stdout.match(/-----BEGIN CERTIFICATE REQUEST-----[\s\S]+?-----END CERTIFICATE REQUEST-----\n?/)?.[0];
  if (!key || !csr) throw new Error("openssl did not produce a key and a request");
  return { key, csr };
}

/* ------------------------------------------------------------- serving */

/** Response headers worth passing back from a gateway. */
const PASS_HEADERS = ["content-type", "content-length", "etag", "last-modified", "cache-control", "content-encoding"];

export interface EdgeHandlerOptions {
  sites: Pick<SiteLookup, "site">;
  gateways: Pick<GatewayPool, "pick" | "succeeded" | "failed">;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  attempts?: number;
  log?: (line: string) => void;
}

/** The gateway URL for a request path on a site. */
export function upstreamUrl(gateway: string, site: string, path: string): string {
  const rel = path.startsWith("/") ? path : `/${path}`;
  return `${gateway}/s/${site}${rel}`;
}

/** An HTTP handler serving c0mpute sites by Host, for both the http and https servers. */
export function createEdgeHandler(opts: EdgeHandlerOptions) {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const attempts = opts.attempts ?? 3;
  const log = opts.log ?? (() => {});

  return async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const send = (status: number, text: string) => {
      res.writeHead(status, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
      res.end(req.method === "HEAD" ? undefined : `${text}\n`);
    };

    const host = normalizeHost(req.headers.host);
    if (!host) return send(400, "this edge serves Moshpit names pointed at c0mpute sites");

    // Over TLS, the name asked for in the handshake and the Host must agree:
    // the certificate presented was for the SNI, and serving another name's
    // site under it would be serving a page the certificate does not vouch for.
    const sni = (req.socket as TLSSocket).servername;
    if (typeof sni === "string" && sni && normalizeHost(sni) !== host) return send(421, "misdirected request");

    if (req.method !== "GET" && req.method !== "HEAD") {
      res.setHeader("allow", "GET, HEAD");
      return send(405, "static site: GET and HEAD only");
    }

    const site = await opts.sites.site(host);
    if (!site) return send(404, `${host} does not point at a c0mpute site`);

    const path = (req.url || "/").startsWith("/") ? (req.url || "/") : "/";
    for (const gw of opts.gateways.pick(attempts)) {
      let upstream: Response;
      try {
        upstream = await fetchImpl(upstreamUrl(gw, site, path), {
          method: req.method,
          headers: {
            ...(req.headers["if-none-match"] ? { "if-none-match": String(req.headers["if-none-match"]) } : {}),
            ...(req.headers["accept-encoding"] ? { "accept-encoding": String(req.headers["accept-encoding"]) } : {}),
          },
          redirect: "manual",
          signal: AbortSignal.timeout(timeoutMs),
        });
      } catch (e) {
        opts.gateways.failed(gw);
        log(`[edge] ${host} via ${gw}: ${(e as Error).message}`);
        continue;
      }
      if (upstream.status >= 500) {
        await upstream.body?.cancel();
        opts.gateways.failed(gw);
        log(`[edge] ${host} via ${gw}: ${upstream.status}`);
        continue;
      }
      opts.gateways.succeeded(gw);
      const headers: Record<string, string> = { "x-c0mpute-gateway": new URL(gw).host };
      for (const h of PASS_HEADERS) {
        const v = upstream.headers.get(h);
        if (v !== null) headers[h] = v;
      }
      res.writeHead(upstream.status, headers);
      if (req.method === "HEAD" || !upstream.body) {
        await upstream.body?.cancel();
        res.end();
        return;
      }
      const reader = upstream.body.getReader();
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          if (!res.write(value)) await new Promise((r) => res.once("drain", r));
        }
      } catch {
        res.destroy();
        return;
      }
      res.end();
      return;
    }
    send(502, "no c0mpute gateway answered for this site; try again shortly");
  };
}

/* --------------------------------------------------------------- servers */

export interface EdgeServerOptions extends EdgeHandlerOptions {
  certs: Pick<CertStore, "context">;
  host?: string;
  httpsPort?: number;
  /** 0 disables plain HTTP. */
  httpPort?: number;
  /**
   * Behind an SNI router that prepends a PROXY protocol header (v1 or v2) to
   * every connection it hands the https port.
   */
  proxyProtocol?: boolean;
  /**
   * Where to splice TLS connections for names that are not c0mpute sites,
   * instead of refusing them: the origin that owned them before the router
   * started sending them here. See lib/sni-front.ts.
   */
  fallback?: { host: string; port: number } | null;
}

/**
 * Start the edge: https (SNI picks the leaf) and, unless disabled, plain http
 * serving the same sites. Plain http is served rather than redirected, for the
 * reason moshpit-origin.conf gives: a visitor who has not installed the Moshpit
 * root gets a working page over http instead of a certificate error.
 */
export async function startEdge(opts: EdgeServerOptions): Promise<{ https: HttpsServer | NetServer; http: HttpServer | null; close(): Promise<void> }> {
  const handler = createEdgeHandler(opts);
  const onRequest = (req: IncomingMessage, res: ServerResponse) => {
    handler(req, res).catch(() => { try { res.destroy(); } catch { /* gone */ } });
  };

  const https = createHttpsServer({
    SNICallback: (servername, cb) => {
      const name = normalizeHost(servername);
      if (!name) return cb(new Error("not a Moshpit name"));
      // Only names the registry says are c0mpute sites: an arbitrary SNI must
      // not make this edge ask the CA for anything.
      opts.sites.site(name)
        .then((site) => (site ? opts.certs.context(name) : null))
        .then((ctx) => (ctx ? cb(null, ctx) : cb(new Error(`no certificate for ${name}`))))
        .catch((e: Error) => cb(e));
    },
  }, onRequest);

  // In front of the TLS server when the edge shares :443 with an origin: the
  // TLS server itself never listens, it is handed the sockets that are ours.
  const front = opts.proxyProtocol || opts.fallback
    ? createSniFront({
      proxyProtocol: Boolean(opts.proxyProtocol),
      fallback: opts.fallback ?? null,
      serves: async (sni) => {
        const name = normalizeHost(sni);
        return Boolean(name && (await opts.sites.site(name)));
      },
      terminate: (socket) => { https.emit("connection", socket); },
      log: opts.log,
    })
    : null;

  const listen = (server: HttpServer | HttpsServer | NetServer, port: number) => new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, opts.host ?? "::", () => { server.off("error", reject); resolve(); });
  });

  const outer = front ?? https;
  await listen(outer, opts.httpsPort ?? 443);
  let http: HttpServer | null = null;
  if (opts.httpPort !== 0) {
    http = createHttpServer(onRequest);
    await listen(http, opts.httpPort ?? 80);
  }
  return {
    https: outer,
    http,
    close: async () => {
      if (front) https.close();
      await Promise.all([outer, http].filter(Boolean).map((s) => new Promise<void>((r) => s!.close(() => r()))));
    },
  };
}
