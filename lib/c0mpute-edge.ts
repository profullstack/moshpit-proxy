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
//
// Any c0mpute node may announce a gateway, so only our own (the seeds and
// C0MPUTE_TRUSTED_GATEWAYS) are proxied as they answer. A discovered gateway is
// a stranger's: from it the edge serves only what it has checked against the
// site owner's signature (lib/c0mpute-verify.ts), and a gateway that cannot
// give a verified read is skipped, never served from unverified.
//
// When every gateway fails a request the edge does not give up at once: it
// retries the round a few times on a Fibonacci schedule (a gateway restarting
// or re-executing for an update is back within seconds), then serves the last
// good copy of that page it saw (marked stale), and only then a 503 page with
// Retry-After. A failing gateway also sits out on a Fibonacci schedule.

import { execFile } from "node:child_process";
import { mkdir, readdir, readFile, rename, stat, unlink, writeFile } from "node:fs/promises";
import { createServer as createHttpServer } from "node:http";
import type { IncomingMessage, Server as HttpServer, ServerResponse } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import type { Server as HttpsServer } from "node:https";
import { createHash, X509Certificate } from "node:crypto";
import { createSecureContext } from "node:tls";
import type { SecureContext, TLSSocket } from "node:tls";
import { join } from "node:path";
import type { Server as NetServer } from "node:net";
import { createSniFront } from "./sni-front.ts";
import { ChunkCache, SeqGuard, VerifyError, chunkLength, entryEtag, verifyChunk, verifyResolve } from "./c0mpute-verify.ts";
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

/* -------------------------------------------------------------- backoff */

/**
 * The first `n` Fibonacci multiples of `baseMs` (1, 1, 2, 3, 5, 8 ...), each
 * capped at `capMs`. The retry schedule everywhere in the edge.
 */
export function fibonacciDelays(n: number, baseMs: number, capMs = Number.MAX_SAFE_INTEGER): number[] {
  const out: number[] = [];
  let a = 1, b = 1;
  for (let i = 0; i < n; i++) {
    out.push(Math.min(capMs, a * baseMs));
    [a, b] = [b, a + b];
  }
  return out;
}

/** The `k`th (1-based) Fibonacci multiple of `baseMs`, capped. */
export function fibonacciDelay(k: number, baseMs: number, capMs = Number.MAX_SAFE_INTEGER): number {
  return fibonacciDelays(Math.max(1, Math.min(k, 60)), baseMs, capMs).at(-1)!;
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
  /** Gateways to start from. Trusted (served from without verification) unless `trustSeeds` is false. */
  seeds?: string[];
  /** More gateways that are ours and served from without verification. */
  trusted?: string[];
  /** Default true: the seeds are our own gateways. */
  trustSeeds?: boolean;
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
  private trusted: Set<string>;
  private nodesUrl: string | null;
  private fetchImpl: typeof fetch;
  private timeoutMs: number;
  private now: () => number;
  private turn = 0;

  constructor(opts: GatewayPoolOptions = {}) {
    const norm = (list: string[] | undefined) => (list ?? []).map(normalizeGateway).filter((u): u is string => Boolean(u));
    const extra = norm(opts.trusted);
    this.seeds = [...new Set([...norm(opts.seeds), ...extra])];
    this.trusted = new Set([...(opts.trustSeeds === false ? [] : norm(opts.seeds)), ...extra]);
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

  /**
   * True for our own gateways (seeds and C0MPUTE_TRUSTED_GATEWAYS). Anything
   * discovered from the node list is a stranger's, and the edge serves its
   * bytes only after checking them against the site owner's signature.
   */
  isTrusted(url: string): boolean { return this.trusted.has(url); }

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
    // 5 s, 5 s, 10 s, 15 s, 25 s, 40 s ... capped at 5 minutes.
    s.downUntil = this.now() + fibonacciDelay(s.failures, 5_000, 300_000);
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

/** Headers that belong to one connection, never passed on to or from an app. */
const HOP_HEADERS = new Set(["connection", "keep-alive", "proxy-connection", "transfer-encoding", "te", "trailer", "upgrade", "proxy-authorization", "proxy-authenticate"]);

/** The most of a request body taken for an app (it is held to retry another gateway). */
const APP_BODY_MAX = 32 * 1024 * 1024;

export interface EdgeHandlerOptions {
  sites: Pick<SiteLookup, "site">;
  /**
   * `isTrusted` says which gateways are ours; a pool without it is taken to be
   * all ours (the edge before any node could be a gateway).
   */
  gateways: Pick<GatewayPool, "pick" | "succeeded" | "failed"> & Partial<Pick<GatewayPool, "isTrusted">>;
  /** Verify trusted gateways too (C0MPUTE_VERIFY_ALL). */
  verifyAll?: boolean;
  /** Highest verified seq per site (rollback guard). In memory by default. */
  seqs?: SeqGuard;
  /** Verified chunks by hash. None (no cache) by default. */
  chunks?: ChunkCache;
  now?: () => number;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  attempts?: number;
  /** Extra rounds over the gateways after the first fails, Fibonacci spaced. Default 6 (~10 s, a gateway restart). */
  retries?: number;
  /** The first retry's wait; later ones are Fibonacci multiples. Default 500 ms. */
  retryBaseMs?: number;
  /** Last good copies to serve when every gateway fails; null disables. */
  lastGood?: LastGood | null;
  sleep?: (ms: number) => Promise<void>;
  log?: (line: string) => void;
}

/** One page as a gateway last served it. */
type Kept = { status: number; headers: Record<string, string>; body: Buffer; at: number };

/**
 * The last good copy of each page, so a visitor gets the site (marked stale)
 * instead of an error while every gateway is down. In memory, least recently
 * used out first, bounded per page and in total.
 */
export class LastGood {
  private pages = new Map<string, Kept>();
  private bytes = 0;
  readonly maxEntryBytes: number;
  readonly maxBytes: number;
  readonly maxDiskBytes: number;
  private dir: string | null;
  private now: () => number;

  /**
   * `dir` keeps every copy on disk too, so they outlive a restart of the edge
   * (the moment they are most needed is right after one). Pruned oldest first
   * past `maxDiskBytes` on `load()`.
   */
  constructor(opts: { maxEntryBytes?: number; maxBytes?: number; maxDiskBytes?: number; dir?: string | null; now?: () => number } = {}) {
    this.maxEntryBytes = opts.maxEntryBytes ?? 4 * 1024 * 1024;
    this.maxBytes = opts.maxBytes ?? 128 * 1024 * 1024;
    this.maxDiskBytes = opts.maxDiskBytes ?? 1024 * 1024 * 1024;
    this.dir = opts.dir ?? null;
    this.now = opts.now ?? Date.now;
  }

  static key(site: string, path: string): string { return `${site}${path}`; }

  get size(): number { return this.pages.size; }

  private file(key: string): string {
    return join(this.dir!, `${createHash("sha256").update(key).digest("hex")}.page`);
  }

  /** Create the directory and prune it to `maxDiskBytes`, oldest first. Never throws. */
  async load(): Promise<void> {
    if (!this.dir) return;
    try {
      await mkdir(this.dir, { recursive: true });
      const files = await Promise.all((await readdir(this.dir)).filter((f) => f.endsWith(".page"))
        .map(async (f) => ({ f, st: await stat(join(this.dir!, f)) })));
      files.sort((a, b) => b.st.mtimeMs - a.st.mtimeMs);
      let total = 0;
      for (const { f, st } of files) {
        total += st.size;
        if (total > this.maxDiskBytes) await unlink(join(this.dir, f)).catch(() => {});
      }
    } catch { /* no disk copies, memory only */ }
  }

  get(key: string): Kept | null {
    const k = this.pages.get(key);
    if (!k) return null;
    this.pages.delete(key);
    this.pages.set(key, k);
    return k;
  }

  /** From memory, else from disk (and back into memory). */
  async recall(key: string): Promise<Kept | null> {
    const hit = this.get(key);
    if (hit || !this.dir) return hit;
    try {
      const raw = await readFile(this.file(key));
      const nl = raw.indexOf(10);
      const meta = JSON.parse(raw.subarray(0, nl).toString("utf8")) as { key: string; status: number; headers: Record<string, string>; at: number };
      if (meta.key !== key) return null;
      const body = raw.subarray(nl + 1);
      this.remember(key, { status: meta.status, headers: meta.headers, body, at: meta.at });
      return this.pages.get(key) ?? null;
    } catch {
      return null;
    }
  }

  put(key: string, status: number, headers: Record<string, string>, body: Buffer): void {
    if (body.length > this.maxEntryBytes) return;
    const kept = { status, headers, body, at: this.now() };
    this.remember(key, kept);
    if (this.dir) {
      const file = this.file(key);
      const tmp = `${file}.${process.pid}.${Math.random().toString(36).slice(2)}`;
      const head = Buffer.from(`${JSON.stringify({ key, status, headers, at: kept.at })}\n`);
      writeFile(tmp, Buffer.concat([head, body])).then(() => rename(tmp, file)).catch(() => { unlink(tmp).catch(() => {}); });
    }
  }

  private remember(key: string, kept: Kept): void {
    const old = this.pages.get(key);
    if (old) { this.bytes -= old.body.length; this.pages.delete(key); }
    this.pages.set(key, kept);
    this.bytes += kept.body.length;
    while (this.bytes > this.maxBytes && this.pages.size) {
      const [k, v] = this.pages.entries().next().value as [string, Kept];
      this.pages.delete(k);
      this.bytes -= v.body.length;
    }
  }
}

const FAIL_PAGE = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Back in a moment</title><meta http-equiv="refresh" content="30">
<body style="background:#070806;color:#edf2e4;font-family:monospace;padding:14vh 24px;text-align:center">
<h1 style="color:#a6ff1a">back in a moment</h1>
<p>no c0mpute gateway could serve this site just now; the network is healing itself.</p>
<p>this page retries on its own every 30 seconds.</p></body>
`;

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
  const retries = opts.retries ?? 6;
  const delays = fibonacciDelays(retries, opts.retryBaseMs ?? 500, 10_000);
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const lastGood = opts.lastGood === undefined ? new LastGood() : opts.lastGood;
  const log = opts.log ?? (() => {});
  const now = opts.now ?? Date.now;
  const verifyAll = Boolean(opts.verifyAll);
  const seqs = opts.seqs ?? new SeqGuard();
  const chunks = opts.chunks ?? new ChunkCache();
  // Gateways that cannot do verified reads just now (no resolve route yet, or
  // caught lying), and until when they sit those out.
  const unverifiable = new Map<string, number>();
  const trusted = (gw: string) => !verifyAll && (opts.gateways.isTrusted ? opts.gateways.isTrusted(gw) : true);
  const sittingOut = (gw: string) => (unverifiable.get(gw) ?? 0) > now();
  const sitOut = (gw: string, ms: number, why: string) => {
    if (!sittingOut(gw)) log(`[edge] ${gw}: no verified reads for ${Math.round(ms / 1000)} s: ${why}`);
    unverifiable.set(gw, now() + ms);
  };
  // Whether an id is a c0mpute app, as our own gateways answer /apps/v1/apps/<id>;
  // kept 5 min for an app, 1 min for a site (an app deployed under a name shows up soon).
  const appKinds = new Map<string, { app: boolean; until: number }>();
  const isApp = async (id: string): Promise<boolean> => {
    const known = appKinds.get(id);
    if (known && known.until > now()) return known.app;
    for (const gw of opts.gateways.pick(64).filter(trusted).slice(0, attempts)) {
      try {
        const r = await fetchImpl(`${gw}/apps/v1/apps/${id}`, { signal: AbortSignal.timeout(timeoutMs), headers: { accept: "application/json" } });
        // Only the gateway's own answer about this very id counts: {"app": {"app_id": id, ...}}.
        const answer = r.status === 200 ? await r.json().catch(() => null) as { app?: { app_id?: unknown } } | null : (await r.body?.cancel(), null);
        if (r.status === 200 || r.status === 404) {
          const app = answer?.app?.app_id === id;
          appKinds.set(id, { app, until: now() + (app ? 300_000 : 60_000) });
          return app;
        }
      } catch {
        // the next gateway
      }
    }
    return false;
  };

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

    const site = await opts.sites.site(host);
    // 421, not 404: "this server does not answer for that name", which a front
    // proxy can tell apart from a c0mpute site's own 404 (and park the name).
    if (!site) return send(421, `${host} does not point at a c0mpute site`);

    const path = (req.url || "/").startsWith("/") ? (req.url || "/") : "/";

    // The id may be a c0mpute app (a backend, /a/<id>/) rather than a static
    // site: the name then serves the app, every method, from our own gateways.
    if (await isApp(site)) return serveApp(site);

    if (req.method !== "GET" && req.method !== "HEAD") {
      res.setHeader("allow", "GET, HEAD");
      return send(405, "static site: GET and HEAD only");
    }

    const key = LastGood.key(site, path);
    const conditional = Boolean(req.headers["if-none-match"]);

    // One pass over the gateways; true when a response was sent.
    const tryRound = async (): Promise<boolean> => {
      // Gateways that cannot serve a verified read just now are passed over,
      // not counted against `attempts`.
      const order = opts.gateways.pick(64).filter((gw) => trusted(gw) || !sittingOut(gw)).slice(0, attempts);
      for (const gw of order) {
        if (!trusted(gw)) {
          if (await serveVerified(gw, order)) return true;
          continue;
        }
        let upstream: Response;
        try {
          upstream = await fetchImpl(upstreamUrl(gw, site, path), {
            method: req.method,
            headers: {
              ...(conditional ? { "if-none-match": String(req.headers["if-none-match"]) } : {}),
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
          return true;
        }
        // Keep a copy of a full 200 for the day every gateway is down.
        const keep = lastGood && upstream.status === 200 && !headers["content-encoding"] ? [] as Buffer[] : null;
        let kept = 0;
        const reader = upstream.body.getReader();
        try {
          for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            if (keep) {
              kept += value.length;
              if (kept <= lastGood!.maxEntryBytes) keep.push(Buffer.from(value));
            }
            if (!res.write(value)) await new Promise((r) => res.once("drain", r));
          }
        } catch {
          res.destroy();
          return true;
        }
        res.end();
        if (keep && kept <= lastGood!.maxEntryBytes) lastGood!.put(key, 200, headers, Buffer.concat(keep));
        return true;
      }
      return false;
    };

    // An app: its answers are live, not signed files, so only our own gateways
    // carry it (nothing to verify from a stranger's). The request goes as it
    // came, body and all, to /a/<app>/<path>; a gateway that cannot be reached
    // or answers 502-504 is passed over while nothing has been sent.
    async function serveApp(app: string): Promise<void> {
      const method = req.method || "GET";
      let body: Buffer | undefined;
      if (method !== "GET" && method !== "HEAD") {
        const parts: Buffer[] = [];
        let size = 0;
        for await (const chunk of req) {
          size += (chunk as Buffer).length;
          if (size > APP_BODY_MAX) return send(413, "request body too large");
          parts.push(chunk as Buffer);
        }
        body = Buffer.concat(parts);
      }
      const headers: Record<string, string> = {};
      for (const [name, value] of Object.entries(req.headers)) {
        if (value === undefined || HOP_HEADERS.has(name) || name === "host") continue;
        headers[name] = Array.isArray(value) ? value.join(", ") : value;
      }
      headers["x-forwarded-host"] = host!;
      headers["x-forwarded-proto"] = (req.socket as TLSSocket).encrypted ? "https" : "http";
      const order = opts.gateways.pick(64).filter(trusted).slice(0, attempts);
      for (const gw of order) {
        let upstream: Response;
        try {
          upstream = await fetchImpl(`${gw}/a/${app}${path}`, {
            method, headers, ...(body ? { body: new Uint8Array(body) } : {}), redirect: "manual", signal: AbortSignal.timeout(Math.max(timeoutMs, 30_000)),
          });
        } catch (e) {
          opts.gateways.failed(gw);
          log(`[edge] ${host} (app) via ${gw}: ${(e as Error).message}`);
          continue;
        }
        if (upstream.status >= 502 && upstream.status <= 504 && gw !== order[order.length - 1]) {
          await upstream.body?.cancel();
          log(`[edge] ${host} (app) via ${gw}: ${upstream.status}`);
          continue;
        }
        opts.gateways.succeeded(gw);
        const out: Record<string, string | string[]> = { "x-c0mpute-gateway": new URL(gw).host, "x-c0mpute-app": app };
        upstream.headers.forEach((value, name) => {
          if (!HOP_HEADERS.has(name) && name !== "set-cookie") out[name] = value;
        });
        const cookies = upstream.headers.getSetCookie?.() ?? [];
        if (cookies.length) out["set-cookie"] = cookies;
        res.writeHead(upstream.status, out);
        if (method === "HEAD" || !upstream.body) {
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
          res.end();
        } catch {
          res.destroy();
        }
        return;
      }
      res.writeHead(503, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "retry-after": "30" });
      res.end(method === "HEAD" ? undefined : FAIL_PAGE);
    }

    // A stranger's gateway: take nothing from it on its word. Ask for the
    // owner-signed evidence, check it (lib/c0mpute-verify.ts) and send only
    // bytes whose hashes the signed manifest names. False when nothing was
    // sent and the next gateway should be tried.
    async function serveVerified(gw: string, others: string[]): Promise<boolean> {
      const reqPath = path.split(/[?#]/)[0] || "/";
      let answer: unknown;
      try {
        const r = await fetchImpl(`${gw}/hosting/v1/sites/${site}/resolve?path=${encodeURIComponent(reqPath)}`, {
          redirect: "manual", signal: AbortSignal.timeout(timeoutMs),
        });
        if (r.status >= 500) {
          await r.body?.cancel();
          opts.gateways.failed(gw);
          log(`[edge] ${host} via ${gw} (verified): ${r.status}`);
          return false;
        }
        if (r.status !== 200) {
          // 404: a gateway older than the resolve route (c0mpute < 0.3.5), or
          // one that does not know the site. Either way, no verified read.
          await r.body?.cancel();
          sitOut(gw, 300_000, `resolve answered ${r.status}`);
          return false;
        }
        answer = await r.json();
      } catch (e) {
        if (e instanceof SyntaxError) { sitOut(gw, 300_000, "resolve answer is not JSON"); return false; }
        opts.gateways.failed(gw);
        log(`[edge] ${host} via ${gw} (verified): ${(e as Error).message}`);
        return false;
      }
      let resolved: ReturnType<typeof verifyResolve>;
      try {
        resolved = verifyResolve(site!, reqPath, answer, seqs.min(site!));
      } catch (e) {
        const msg = e instanceof VerifyError ? e.message : String(e);
        log(`[edge] ${host}${reqPath} via ${gw}: REJECTED: ${msg}`);
        sitOut(gw, 600_000, `failed verification (${msg})`);
        return false;
      }
      opts.gateways.succeeded(gw);
      seqs.note(site!, resolved.record.seq);

      const base: Record<string, string> = {
        "x-c0mpute-gateway": new URL(gw).host,
        "x-c0mpute-verified": "1",
        "x-content-type-options": "nosniff",
      };
      const entry = resolved.entry;
      if (!entry) {
        res.writeHead(404, { ...base, "content-type": "text/plain; charset=utf-8", "cache-control": "public, max-age=60" });
        res.end(req.method === "HEAD" ? undefined : "not found");
        return true;
      }
      const etag = entryEtag(entry);
      const headers: Record<string, string> = {
        ...base,
        "content-type": /^[\x20-\x7e]{1,255}$/.test(entry.content_type) ? entry.content_type : "application/octet-stream",
        "content-length": String(entry.size),
        etag,
        "cache-control": "public, max-age=60",
      };
      if (resolved.status === 200 && conditional && String(req.headers["if-none-match"]).split(/\s*,\s*/).includes(etag)) {
        delete headers["content-length"];
        res.writeHead(304, headers);
        res.end();
        return true;
      }
      if (req.method === "HEAD") {
        res.writeHead(resolved.status, headers);
        res.end();
        return true;
      }

      // Chunks from anywhere: the hash makes the source irrelevant. The
      // gateway that resolved first, then the others still in the running.
      const sources = [gw, ...others, ...opts.gateways.pick(64)]
        .filter((o, i, all) => all.indexOf(o) === i && !sittingOut(o));
      const chunk = async (i: number): Promise<Buffer | null> => {
        const hash = entry.chunks[i];
        const want = chunkLength(entry.size, i);
        const cached = await chunks.get(hash);
        if (cached && cached.length === want) return cached;
        for (const src of sources) {
          if (sittingOut(src)) continue;
          try {
            const r = await fetchImpl(`${src}/hosting/v1/sites/${site}/chunks/${hash}`, { redirect: "manual", signal: AbortSignal.timeout(timeoutMs) });
            if (r.status !== 200) { await r.body?.cancel(); continue; }
            const bytes = Buffer.from(await r.arrayBuffer());
            verifyChunk(bytes, hash, want);
            chunks.put(hash, bytes);
            return bytes;
          } catch (e) {
            if (e instanceof VerifyError) {
              log(`[edge] ${host}${reqPath} chunk from ${src}: REJECTED: ${e.message}`);
              sitOut(src, 600_000, `served a bad chunk (${e.message})`);
            }
          }
        }
        return null;
      };

      // The first chunk before the status line, so a file whose chunks cannot
      // be had falls through to the next gateway (and then the stale copy).
      const first = await chunk(0);
      if (!first) {
        log(`[edge] ${host}${reqPath}: no gateway had a good copy of chunk 0 of ${resolved.path}`);
        return false;
      }
      res.writeHead(resolved.status, headers);
      const keep = lastGood && resolved.status === 200 && entry.size <= lastGood.maxEntryBytes ? [first] : null;
      if (!res.write(first)) await new Promise((r) => res.once("drain", r));
      for (let i = 1; i < entry.chunks.length; i++) {
        const next = await chunk(i);
        if (!next) {
          // Every byte sent so far was checked; the rest cannot be had. Cut
          // the response short rather than send anything unverified.
          log(`[edge] ${host}${reqPath}: chunk ${i} of ${resolved.path} unavailable mid-file`);
          res.destroy();
          return true;
        }
        keep?.push(next);
        if (!res.write(next)) await new Promise((r) => res.once("drain", r));
      }
      res.end();
      if (keep) lastGood!.put(key, 200, headers, Buffer.concat(keep));
      return true;
    }

    if (await tryRound()) return;
    for (const ms of delays) {
      if (res.destroyed || req.socket.destroyed) return;
      await sleep(ms);
      if (await tryRound()) return;
    }

    const stale = lastGood ? await lastGood.recall(key) : null;
    if (stale) {
      log(`[edge] ${host}${path}: every gateway failed ${delays.length + 1} rounds; serving the last good copy`);
      const headers: Record<string, string> = { ...stale.headers, "x-c0mpute-stale": "1",
        "cache-control": "no-store", "content-length": String(stale.body.length) };
      delete headers["content-encoding"];
      res.writeHead(stale.status, headers);
      res.end(req.method === "HEAD" ? undefined : stale.body);
      return;
    }
    log(`[edge] ${host}${path}: every gateway failed ${delays.length + 1} rounds; no copy kept`);
    res.writeHead(503, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "retry-after": "30" });
    res.end(req.method === "HEAD" ? undefined : FAIL_PAGE);
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
