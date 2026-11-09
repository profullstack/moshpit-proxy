// Verified reads from untrusted c0mpute gateways. Fixtures are built here in
// the exact formats c0mpute's hosting/site.rs produces (serde_json, BTreeMap
// key order, ed25519 over the same signing bytes), plus real records signed by
// the Rust node as golden vectors.

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { createServer, request as httpRequest } from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";

import {
  ChunkCache,
  FILE_CHUNK_BYTES,
  MAX_FREE_SITE_BYTES,
  MAX_PARTS,
  MAX_SITE_BYTES,
  SeqGuard,
  blake3hex,
  candidates,
  chunkLength,
  cmpPath,
  partFor,
  signingBytes,
  siteIdFor,
  verifyChunk,
  verifyRecord,
  verifyResolve,
} from "../lib/c0mpute-verify.ts";
import type { FileEntry, ResolveAnswer, SiteRecord } from "../lib/c0mpute-verify.ts";
import { createEdgeHandler, GatewayPool } from "../lib/c0mpute-edge.ts";
import { tempDir } from "./helpers.ts";

/* ------------------------------------------------------------ fixtures */

type Key = { owner: string; priv: KeyObject };

function newKey(): Key {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return { owner: publicKey.export({ format: "der", type: "spki" }).subarray(12).toString("hex"), priv: privateKey };
}

function signRecord(key: Key, r: Omit<SiteRecord, "sig">): SiteRecord {
  const rec = { ...r, sig: "" } as SiteRecord;
  rec.sig = edSign(null, signingBytes(rec), key.priv).toString("hex");
  return rec;
}

interface Site {
  id: string;
  key: Key;
  record: SiteRecord;
  manifestBytes: Buffer;
  /** Manifest parts by hash (v2 only), and the root's refs. */
  parts: Map<string, Buffer>;
  refs: { first: string; hash: string; files: number; bytes: number }[];
  entries: Map<string, FileEntry>;
  chunks: Map<string, Buffer>;
}

/** A site as `c0mpute hosting publish` would make it. `partFiles` > 0 makes a v2 (parted) manifest. */
function makeSite(files: Record<string, string | Buffer>, opts: { name?: string; key?: Key; seq?: number; partFiles?: number; recordV?: 1 | 2 } = {}): Site {
  const key = opts.key ?? newKey();
  const name = opts.name ?? "demo";
  const chunks = new Map<string, Buffer>();
  const entries = new Map<string, FileEntry>();
  const paths = Object.keys(files).sort(cmpPath);
  for (const p of paths) {
    const body = Buffer.from(files[p]);
    const hashes: string[] = [];
    for (let off = 0; off === 0 || off < body.length; off += FILE_CHUNK_BYTES) {
      const c = body.subarray(off, off + FILE_CHUNK_BYTES);
      const h = blake3hex(c);
      chunks.set(h, Buffer.from(c));
      hashes.push(h);
    }
    entries.set(p, { size: body.length, content_type: p.endsWith(".html") ? "text/html; charset=utf-8" : "application/octet-stream", chunks: hashes });
  }
  // serde_json of a BTreeMap: keys in byte order, compact.
  const obj = (ps: string[]) => Object.fromEntries(ps.map((p) => [p, entries.get(p)!]));
  const total = paths.reduce((n, p) => n + entries.get(p)!.size, 0);
  const parts = new Map<string, Buffer>();
  const refs: Site["refs"] = [];
  let manifestBytes: Buffer;
  if (opts.partFiles) {
    for (let i = 0; i < paths.length; i += opts.partFiles) {
      const ps = paths.slice(i, i + opts.partFiles);
      const bytes = Buffer.from(JSON.stringify({ v: 2, files: obj(ps) }));
      const hash = blake3hex(bytes);
      parts.set(hash, bytes);
      refs.push({ first: ps[0], hash, files: ps.length, bytes: ps.reduce((n, p) => n + entries.get(p)!.size, 0) });
    }
    manifestBytes = Buffer.from(JSON.stringify({ v: 2, name, files: paths.length, bytes: total, parts: refs }));
  } else {
    manifestBytes = Buffer.from(JSON.stringify({ v: 1, name, files: obj(paths) }));
  }
  const id = siteIdFor(key.owner, name);
  const base = { site_id: id, name, owner: key.owner, manifest: blake3hex(manifestBytes), seq: opts.seq ?? 1_794_000_000_000, size: total, domains: [] as string[] };
  const record = opts.recordV === 2
    ? signRecord(key, { v: 2, ...base, preferred_hosts: ["12D3KooWFTsCjAVPKYnak1H8N7By5UpgeipVScmuAyGeRzzsLwSu"], price_per_gib_month: "0.004" })
    : signRecord(key, { v: 1, ...base });
  return { id, key, record, manifestBytes, parts, refs, entries, chunks };
}

/** What an honest gateway's resolve route answers. */
function honestAnswer(site: Site, reqPath: string): ResolveAnswer {
  const consulted = new Set<string>();
  const lookup = (p: string): FileEntry | null => {
    if (site.refs.length) {
      const ref = partFor(site.refs, p);
      if (!ref) return null;
      consulted.add(ref.hash);
    }
    return site.entries.get(p) ?? null;
  };
  let path: string | null = null, status = 404;
  for (const c of candidates(reqPath)) if (lookup(c)) { path = c; status = 200; break; }
  if (!path && lookup("404.html")) path = "404.html";
  return {
    v: 1,
    record: site.record,
    manifest: site.manifestBytes.toString("base64"),
    parts: [...consulted].map((h) => site.parts.get(h)!.toString("base64")),
    path,
    status,
    entry: path ? site.entries.get(path)! : null,
  };
}

const PAGES = { "index.html": "<h1>The Future of Hosting</h1>", "og.png": "PNGDATA", "404.html": "lost", "foo": "raw foo", "foo.html": "foo page", "docs/index.html": "docs" };

/* -------------------------------------------------- golden: the Rust node */

test("records signed by the Rust node verify (v1 and v2), and site ids match the node's", () => {
  const v1 = { v: 1, site_id: "1d9a7ea0594aaad346a6", name: "git-demo", owner: "827265f7d4362299c288a4eb17ae4cbf44e9932e883487adea3ed8d80f8aa299", manifest: "2df48aab981cba003363bc00743b145ede38649b297c1f797a6d77b12bb01e07", seq: 1794221463133, size: 3400, domains: [], sig: "8b9ec5b65429607ea8df7f27a22ab7810a7fe03b8d1fef8234c62f091927e6a2f6d8fb76c0ae1b9d8dda1f8dce4501f349d4aca99181206a464d37a1f291bc06" };
  const v2 = { v: 2, site_id: "37072519c7c3c8b3317b", name: "market", owner: "08107c499b722f28b24fe74b147e7ab6d154dfa95104d7f75e2afb587848c971", manifest: "e47db91a01f24e2c10f0eb39bbace65a60c76152de1c5bbaafe751cc7dbacf5c", seq: 1, size: 5242901, domains: [], preferred_hosts: ["12D3KooWFTsCjAVPKYnak1H8N7By5UpgeipVScmuAyGeRzzsLwSu", "12D3KooWPqGuuupmQnZUKnK4pBPxoMeMiNCFf2sHndTKH2Mif2TQ"], price_per_gib_month: "1", sig: "c03bee448306d731811a2f4958ea4bbc9e37d1126cf270e602574956605c1a1540d5bcee71cf0cbe49f37e7736e9613b92d450d0a970df1383f418e3c3ce1300" };
  assert.equal(verifyRecord(v1, v1.site_id).seq, 1794221463133);
  assert.equal(verifyRecord(v2, v2.site_id).v, 2);
  assert.throws(() => verifyRecord({ ...v2, price_per_gib_month: "2" }, v2.site_id), /signature/, "terms are signed");
  assert.equal(siteIdFor("07f84b7788e3f76ea66e865d594e99d495a432d651643b3837a4f08daa94cf1b", "ads-radio"), "c8dfa86eb28cfce56754");
  assert.equal(blake3hex(new Uint8Array()), "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
});

test("candidates mirror site.rs", () => {
  assert.deepEqual(candidates("/"), ["index.html"]);
  assert.deepEqual(candidates("/docs/"), ["docs/index.html"]);
  assert.deepEqual(candidates("/foo"), ["foo", "foo.html", "foo/index.html"]);
  assert.deepEqual(candidates("/a/b.css?x=1#y"), ["a/b.css"]);
  assert.deepEqual(candidates("/hello%20world"), ["hello world", "hello world.html", "hello world/index.html"]);
  assert.deepEqual(candidates("/caf%C3%A9.txt"), ["café.txt"]);
});

/* ------------------------------------------------------ verifyResolve */

test("an honest answer verifies: index, extensionless .html, directory index, 404.html", () => {
  const s = makeSite(PAGES);
  const r = verifyResolve(s.id, "/", honestAnswer(s, "/"));
  assert.equal(r.path, "index.html");
  assert.equal(r.status, 200);
  assert.equal(verifyResolve(s.id, "/foo", honestAnswer(s, "/foo")).path, "foo");
  assert.equal(verifyResolve(s.id, "/docs/", honestAnswer(s, "/docs/")).path, "docs/index.html");
  assert.equal(verifyResolve(s.id, "/docs", honestAnswer(s, "/docs")).path, "docs/index.html");
  const nf = verifyResolve(s.id, "/missing.css", honestAnswer(s, "/missing.css"));
  assert.deepEqual([nf.path, nf.status], ["404.html", 404]);
  const plain = makeSite({ "index.html": "x" });
  const none = verifyResolve(plain.id, "/nope", honestAnswer(plain, "/nope"));
  assert.deepEqual([none.path, none.status, none.entry], [null, 404, null]);
});

test("a wrong signature, a tampered field, or a forged record is refused", () => {
  const s = makeSite(PAGES);
  const a = honestAnswer(s, "/");
  const flip = (hex: string) => (hex[0] === "0" ? "1" : "0") + hex.slice(1);
  assert.throws(() => verifyResolve(s.id, "/", { ...a, record: { ...s.record, sig: flip(s.record.sig) } }), /signature/);
  assert.throws(() => verifyResolve(s.id, "/", { ...a, record: { ...s.record, seq: s.record.seq + 1 } }), /signature/);
  // A stranger signs a record for this site id with their own key.
  const mallory = newKey();
  const forged = signRecord(mallory, { ...s.record, owner: mallory.owner });
  assert.throws(() => verifyResolve(s.id, "/", { ...a, record: forged }), /site id/);
});

test("a record for another site is refused", () => {
  const s = makeSite(PAGES);
  const other = makeSite(PAGES, { name: "other" });
  assert.throws(() => verifyResolve(s.id, "/", honestAnswer(other, "/")), /another site/);
});

test("rollback: a record older than the highest seq verified is refused", () => {
  const key = newKey();
  const v1 = makeSite({ "index.html": "old" }, { key, seq: 100 });
  const v2 = makeSite({ "index.html": "new" }, { key, seq: 200 });
  assert.equal(v1.id, v2.id);
  assert.equal(verifyResolve(v2.id, "/", honestAnswer(v2, "/"), 200).record.seq, 200);
  assert.throws(() => verifyResolve(v1.id, "/", honestAnswer(v1, "/"), 200), /rollback/);
});

test("a tampered manifest, or one for another name, is refused", () => {
  const s = makeSite(PAGES);
  const a = honestAnswer(s, "/");
  const bad = Buffer.from(s.manifestBytes.toString().replace("The", "the"));
  assert.throws(() => verifyResolve(s.id, "/", { ...a, manifest: Buffer.from(s.manifestBytes.toString().replace('"og.png"', '"og.PNG"')).toString("base64") }), /manifest does not match/);
  assert.throws(() => verifyResolve(s.id, "/", { ...a, manifest: bad.toString("base64") + "AA" }), /manifest/);
});

test("candidate skipping: the gateway may not serve a later candidate when an earlier one exists", () => {
  const s = makeSite(PAGES);
  const honest = honestAnswer(s, "/foo");
  const lie = { ...honest, path: "foo.html", entry: s.entries.get("foo.html")! };
  assert.throws(() => verifyResolve(s.id, "/foo", lie), /resolved "foo.html", the site resolves "foo"/);
  // Nor claim a page does not exist when it does, nor pass 404.html off as 200.
  assert.throws(() => verifyResolve(s.id, "/", { ...honestAnswer(s, "/"), path: null, status: 404, entry: null }), /resolved null/);
  assert.throws(() => verifyResolve(s.id, "/nope.css", { ...honestAnswer(s, "/nope.css"), status: 200 }), /status/);
  // Nor swap in another file's entry under the right path.
  assert.throws(() => verifyResolve(s.id, "/", { ...honestAnswer(s, "/"), entry: s.entries.get("og.png")! }), /entry/);
  assert.throws(() => verifyResolve(s.id, "/", { ...honestAnswer(s, "/"), entry: { ...s.entries.get("index.html")!, content_type: "text/javascript" } }), /entry/);
});

test("404.html is served as a 404, and claiming a plain 404 when 404.html exists is refused", () => {
  const s = makeSite(PAGES);
  const r = verifyResolve(s.id, "/gone", honestAnswer(s, "/gone"));
  assert.deepEqual([r.path, r.status, r.entry!.size], ["404.html", 404, 4]);
  assert.throws(() => verifyResolve(s.id, "/gone", { ...honestAnswer(s, "/gone"), path: null, entry: null }), /resolved null/);
});

test("v2 parted sites: parts verified by hash, a left-out part is refused, skipping across parts is caught", () => {
  const files: Record<string, string> = {};
  for (let i = 0; i < 20; i++) files[`p/f${String(i).padStart(2, "0")}.txt`] = `file ${i}`;
  Object.assign(files, { "index.html": "root", "zz/foo": "raw", "zz/foo.html": "page" });
  const s = makeSite(files, { partFiles: 3, recordV: 2 });
  assert.ok(s.refs.length >= 7);
  const r = verifyResolve(s.id, "/p/f13.txt", honestAnswer(s, "/p/f13.txt"));
  assert.equal(r.entry!.size, 7);
  assert.equal(verifyResolve(s.id, "/", honestAnswer(s, "/")).path, "index.html");

  const a = honestAnswer(s, "/p/f13.txt");
  assert.throws(() => verifyResolve(s.id, "/p/f13.txt", { ...a, parts: [] }), /left out the manifest part/);
  const tampered = Buffer.from(Buffer.from(a.parts![0], "base64").toString().replace("file", "fil3")).toString("base64");
  assert.throws(() => verifyResolve(s.id, "/p/f13.txt", { ...a, parts: [tampered] }), /does not name/);

  // zz/foo and zz/foo.html: claim the .html, hand over only the part holding it.
  const honest = honestAnswer(s, "/zz/foo");
  assert.equal(honest.path, "zz/foo");
  const fooHtmlPart = partFor(s.refs, "zz/foo.html")!;
  const lie = { ...honest, path: "zz/foo.html", entry: s.entries.get("zz/foo.html")!, parts: [s.parts.get(fooHtmlPart.hash)!.toString("base64")] };
  assert.throws(() => verifyResolve(s.id, "/zz/foo", lie), /resolved|left out/);
});

test("size caps mirror site.rs (c0mpute 0.3.7): 4 TiB per site, 64 GiB on a v1 record, 2630 parts", () => {
  const GIB = 1024 ** 3;
  assert.equal(MAX_SITE_BYTES, 4 * 1024 * GIB);
  assert.equal(MAX_FREE_SITE_BYTES, 64 * GIB);
  assert.equal(MAX_PARTS, 2630);

  const key = newKey();
  const record = (v: 1 | 2, size: number) => {
    const base = { site_id: siteIdFor(key.owner, "media"), name: "media", owner: key.owner, manifest: blake3hex("m"), seq: 1, size, domains: [] as string[] };
    return v === 2
      ? signRecord(key, { v: 2, ...base, preferred_hosts: ["12D3KooWFTsCjAVPKYnak1H8N7By5UpgeipVScmuAyGeRzzsLwSu"], price_per_gib_month: "0.004" })
      : signRecord(key, { v: 1, ...base });
  };
  const id = siteIdFor(key.owner, "media");
  assert.equal(verifyRecord(record(2, 3 * GIB), id).size, 3 * GIB);
  assert.equal(verifyRecord(record(2, MAX_SITE_BYTES), id).size, MAX_SITE_BYTES);
  assert.throws(() => verifyRecord(record(2, MAX_SITE_BYTES + 1), id), /size cap/);
  assert.equal(verifyRecord(record(1, 2 * GIB), id).size, 2 * GIB);
  assert.equal(verifyRecord(record(1, MAX_FREE_SITE_BYTES), id).size, MAX_FREE_SITE_BYTES);
  assert.throws(() => verifyRecord(record(1, MAX_FREE_SITE_BYTES + 1), id), /size cap/);
});

test("a v2 site over 1 GiB verifies end to end, with more parts than files alone would need", () => {
  const GIB = 1024 ** 3;
  const key = newKey();
  const name = "media";
  const index = Buffer.from("<video src=big.mkv>");
  const size = 3 * GIB + 5;
  const big: FileEntry = { size, content_type: "video/x-matroska", chunks: Array.from({ length: Math.ceil(size / FILE_CHUNK_BYTES) }, (_, i) => blake3hex(`chunk ${i}`)) };
  const entries: Record<string, FileEntry> = { "big.mkv": big, "index.html": { size: index.length, content_type: "text/html; charset=utf-8", chunks: [blake3hex(index)] } };
  const partBytes = Buffer.from(JSON.stringify({ v: 2, files: entries }));
  const real = { first: "big.mkv", hash: blake3hex(partBytes), files: 2, bytes: size + index.length };
  // Striped media sites split parts by chunk count too, so a root may list
  // more parts than MAX_FILES / PART_FILES (2500). Pad with empty-sized parts.
  const site = (nParts: number, total = real.bytes) => {
    const refs = [real];
    for (let i = 1; i < nParts; i++) refs.push({ first: `zz/${String(i).padStart(5, "0")}`, hash: blake3hex(`part ${i}`), files: 1, bytes: 0 });
    const files = refs.reduce((n, r) => n + r.files, 0);
    const manifest = Buffer.from(JSON.stringify({ v: 2, name, files, bytes: total, parts: refs }));
    const rec = signRecord(key, { v: 2, site_id: siteIdFor(key.owner, name), name, owner: key.owner, manifest: blake3hex(manifest), seq: 1, size: total, domains: [], preferred_hosts: ["12D3KooWFTsCjAVPKYnak1H8N7By5UpgeipVScmuAyGeRzzsLwSu"], price_per_gib_month: "0.004" });
    return { id: rec.site_id, answer: (path: string | null, entry: FileEntry | null): ResolveAnswer => ({ v: 1, record: rec, manifest: manifest.toString("base64"), parts: [partBytes.toString("base64")], path, status: 200, entry }) };
  };
  const s = site(1);
  const r = verifyResolve(s.id, "/big.mkv", s.answer("big.mkv", big));
  assert.deepEqual([r.status, r.entry!.size, r.entry!.chunks.length], [200, size, 3073]);
  assert.equal(verifyResolve(s.id, "/", s.answer("index.html", entries["index.html"])).path, "index.html");

  const wide = site(MAX_PARTS);
  assert.equal(verifyResolve(wide.id, "/big.mkv", wide.answer("big.mkv", big)).entry!.size, size);
  const tooWide = site(MAX_PARTS + 1);
  assert.throws(() => verifyResolve(tooWide.id, "/big.mkv", tooWide.answer("big.mkv", big)), /too many parts/);
});

test("chunks: hash and length checked", () => {
  const body = Buffer.alloc(FILE_CHUNK_BYTES + 10, 7);
  const s = makeSite({ "big.bin": body });
  const e = s.entries.get("big.bin")!;
  assert.equal(e.chunks.length, 2);
  assert.equal(chunkLength(e.size, 1), 10);
  verifyChunk(s.chunks.get(e.chunks[1])!, e.chunks[1], 10);
  const bad = Buffer.from(s.chunks.get(e.chunks[1])!); bad[0] ^= 1;
  assert.throws(() => verifyChunk(bad, e.chunks[1], 10), /does not match/);
  assert.throws(() => verifyChunk(s.chunks.get(e.chunks[0])!, e.chunks[1], 10), /bytes/);
});

test("SeqGuard keeps the floor across a restart", async () => {
  const dir = await tempDir();
  const file = join(dir, "seqs.json");
  const g = new SeqGuard({ file });
  g.note("0123456789abcdef0123", 5);
  g.note("0123456789abcdef0123", 3);
  await g.flush();
  const g2 = new SeqGuard({ file });
  await g2.load();
  assert.equal(g2.min("0123456789abcdef0123"), 5);
});

/* ------------------------------------------------------ through the edge */

interface FakeGateway {
  url: string;
  site: Site;
  /** Resolve route present (c0mpute >= 0.3.5). */
  routes?: boolean;
  tamperChunk?: boolean;
  /** /s/ requests seen: an untrusted gateway must never get one. */
  sSeen?: number;
}

function gatewayFetch(gws: FakeGateway[], seen: string[] = []): typeof fetch {
  return (async (input: string | URL | Request) => {
    const url = new URL(String(input));
    seen.push(url.href);
    const gw = gws.find((g) => g.url === url.origin);
    if (!gw) throw new Error(`connect ECONNREFUSED ${url.origin}`);
    const m = url.pathname.match(/^\/hosting\/v1\/sites\/([0-9a-f]{20})\/(resolve|chunks\/([0-9a-f]{64}))$/);
    if (url.pathname.startsWith("/s/")) {
      gw.sSeen = (gw.sSeen ?? 0) + 1;
      return new Response("UNVERIFIED BYTES", { status: 200, headers: { "content-type": "text/html" } });
    }
    if (!m || gw.routes === false) return new Response("not found", { status: 404 });
    if (m[2] === "resolve") return Response.json(honestAnswer(gw.site, url.searchParams.get("path") ?? "/"));
    const c = gw.site.chunks.get(m[3]);
    if (!c) return new Response("no", { status: 404 });
    const out = Buffer.from(c);
    if (gw.tamperChunk) out[0] ^= 0xff;
    return new Response(out);
  }) as typeof fetch;
}

function pool(urls: string[], trusted: string[] = []) {
  return { pick: () => urls, succeeded: () => {}, failed: () => {}, isTrusted: (u: string) => trusted.includes(u) };
}

async function serve(handler: (req: IncomingMessage, res: ServerResponse) => Promise<void>) {
  const server = createServer((req, res) => { void handler(req, res); });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as AddressInfo).port;
  const call = (path: string, method = "GET", headers: Record<string, string> = {}) =>
    new Promise<{ status: number; body: Buffer; headers: Record<string, string | string[] | undefined> }>((resolve, reject) => {
      const req = httpRequest({ host: "127.0.0.1", port, method, path, headers: { host: "blue.eggs", ...headers } }, (res) => {
        const parts: Buffer[] = [];
        res.on("data", (d) => parts.push(d));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(parts), headers: res.headers }));
        res.on("error", reject);
      });
      req.on("error", reject);
      req.end();
    });
  return { call, close: () => server.close() };
}

const quiet = { sleep: async () => {}, retries: 0, lastGood: null } as const;

test("edge: an untrusted gateway is served from only after verification; multi-chunk files stream", async (t) => {
  const big = Buffer.alloc(2 * FILE_CHUNK_BYTES + 123);
  for (let i = 0; i < big.length; i++) big[i] = (i * 31) & 0xff;
  const s = makeSite({ ...PAGES, "big.bin": big });
  const g: FakeGateway = { url: "http://stranger:7777", site: s };
  const handler = createEdgeHandler({ ...quiet, sites: { site: async () => s.id }, gateways: pool([g.url]), fetchImpl: gatewayFetch([g]) });
  const srv = await serve(handler);
  t.after(srv.close);

  const home = await srv.call("/");
  assert.equal(home.status, 200);
  assert.equal(home.body.toString(), PAGES["index.html"]);
  assert.equal(home.headers["x-c0mpute-verified"], "1");
  assert.equal(home.headers["content-type"], "text/html; charset=utf-8");
  const b = await srv.call("/big.bin");
  assert.equal(b.status, 200);
  assert.ok(b.body.equals(big));
  const nf = await srv.call("/nope.css");
  assert.deepEqual([nf.status, nf.body.toString()], [404, "lost"]);
  const head = await srv.call("/og.png", "HEAD");
  assert.deepEqual([head.status, head.headers["content-length"], head.body.length], [200, "7", 0]);
  const etag = String(home.headers.etag);
  assert.equal((await srv.call("/", "GET", { "if-none-match": etag })).status, 304);
  assert.equal(g.sSeen ?? 0, 0, "never asked an untrusted gateway for raw /s/ bytes");
});

test("edge: a tampered chunk is never served; an honest source supplies it, else the request fails", async (t) => {
  const s = makeSite(PAGES);
  const liar: FakeGateway = { url: "http://liar:7777", site: s, tamperChunk: true };
  const honest: FakeGateway = { url: "http://honest:7777", site: s };
  const logs: string[] = [];
  const h1 = createEdgeHandler({ ...quiet, log: (l) => logs.push(l), sites: { site: async () => s.id }, gateways: pool([liar.url, honest.url]), fetchImpl: gatewayFetch([liar, honest]) });
  const srv1 = await serve(h1);
  t.after(srv1.close);
  const ok = await srv1.call("/");
  assert.equal(ok.status, 200);
  assert.equal(ok.body.toString(), PAGES["index.html"]);
  assert.ok(logs.some((l) => /REJECTED/.test(l) && l.includes("liar")));

  const h2 = createEdgeHandler({ ...quiet, sites: { site: async () => s.id }, gateways: pool([liar.url]), fetchImpl: gatewayFetch([liar]) });
  const srv2 = await serve(h2);
  t.after(srv2.close);
  const bad = await srv2.call("/");
  assert.equal(bad.status, 503);
  assert.ok(!bad.body.toString().includes("Future"), "no tampered or unverified bytes");
});

test("edge: an untrusted gateway without the resolve route (c0mpute < 0.3.5) is skipped, never proxied", async (t) => {
  const s = makeSite(PAGES);
  const old: FakeGateway = { url: "http://old:7777", site: s, routes: false };
  const ours: FakeGateway = { url: "http://127.0.0.1:7777", site: s };
  const seen: string[] = [];
  const h = createEdgeHandler({ ...quiet, sites: { site: async () => s.id }, gateways: pool([old.url, ours.url], [ours.url]), fetchImpl: gatewayFetch([old, ours], seen) });
  const srv = await serve(h);
  t.after(srv.close);
  const r = await srv.call("/");
  assert.equal(r.status, 200);
  assert.equal(r.body.toString(), "UNVERIFIED BYTES", "our own gateway is proxied as before");
  assert.equal(r.headers["x-c0mpute-gateway"], "127.0.0.1:7777");
  assert.equal(old.sSeen ?? 0, 0);
  // Sitting out now: the next request does not even ask it.
  const before = seen.filter((u) => u.startsWith(old.url)).length;
  await srv.call("/og.png");
  assert.equal(seen.filter((u) => u.startsWith(old.url)).length, before);

  const alone = createEdgeHandler({ ...quiet, sites: { site: async () => s.id }, gateways: pool([old.url]), fetchImpl: gatewayFetch([old]) });
  const srv2 = await serve(alone);
  t.after(srv2.close);
  assert.equal((await srv2.call("/")).status, 503);
  assert.equal(old.sSeen ?? 0, 0);
});

test("edge: rollback to an older record is refused across gateways", async (t) => {
  const key = newKey();
  const newer = makeSite({ "index.html": "new" }, { key, seq: 200 });
  const older = makeSite({ "index.html": "old" }, { key, seq: 100 });
  const a: FakeGateway = { url: "http://a:7777", site: newer };
  const b: FakeGateway = { url: "http://b:7777", site: older };
  let order = [a.url];
  const gws = { pick: () => order, succeeded: () => {}, failed: () => {}, isTrusted: () => false };
  const h = createEdgeHandler({ ...quiet, sites: { site: async () => newer.id }, gateways: gws, fetchImpl: gatewayFetch([a, b]) });
  const srv = await serve(h);
  t.after(srv.close);
  assert.equal((await srv.call("/")).body.toString(), "new");
  order = [b.url];
  const r = await srv.call("/");
  assert.equal(r.status, 503);
  assert.notEqual(r.body.toString(), "old");
});

test("edge: C0MPUTE_VERIFY_ALL verifies our own gateways too; the pool trusts seeds, not discoveries", async (t) => {
  const s = makeSite(PAGES);
  const ours: FakeGateway = { url: "http://127.0.0.1:7777", site: s };
  const h = createEdgeHandler({ ...quiet, verifyAll: true, sites: { site: async () => s.id }, gateways: pool([ours.url], [ours.url]), fetchImpl: gatewayFetch([ours]) });
  const srv = await serve(h);
  t.after(srv.close);
  const r = await srv.call("/");
  assert.equal(r.body.toString(), PAGES["index.html"]);
  assert.equal(r.headers["x-c0mpute-verified"], "1");
  assert.equal(ours.sSeen ?? 0, 0);

  const p = new GatewayPool({
    seeds: ["http://127.0.0.1:7777"], trusted: ["https://gw.example"], nodesUrl: "http://nodes/api",
    fetchImpl: (async (u: string) => (String(u) === "http://nodes/api"
      ? Response.json({ nodes: [{ gateway: "http://2.56.246.141:7777" }] }) : new Response("ok"))) as typeof fetch,
  });
  await p.refresh();
  assert.equal(p.size, 3);
  assert.ok(p.isTrusted("http://127.0.0.1:7777"));
  assert.ok(p.isTrusted("https://gw.example"));
  assert.ok(!p.isTrusted("http://2.56.246.141:7777"), "discovered from /api/nodes: a stranger's");
});

test("ChunkCache returns only bytes that still hash right", async () => {
  const dir = await tempDir();
  const c = new ChunkCache({ dir });
  await c.load();
  const bytes = Buffer.from("chunk");
  const h = blake3hex(bytes);
  c.put(h, bytes);
  await new Promise((r) => setTimeout(r, 50));
  assert.ok((await c.get(h))?.equals(bytes));
  assert.equal(await c.get(blake3hex("other")), null);
});
