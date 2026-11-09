// Verified reads of a c0mpute site from a gateway the edge does not trust.
//
// Any c0mpute node may announce itself as a public gateway, so the edge can
// no longer assume the gateway it asks is honest. For those gateways it does
// not take `/s/<site>/<path>` bytes at all. It asks for the evidence instead:
//
//   GET {gw}/hosting/v1/sites/{site}/resolve?path=<request path>
//     -> the owner's signed record, the manifest chunk (and, for a parted site,
//        the manifest parts consulted), and which file the gateway says the
//        path resolves to;
//   GET {gw}/hosting/v1/sites/{site}/chunks/{hex}
//     -> one chunk, by its blake3 hash.
//
// and checks every link of the chain the site owner signed: ed25519 signature
// over the record, site id derived from the owner key and name, manifest by its
// blake3, parts by theirs, the path resolution itself (a gateway must not skip
// a candidate that exists), and every chunk by its hash. Rollback to an older
// signed version is refused by remembering the highest seq seen per site.
//
// Every rule mirrors c0mpute `node/crates/c0mpute-core/src/hosting/site.rs`
// (profullstack/c0mpute); a change there must change here.

import { createPublicKey, verify as edVerify } from "node:crypto";
import { mkdir, readdir, readFile, rename, stat, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { blake3 } from "../vendor/noble-hashes/blake3.js";

/** Files are cut into chunks of this size (site.rs FILE_CHUNK_BYTES). */
export const FILE_CHUNK_BYTES = 1024 * 1024;
/** Largest site (site.rs MAX_SITE_BYTES). */
export const MAX_SITE_BYTES = 1024 * 1024 * 1024;
const MAX_FILES = 10_000_000;
const MAX_INLINE_FILES = 10_000;
const PART_FILES = 4_000;

const HASH_RE = /^[0-9a-f]{64}$/;
const KEY_RE = /^[0-9a-f]{64}$/;
const SIG_RE = /^[0-9a-f]{128}$/;
const SITE_RE = /^[0-9a-f]{20}$/;
const NAME_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

export class VerifyError extends Error {}

function fail(msg: string): never { throw new VerifyError(msg); }

/** blake3 of `bytes`, lowercase hex. */
export function blake3hex(bytes: Uint8Array | string): string {
  const data = typeof bytes === "string" ? new TextEncoder().encode(bytes) : bytes;
  return Buffer.from(blake3(data)).toString("hex");
}

/** Compare as Rust compares `String`s: by UTF-8 bytes. */
export function cmpPath(a: string, b: string): number {
  return Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

/* -------------------------------------------------------------- records */

export interface SiteRecord {
  v: number;
  site_id: string;
  name: string;
  owner: string;
  manifest: string;
  seq: number;
  size: number;
  domains: string[];
  preferred_hosts?: string[];
  price_per_gib_month?: string | null;
  payer?: string | null;
  sig: string;
}

/** The bytes the owner signs (site.rs SiteRecord::signing_bytes). */
export function signingBytes(r: SiteRecord): Buffer {
  const base = `${r.v >= 2 ? "c0mpute-hosting-v2" : "c0mpute-hosting-v1"}\n${r.site_id}\n${r.name}\n${r.owner}\n${r.manifest}\n${r.seq}\n${r.size}\n${(r.domains ?? []).join(",")}`;
  if (r.v < 2) return Buffer.from(base, "utf8");
  return Buffer.from(`${base}\n${(r.preferred_hosts ?? []).join(",")}\n${r.price_per_gib_month ?? ""}\n${r.payer ?? ""}`, "utf8");
}

/** The id a site with this owner and name always has (site.rs site_id_for). */
export function siteIdFor(ownerHex: string, name: string): string {
  return blake3hex(`c0mpute-site\n${ownerHex}\n${name}`).slice(0, 20);
}

const SPKI_ED25519 = Buffer.from("302a300506032b6570032100", "hex");

/** ed25519 over raw 32-byte key and 64-byte signature, both hex. */
export function ed25519Verify(ownerHex: string, sigHex: string, message: Uint8Array): boolean {
  if (!KEY_RE.test(ownerHex) || !SIG_RE.test(sigHex)) return false;
  try {
    const key = createPublicKey({ key: Buffer.concat([SPKI_ED25519, Buffer.from(ownerHex, "hex")]), format: "der", type: "spki" });
    return edVerify(null, message, key, Buffer.from(sigHex, "hex"));
  } catch {
    return false;
  }
}

const isStrArray = (v: unknown): v is string[] => Array.isArray(v) && v.every((s) => typeof s === "string");
const isU64 = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;

/**
 * Check a record is well formed, is the site asked for, and that its owner
 * signed it. Returns the record typed; throws VerifyError otherwise.
 */
export function verifyRecord(input: unknown, siteId: string): SiteRecord {
  const r = input as SiteRecord;
  if (!r || typeof r !== "object") fail("record is not an object");
  if (r.v !== 1 && r.v !== 2) fail(`unsupported record version ${String(r.v)}`);
  if (typeof r.site_id !== "string" || typeof r.name !== "string" || typeof r.owner !== "string"
    || typeof r.manifest !== "string" || typeof r.sig !== "string") fail("record fields missing");
  if (!isU64(r.seq) || !isU64(r.size)) fail("record seq/size is not a safe integer");
  const domains = r.domains ?? [];
  if (!isStrArray(domains)) fail("record domains malformed");
  if (r.v === 1) {
    if ((r.preferred_hosts?.length ?? 0) > 0 || (r.price_per_gib_month ?? null) !== null || (r.payer ?? null) !== null) {
      fail("a v1 record carries no marketplace terms");
    }
  } else {
    if (!isStrArray(r.preferred_hosts ?? [])) fail("record preferred_hosts malformed");
    if (r.price_per_gib_month != null && typeof r.price_per_gib_month !== "string") fail("record price malformed");
    if (r.payer != null && !(typeof r.payer === "string" && KEY_RE.test(r.payer))) fail("record payer malformed");
  }
  if (!NAME_RE.test(r.name)) fail("bad site name");
  if (!KEY_RE.test(r.owner)) fail("owner is not a hex ed25519 key");
  if (!HASH_RE.test(r.manifest)) fail("manifest is not a hash");
  if (r.size > MAX_SITE_BYTES) fail("site is over the size cap");
  if (!SITE_RE.test(siteId) || r.site_id !== siteId) fail("record is for another site");
  if (siteIdFor(r.owner, r.name) !== r.site_id) fail("site id does not match owner and name");
  if (!ed25519Verify(r.owner, r.sig, signingBytes({ ...r, domains }))) fail("bad record signature");
  return { ...r, domains };
}

/* ------------------------------------------------------------ manifests */

export interface FileEntry { size: number; content_type: string; chunks: string[] }
export interface PartRef { first: string; hash: string; files: number; bytes: number }
export type Manifest =
  | { kind: "inline"; name: string; files: Map<string, FileEntry> }
  | { kind: "parted"; name: string; files: number; bytes: number; parts: PartRef[] };

/** A manifest path (site.rs valid_path). */
export function validPath(p: string): boolean {
  return p.length > 0 && Buffer.byteLength(p) <= 1024 && !p.startsWith("/") && !p.includes("\\")
    && p.split("/").every((s) => s !== "" && s !== "." && s !== "..")
    // eslint-disable-next-line no-control-regex
    && !/[\u0000-\u001f\u007f-\u009f]/.test(p);
}

/** Chunks a file of `size` bytes is cut into. */
export function chunkCount(size: number): number {
  return Math.max(1, Math.ceil(size / FILE_CHUNK_BYTES));
}

function checkEntry(path: string, e: unknown): FileEntry {
  const f = e as FileEntry;
  if (!validPath(path)) fail(`invalid path in manifest: ${JSON.stringify(path)}`);
  if (!f || typeof f !== "object" || !isU64(f.size) || typeof f.content_type !== "string" || !isStrArray(f.chunks)) {
    fail(`file ${JSON.stringify(path)} is malformed`);
  }
  if (f.chunks.length !== chunkCount(f.size) || !f.chunks.every((h) => HASH_RE.test(h))) {
    fail(`file ${JSON.stringify(path)} has a bad chunk list`);
  }
  return { size: f.size, content_type: f.content_type, chunks: [...f.chunks] };
}

function filesMap(files: unknown, max: number): Map<string, FileEntry> {
  if (!files || typeof files !== "object" || Array.isArray(files)) fail("manifest files malformed");
  const keys = Object.keys(files);
  if (keys.length > max) fail("manifest lists too many files");
  const out = new Map<string, FileEntry>();
  for (const k of keys) out.set(k, checkEntry(k, (files as Record<string, unknown>)[k]));
  return out;
}

function parseJson(bytes: Uint8Array, what: string): Record<string, unknown> {
  let v: unknown;
  try { v = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); } catch { fail(`${what} is not JSON`); }
  if (!v || typeof v !== "object" || Array.isArray(v)) fail(`${what} is not an object`);
  return v as Record<string, unknown>;
}

/** Parse and check the manifest chunk a verified record pins. */
export function verifyManifest(bytes: Uint8Array, record: SiteRecord): Manifest {
  if (blake3hex(bytes) !== record.manifest) fail("manifest does not match the record's hash");
  const m = parseJson(bytes, "manifest");
  if (m.name !== record.name) fail("manifest is for another site name");
  if (m.v === 1) {
    const files = filesMap(m.files, MAX_INLINE_FILES);
    let total = 0;
    for (const f of files.values()) total += f.size;
    if (total > MAX_SITE_BYTES) fail("site is over the size cap");
    return { kind: "inline", name: m.name as string, files };
  }
  if (m.v === 2) {
    const parts = m.parts as PartRef[];
    if (!isU64(m.files) || !isU64(m.bytes) || !Array.isArray(parts) || parts.length === 0) fail("manifest root malformed");
    if ((m.files as number) > MAX_FILES || (m.bytes as number) > MAX_SITE_BYTES) fail("manifest root out of bounds");
    if (parts.length > Math.ceil(MAX_FILES / PART_FILES)) fail("manifest has too many parts");
    let files = 0, total = 0;
    for (const p of parts) {
      if (!p || typeof p.first !== "string" || typeof p.hash !== "string" || !isU64(p.files) || !isU64(p.bytes)
        || !HASH_RE.test(p.hash) || !validPath(p.first)) fail("manifest parts are malformed");
      files += p.files;
      total += p.bytes;
    }
    if (files !== m.files || total !== m.bytes) fail("manifest parts do not add up");
    for (let i = 1; i < parts.length; i++) if (cmpPath(parts[i - 1].first, parts[i].first) >= 0) fail("manifest parts out of order");
    return { kind: "parted", name: m.name as string, files: m.files as number, bytes: m.bytes as number,
      parts: parts.map((p) => ({ first: p.first, hash: p.hash, files: p.files, bytes: p.bytes })) };
  }
  fail(`unsupported manifest version ${String(m.v)}`);
}

/** Parse and check one part of a parted manifest against the ref naming it. */
export function verifyPart(bytes: Uint8Array, ref: PartRef): Map<string, FileEntry> {
  if (blake3hex(bytes) !== ref.hash) fail("manifest part does not match its hash");
  const p = parseJson(bytes, "manifest part");
  if (p.v !== 2) fail("manifest part version");
  const files = filesMap(p.files, PART_FILES);
  if (files.size !== ref.files) fail("manifest part does not match the root");
  let first: string | null = null, total = 0;
  for (const [k, f] of files) {
    if (first === null || cmpPath(k, first) < 0) first = k;
    total += f.size;
  }
  if (first !== ref.first) fail("manifest part starts at the wrong path");
  if (total !== ref.bytes) fail("manifest part size does not match the root");
  return files;
}

/** The part that would hold `path`: the last whose first path <= it. */
export function partFor(parts: PartRef[], path: string): PartRef | null {
  let found: PartRef | null = null;
  for (const p of parts) {
    if (cmpPath(p.first, path) <= 0) found = p; else break;
  }
  return found;
}

/* ------------------------------------------------------------ resolving */

function percentDecode(s: string): string {
  const bytes = Buffer.from(s, "utf8");
  const out: number[] = [];
  const hex = (b: number) => (b >= 48 && b <= 57 ? b - 48 : b >= 97 && b <= 102 ? b - 87 : b >= 65 && b <= 70 ? b - 55 : -1);
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] === 37 && i + 2 < bytes.length) {
      const h = hex(bytes[i + 1]), l = hex(bytes[i + 2]);
      if (h >= 0 && l >= 0) { out.push(h * 16 + l); i += 2; continue; }
    }
    out.push(bytes[i]);
  }
  return new TextDecoder("utf-8").decode(Uint8Array.from(out));
}

/** The manifest paths a request path may map to, in order (site.rs candidates). */
export function candidates(request: string): string[] {
  const p = request.replace(/^\/+/, "").split(/[?#]/)[0] ?? "";
  const decoded = percentDecode(p);
  if (decoded === "" || decoded.endsWith("/")) return [`${decoded}index.html`];
  const out = [decoded];
  const last = decoded.slice(decoded.lastIndexOf("/") + 1);
  if (!last.includes(".")) out.push(`${decoded}.html`, `${decoded}/index.html`);
  return out;
}

/** What a gateway's resolve route answers, as sent. */
export interface ResolveAnswer {
  v: number;
  record: unknown;
  manifest: string;
  parts?: string[];
  path: string | null;
  status: number;
  entry: FileEntry | null;
}

export interface Resolved {
  record: SiteRecord;
  /** The manifest path served, or null for a plain 404. */
  path: string | null;
  status: 200 | 404;
  entry: FileEntry | null;
}

const b64 = (s: unknown, what: string): Buffer => {
  if (typeof s !== "string" || !/^[A-Za-z0-9+/_-]*={0,2}$/.test(s)) fail(`${what} is not base64`);
  return Buffer.from(s, "base64");
};

/**
 * Check a gateway's resolve answer for `requestPath` of `siteId`, end to end.
 * `minSeq` is the highest seq already verified for the site (rollback guard).
 */
export function verifyResolve(siteId: string, requestPath: string, answer: unknown, minSeq = 0): Resolved {
  const a = answer as ResolveAnswer;
  if (!a || typeof a !== "object" || a.v !== 1) fail("resolve answer malformed");
  const record = verifyRecord(a.record, siteId);
  if (record.seq < minSeq) fail(`rollback: seq ${record.seq} is older than ${minSeq}`);
  const manifest = verifyManifest(b64(a.manifest, "manifest"), record);

  let lookup: (path: string) => FileEntry | null;
  if (manifest.kind === "inline") {
    lookup = (path) => manifest.files.get(path) ?? null;
  } else {
    const given = new Map<string, Map<string, FileEntry>>();
    if (a.parts !== undefined && !Array.isArray(a.parts)) fail("resolve parts malformed");
    for (const raw of a.parts ?? []) {
      const bytes = b64(raw, "manifest part");
      const hash = blake3hex(bytes);
      const ref = manifest.parts.find((p) => p.hash === hash);
      if (!ref) fail("a manifest part the root does not name");
      given.set(hash, verifyPart(bytes, ref));
    }
    lookup = (path) => {
      const ref = partFor(manifest.parts, path);
      if (!ref) return null;
      const files = given.get(ref.hash);
      if (!files) fail(`the gateway left out the manifest part for ${JSON.stringify(path)}`);
      return files.get(path) ?? null;
    };
  }

  // What the site actually serves for this path, worked out here, not taken
  // from the gateway: the first candidate present, else 404.html as a 404.
  let want: { path: string; status: 200 | 404; entry: FileEntry } | null = null;
  for (const c of candidates(requestPath)) {
    const e = lookup(c);
    if (e) { want = { path: c, status: 200, entry: e }; break; }
  }
  if (!want) {
    const e = lookup("404.html");
    if (e) want = { path: "404.html", status: 404, entry: e };
  }

  if (!want) {
    if (a.path !== null || a.status !== 404) fail("the gateway claims a file the site does not resolve to");
    return { record, path: null, status: 404, entry: null };
  }
  if (a.path !== want.path) fail(`the gateway resolved ${JSON.stringify(a.path)}, the site resolves ${JSON.stringify(want.path)}`);
  if (a.status !== want.status) fail("the gateway's status does not match the site's");
  const e = a.entry;
  if (!e || e.size !== want.entry.size || e.content_type !== want.entry.content_type || !Array.isArray(e.chunks)
    || e.chunks.length !== want.entry.chunks.length || e.chunks.some((h, i) => h !== want!.entry.chunks[i])) {
    fail("the gateway's entry does not match the manifest");
  }
  return { record, path: want.path, status: want.status, entry: want.entry };
}

/** Check one chunk against the hash the manifest gives it. */
export function verifyChunk(bytes: Uint8Array, hash: string, expectedLength?: number): void {
  if (expectedLength !== undefined && bytes.length !== expectedLength) fail(`chunk ${hash.slice(0, 12)} is ${bytes.length} bytes, want ${expectedLength}`);
  if (blake3hex(bytes) !== hash) fail(`chunk ${hash.slice(0, 12)} does not match its hash`);
}

/** The length chunk `i` of a file of `size` bytes must have. */
export function chunkLength(size: number, i: number): number {
  return Math.max(0, Math.min(FILE_CHUNK_BYTES, size - i * FILE_CHUNK_BYTES));
}

/** The ETag a gateway gives a file (mod.rs Hosting::serve). */
export function entryEtag(entry: FileEntry): string {
  return `"${blake3hex(entry.chunks.join(",")).slice(0, 32)}"`;
}

/* ------------------------------------------------------- rollback guard */

/**
 * The highest verified seq per site. A record with a lower seq, from any
 * gateway, is a rollback to an older signed version and is refused. Kept on
 * disk (one JSON file) when given a path.
 */
export class SeqGuard {
  private seqs = new Map<string, number>();
  private file: string | null;
  private dirty = false;
  private writing: Promise<void> | null = null;

  constructor(opts: { file?: string | null } = {}) { this.file = opts.file ?? null; }

  async load(): Promise<void> {
    if (!this.file) return;
    try {
      const raw = JSON.parse(await readFile(this.file, "utf8")) as Record<string, unknown>;
      for (const [k, v] of Object.entries(raw)) if (SITE_RE.test(k) && isU64(v)) this.seqs.set(k, v);
    } catch { /* none yet */ }
  }

  min(site: string): number { return this.seqs.get(site) ?? 0; }

  note(site: string, seq: number): void {
    if (seq <= this.min(site)) return;
    this.seqs.set(site, seq);
    if (!this.file) return;
    this.dirty = true;
    if (!this.writing) this.writing = this.drain().finally(() => { this.writing = null; });
  }

  /** Wait until every noted seq is on disk. */
  async flush(): Promise<void> {
    while (this.writing) await this.writing;
    if (this.dirty) await this.drain();
  }

  private async drain(): Promise<void> {
    if (!this.file) return;
    while (this.dirty) {
      this.dirty = false;
      const tmp = `${this.file}.${process.pid}.tmp`;
      try {
        await writeFile(tmp, JSON.stringify(Object.fromEntries(this.seqs)));
        await rename(tmp, this.file);
      } catch { unlink(tmp).catch(() => {}); }
    }
  }
}

/* ---------------------------------------------------------- chunk cache */

/**
 * Verified chunks on disk, by hash. Chunks are immutable, so a cached one is
 * good forever; it is re-hashed on read anyway (a disk can rot). Pruned oldest
 * first past `maxDiskBytes` on `load()`.
 */
export class ChunkCache {
  private dir: string | null;
  readonly maxDiskBytes: number;

  constructor(opts: { dir?: string | null; maxDiskBytes?: number } = {}) {
    this.dir = opts.dir ?? null;
    this.maxDiskBytes = opts.maxDiskBytes ?? 1024 * 1024 * 1024;
  }

  async load(): Promise<void> {
    if (!this.dir) return;
    try {
      await mkdir(this.dir, { recursive: true });
      const files = await Promise.all((await readdir(this.dir)).filter((f) => HASH_RE.test(f))
        .map(async (f) => ({ f, st: await stat(join(this.dir!, f)) })));
      files.sort((a, b) => b.st.mtimeMs - a.st.mtimeMs);
      let total = 0;
      for (const { f, st } of files) {
        total += st.size;
        if (total > this.maxDiskBytes) await unlink(join(this.dir, f)).catch(() => {});
      }
    } catch { /* no disk cache */ }
  }

  async get(hash: string): Promise<Buffer | null> {
    if (!this.dir || !HASH_RE.test(hash)) return null;
    try {
      const bytes = await readFile(join(this.dir, hash));
      if (blake3hex(bytes) === hash) return bytes;
      await unlink(join(this.dir, hash)).catch(() => {});
    } catch { /* not cached */ }
    return null;
  }

  /** Only ever called with bytes already checked against `hash`. */
  put(hash: string, bytes: Uint8Array): void {
    if (!this.dir || !HASH_RE.test(hash)) return;
    const file = join(this.dir, hash);
    const tmp = `${file}.${process.pid}.${Math.random().toString(36).slice(2)}`;
    writeFile(tmp, bytes).then(() => rename(tmp, file)).catch(() => { unlink(tmp).catch(() => {}); });
  }
}
