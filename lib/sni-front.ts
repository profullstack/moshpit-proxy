// Sharing :443 with something else: the c0mpute edge behind an SNI router.
//
// A box whose :443 already belongs to an SNI router (nginx `stream {}` with
// ssl_preread, like dev2's) can hand the edge the names it does not serve
// itself, but the router cannot know which Moshpit names are c0mpute sites:
// anyone can point one at c0mpute at any time. So the router sends the edge
// every Moshpit-shaped name it has no route for, and the edge sorts them:
//
//   - a name the registry says is a c0mpute site is terminated here, as usual;
//   - anything else is spliced, byte for byte, to a fallback (the origin that
//     answered those names before), so a name the box serves itself keeps
//     working exactly as it did.
//
// The router usually prepends a PROXY protocol header (v1 or v2). It is
// dropped on the TLS path (the edge has no use for the visitor's address) and
// passed on untouched to the fallback, which expects it.

import { connect, createServer } from "node:net";
import type { Server, Socket } from "node:net";

/** Bytes of a PROXY protocol header at the start of `buf`: >0 found, 0 none, -1 need more. */
export function proxyHeaderLength(buf: Buffer): number {
  const V2 = Buffer.from([0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a]);
  const v1 = Buffer.from("PROXY ");
  const n = Math.min(buf.length, 12);
  if (buf.subarray(0, n).equals(V2.subarray(0, n))) {
    if (buf.length < 16) return -1;
    const total = 16 + buf.readUInt16BE(14);
    return buf.length < total ? -1 : total;
  }
  const m = Math.min(buf.length, 6);
  if (buf.subarray(0, m).equals(v1.subarray(0, m))) {
    const end = buf.indexOf("\r\n");
    if (end === -1) return buf.length >= 107 ? 0 : -1; // v1 lines are at most 107 bytes
    return end + 2;
  }
  return 0;
}

/**
 * The server name in a TLS ClientHello at the start of `buf`.
 * A string, null (a ClientHello without SNI, or not TLS at all), or undefined
 * when more bytes are needed.
 */
export function clientHelloSni(buf: Buffer): string | null | undefined {
  if (buf.length < 5) return undefined;
  if (buf[0] !== 0x16) return null; // not a handshake record
  const recLen = buf.readUInt16BE(3);
  if (buf.length < 5 + recLen) return undefined;
  const hs = buf.subarray(5, 5 + recLen);
  if (hs.length < 4 || hs[0] !== 0x01) return null; // not a ClientHello
  const hsLen = (hs[1] << 16) | (hs[2] << 8) | hs[3];
  // A ClientHello split across records is legal but no browser sends one
  // under 16 KiB; treat it as "no SNI" rather than reassembling.
  if (hsLen + 4 > hs.length) return null;
  let p = 4 + 2 + 32; // version, random
  const need = (k: number) => p + k <= 4 + hsLen;
  if (!need(1)) return null;
  p += 1 + hs[p]; // session id
  if (!need(2)) return null;
  p += 2 + hs.readUInt16BE(p); // cipher suites
  if (!need(1)) return null;
  p += 1 + hs[p]; // compression methods
  if (!need(2)) return null;
  const extEnd = p + 2 + hs.readUInt16BE(p);
  p += 2;
  while (p + 4 <= extEnd && p + 4 <= hs.length) {
    const type = hs.readUInt16BE(p);
    const len = hs.readUInt16BE(p + 2);
    p += 4;
    if (type === 0x0000) {
      // server_name_list: u16 length, then (u8 type, u16 len, name)*
      let q = p + 2;
      while (q + 3 <= p + len) {
        const kind = hs[q];
        const nlen = hs.readUInt16BE(q + 1);
        if (kind === 0) return hs.subarray(q + 3, q + 3 + nlen).toString("latin1");
        q += 3 + nlen;
      }
      return null;
    }
    p += len;
  }
  return null;
}

export interface SniFrontOptions {
  /** Expect a PROXY protocol header before the ClientHello. */
  proxyProtocol: boolean;
  /** Whether this edge terminates `servername` (a c0mpute site). */
  serves: (servername: string | null) => Promise<boolean>;
  /** Where every other connection goes, PROXY header included. Null closes them. */
  fallback: { host: string; port: number } | null;
  /** Hand a socket (header stripped, ClientHello unread) to the TLS server. */
  terminate: (socket: Socket) => void;
  timeoutMs?: number;
  log?: (line: string) => void;
}

const MAX_PEEK = 5 + 16384 + 232; // one full TLS record plus the largest PROXY header

/** A plain TCP server that reads the PROXY header and SNI, then terminates or splices. */
export function createSniFront(opts: SniFrontOptions): Server {
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const log = opts.log ?? (() => {});

  return createServer((socket) => {
    let buf = Buffer.alloc(0);
    let decided = false;
    const timer = setTimeout(() => { if (!decided) socket.destroy(); }, timeoutMs);
    socket.on("error", () => socket.destroy());

    const onData = (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      const hdr = opts.proxyProtocol ? proxyHeaderLength(buf) : 0;
      if (hdr === -1 && buf.length < MAX_PEEK) return;
      const rest = buf.subarray(Math.max(hdr, 0));
      const sni = clientHelloSni(rest);
      if (sni === undefined && buf.length < MAX_PEEK) return;
      decided = true;
      clearTimeout(timer);
      socket.off("data", onData);
      socket.pause();
      route(socket, buf, rest, sni ?? null);
    };
    socket.on("data", onData);
  });

  function route(socket: Socket, all: Buffer, rest: Buffer, sni: string | null) {
    opts.serves(sni).catch(() => false).then((mine) => {
      if (socket.destroyed) return;
      if (mine) {
        socket.unshift(rest);
        opts.terminate(socket);
        return;
      }
      if (!opts.fallback) { socket.destroy(); return; }
      const up = connect(opts.fallback.port, opts.fallback.host);
      up.setNoDelay(true);
      up.on("error", (e) => { log(`[edge] fallback for ${sni ?? "(no sni)"}: ${e.message}`); socket.destroy(); });
      socket.on("error", () => up.destroy());
      socket.on("close", () => up.destroy());
      up.on("close", () => socket.destroy());
      up.once("connect", () => {
        up.write(all);
        socket.pipe(up);
        up.pipe(socket);
        socket.resume();
      });
    });
  }
}
