// Port 80, for the half of the web that is not https://.
//
// Proxy mode points Moshpit names at loopback, because DNS carries an address
// and has nowhere to put a port — a browser sent to `chovy.hacker` arrives at
// 127.0.0.1:443 or 127.0.0.1:80, and nothing else can be arranged. The TLS
// proxy took 443 and left 80 alone, so `http://chovy.hacker` landed on whatever
// web server the machine happened to be running. On a developer's desktop that
// is nginx, and the answer to every Moshpit name over http:// was its welcome
// page.
//
// So this takes 80 as well and forwards to the same origin the TLS path would
// have used.
//
// It verifies nothing, and cannot. There is no key to pin on a plain HTTP
// connection and no transport security to have an opinion about. That is not a
// downgrade: before proxy mode existed the name resolved straight to the origin
// and the browser spoke unauthenticated HTTP to it directly. This puts one hop
// in the middle of a conversation that was never protected. The upgrade path is
// https://, which is what the rest of this program is for.
import { createServer, connect, isIP } from "node:net";
import type { Server, Socket } from "node:net";

export interface HttpProxyOptions {
  pins: { lookup(name: string): Promise<{ target?: string } | null> };
  gatewayHost: string;
  /** Where a name with no registry target is sent. Port 80, not the TLS gateway port. */
  gatewayPort?: number;
  listenHost?: string;
  listenPort?: number;
  inNamespace(name: string): boolean;
  connectTimeoutMs?: number;
  log?: (line: string) => void;
}

/** The `Host:` of a request head, or null when there is not one yet. */
export function hostFromHead(head: string): string | null {
  // Only the request head is ever inspected, and only for this one field. The
  // body is never read into this process; it is piped.
  const match = /^host:[ \t]*([^\r\n]+)/im.exec(head);
  if (!match) return null;
  const value = match[1].trim().toLowerCase();
  // `Host: name:80` is legal and common. The port is ours, not the origin's.
  const bracketed = /^\[([^\]]+)\](?::\d+)?$/.exec(value);
  if (bracketed) return bracketed[1];
  if (isIP(value) === 6) return value;
  const colon = value.lastIndexOf(":");
  return colon > 0 && /^\d+$/.test(value.slice(colon + 1)) ? value.slice(0, colon) : value;
}

function upstreamFor(target: string | undefined, gatewayHost: string): { host: string; port?: number } {
  const t = target?.trim();
  if (!t) return { host: gatewayHost };
  const bracketed = /^\[([^\]]+)\](?::(\d+))?$/.exec(t);
  if (bracketed) return { host: bracketed[1], port: bracketed[2] ? Number(bracketed[2]) : undefined };
  if (isIP(t) === 6) return { host: t };
  const colon = t.lastIndexOf(":");
  if (colon > 0 && /^\d+$/.test(t.slice(colon + 1))) return { host: t.slice(0, colon), port: Number(t.slice(colon + 1)) };
  return { host: t };
}

const REFUSED = "HTTP/1.1 421 Misdirected Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

export function createHttpProxy(options: HttpProxyOptions) {
  const listenHost = options.listenHost ?? "127.0.0.1";
  const listenPort = options.listenPort ?? 80;
  const gatewayPort = options.gatewayPort ?? 80;
  const connectTimeoutMs = options.connectTimeoutMs ?? 10_000;
  const log = options.log ?? (() => {});

  let served = 0;
  let refused = 0;
  let upstreamErrors = 0;

  const server: Server = createServer((browser: Socket) => {
    // The head is accumulated only until `Host:` can be answered, then every
    // byte read so far is replayed to the origin and the two sockets are
    // joined. Nothing is parsed beyond that, and nothing is rewritten.
    let head = "";
    let settled = false;

    const refuse = () => {
      if (settled) return;
      settled = true;
      refused++;
      try { browser.end(REFUSED); } catch { /* already gone */ }
    };

    const onData = (chunk: Buffer) => {
      if (settled) return;
      head += chunk.toString("latin1");
      const endOfHead = head.indexOf("\r\n\r\n");
      const name = hostFromHead(head);

      // A request head with no Host by the time it ends is HTTP/1.0 or broken;
      // either way there is no name to forward it under.
      if (!name) {
        if (endOfHead !== -1 || head.length > 16 * 1024) refuse();
        return;
      }
      if (!options.inNamespace(name)) return refuse();

      settled = true;
      browser.removeListener("data", onData);
      browser.pause();
      void forward(name, browser, Buffer.from(head, "latin1"));
    };

    browser.on("data", onData);
    browser.on("error", () => { try { browser.destroy(); } catch { /* gone */ } });
    browser.setTimeout(connectTimeoutMs, () => { if (!settled) refuse(); });
  });

  async function forward(name: string, browser: Socket, pending: Buffer) {
    const allowed = await options.pins.lookup(name).catch(() => null);
    const where = upstreamFor(allowed?.target, options.gatewayHost);
    const upstream = connect({ host: where.host, port: where.port ?? gatewayPort });

    upstream.once("connect", () => {
      served++;
      log(`ok ${name} (http) → ${where.host}:${where.port ?? gatewayPort}`);
      upstream.write(pending);
      browser.pipe(upstream);
      upstream.pipe(browser);
      browser.resume();
    });

    const fail = () => {
      upstreamErrors++;
      log(`!! ${name} (http) — upstream ${where.host} did not answer`);
      try { browser.end(REFUSED); } catch { /* gone */ }
      try { upstream.destroy(); } catch { /* gone */ }
    };
    upstream.once("error", fail);
    upstream.setTimeout(connectTimeoutMs, fail);
  }

  return {
    listen(): Promise<number> {
      return new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(listenPort, listenHost, () => {
          const address = server.address();
          resolve(typeof address === "object" && address ? address.port : listenPort);
        });
      });
    },
    close(): Promise<void> {
      return new Promise((resolve) => server.close(() => resolve()));
    },
    stats() {
      return { served, refused, upstreamErrors };
    },
  };
}
