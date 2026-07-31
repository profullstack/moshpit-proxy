// The proxy. Two TLS sessions, one verification that actually means something.
//
//   browser --TLS--> proxy --TLS--> gateway (SNI passthrough) --TCP--> origin
//           local CA        registry-pinned key
//
// The right-hand session is the real one. Its certificate is checked against
// the key the registry published for this name, and nothing else: no chain, no
// issuer, no CA, no expiry-driven outage. The left-hand session exists only
// because browsers cannot be taught to do that check themselves.
//
// Note what the gateway is *not* doing in this picture. Under topology B it
// runs ssl_preread and routes on the SNI without a private key, so it never
// holds plaintext. The session terminating at the origin is genuinely
// end-to-end; the gateway learns which name was asked for and how many bytes
// moved, which is what a router learns.
//
// Known limitation, stated where someone will find it: ALPN is forced to
// http/1.1 in both directions. Raw bytes are piped between two independent TLS
// sessions, so the application protocol has to match on both, and the upstream
// protocol is not known until after the browser's handshake has already had to
// commit. Mirroring it properly means probing the origin from SNICallback and
// answering ALPNCallback from cache — worth doing, not worth blocking on.
// HTTP/3 would not survive a TCP proxy regardless.

import { createSecureContext, createServer, connect } from "node:tls";
import type { Server, TLSSocket } from "node:tls";
import type { LocalCa } from "./ca.ts";
import type { PinClient } from "./pins.ts";
import { pinFromPeer, pinMatches } from "./spki.ts";

export type ProxyStats = {
  accepted: number;
  verified: number;
  refusedNoName: number;
  refusedNoPin: number;
  refusedBadPin: number;
  upstreamErrors: number;
};

export type Proxy = {
  listen(): Promise<number>;
  close(): Promise<void>;
  stats(): ProxyStats;
  port(): number;
};

export function createProxy(options: {
  pins: PinClient;
  ca: LocalCa;
  gatewayHost: string;
  gatewayPort?: number;
  listenHost?: string;
  listenPort?: number;
  tlds: string[];
  tofu?: boolean;
  connectTimeoutMs?: number;
  idleTimeoutMs?: number;
  log?: (line: string) => void;
}): Proxy {
  const gatewayPort = options.gatewayPort ?? 443;
  const listenHost = options.listenHost ?? "127.0.0.1";
  const listenPort = options.listenPort ?? 8443;
  const connectTimeoutMs = options.connectTimeoutMs ?? 10_000;
  const idleTimeoutMs = options.idleTimeoutMs ?? 120_000;
  const tofu = options.tofu ?? false;
  const log = options.log ?? (() => {});
  const suffixes = options.tlds.map((t) => `.${t.replace(/^\.+/, "").toLowerCase()}`);

  const stats: ProxyStats = {
    accepted: 0, verified: 0,
    refusedNoName: 0, refusedNoPin: 0, refusedBadPin: 0, upstreamErrors: 0,
  };

  function inNamespace(name: string): boolean {
    return suffixes.some((suffix) => name.endsWith(suffix));
  }

  const server: Server = createServer({
    // Only http/1.1 is offered; see the note at the top of the file.
    ALPNProtocols: ["http/1.1"],

    // Refusing here rather than after the handshake is deliberate. A name with
    // no published key produces a TLS failure, which is what the browser
    // already knows how to explain, instead of a reset mid-request that looks
    // like the site is down.
    SNICallback: (servername, callback) => {
      const name = String(servername ?? "").trim().toLowerCase();
      if (!name || !inNamespace(name)) {
        stats.refusedNoName++;
        callback(new Error(`not a Moshpit name: ${name || "(none)"}`));
        return;
      }
      options.pins
        .lookup(name)
        .then(async (found) => {
          if (!found && !tofu) {
            stats.refusedNoPin++;
            log(`refuse ${name}: no key published`);
            throw new Error(`no pin published for ${name}`);
          }
          const leaf = await options.ca.certFor(name);
          return createSecureContext({ cert: leaf.cert, key: leaf.key });
        })
        .then((context) => callback(null, context))
        .catch((error) => callback(error as Error));
    },
  });

  server.on("secureConnection", (browser: TLSSocket) => {
    stats.accepted++;
    const name = String(browser.servername ?? "").toLowerCase();
    if (!name || !inNamespace(name)) {
      stats.refusedNoName++;
      browser.destroy();
      return;
    }

    // Nothing is read from the browser until the origin has been verified.
    // A paused socket buffers, so no request bytes can reach an unverified
    // peer even if the browser starts talking immediately.
    browser.pause();
    browser.setTimeout(idleTimeoutMs, () => browser.destroy());

    void verifyAndPipe(name, browser);
  });

  async function verifyAndPipe(name: string, browser: TLSSocket) {
    const allowed = await options.pins.lookup(name);
    if (!allowed && !tofu) {
      stats.refusedNoPin++;
      browser.destroy();
      return;
    }

    const upstream = connect({
      host: options.gatewayHost,
      port: gatewayPort,
      // The SNI the gateway routes on. It is also the identity being pinned.
      servername: name,
      ALPNProtocols: ["http/1.1"],
      // Not "no verification" — different verification. The chain is
      // meaningless here by design (the origin is self-signed and no CA has
      // ever heard of this name); the key is what is checked, below, and a
      // failure there closes the connection.
      rejectUnauthorized: false,
    });

    const timer = setTimeout(() => {
      stats.upstreamErrors++;
      upstream.destroy(new Error("upstream connect timeout"));
    }, connectTimeoutMs);

    upstream.once("secureConnect", () => {
      clearTimeout(timer);

      const presented = pinFromPeer(upstream);
      if (!presented) {
        stats.refusedBadPin++;
        log(`refuse ${name}: origin presented no certificate`);
        upstream.destroy();
        browser.destroy();
        return;
      }

      const expected = allowed?.pins ?? [];
      if (expected.length === 0) {
        if (!tofu) {
          stats.refusedNoPin++;
          upstream.destroy();
          browser.destroy();
          return;
        }
        // First sight of a key, with TOFU explicitly enabled. Recorded so a
        // later substitution is caught even though this one could not be.
        options.pins.remember(name, presented);
        log(`tofu ${name}: recorded ${presented}`);
      } else if (!pinMatches(presented, expected)) {
        stats.refusedBadPin++;
        log(`refuse ${name}: key mismatch, presented ${presented}`);
        upstream.destroy();
        browser.destroy();
        return;
      }

      stats.verified++;
      log(`ok ${name} (${allowed?.source ?? "tofu"})`);

      upstream.setTimeout(idleTimeoutMs, () => upstream.destroy());
      browser.resume();
      browser.pipe(upstream);
      upstream.pipe(browser);
    });

    const shutDown = (error?: Error) => {
      clearTimeout(timer);
      if (error) stats.upstreamErrors++;
      upstream.destroy();
      browser.destroy();
    };
    upstream.on("error", shutDown);
    browser.on("error", () => shutDown());
    upstream.on("close", () => browser.destroy());
    browser.on("close", () => upstream.destroy());
  }

  // A handshake that fails because a name has no key is an expected outcome
  // here, not a crash. Without this the process exits on the first one.
  server.on("tlsClientError", () => {});

  return {
    listen() {
      return new Promise<number>((resolve, reject) => {
        server.once("error", reject);
        server.listen(listenPort, listenHost, () => {
          server.removeListener("error", reject);
          const address = server.address();
          resolve(typeof address === "object" && address ? address.port : listenPort);
        });
      });
    },
    close() {
      return new Promise<void>((resolve) => server.close(() => resolve()));
    },
    stats: () => ({ ...stats }),
    port() {
      const address = server.address();
      return typeof address === "object" && address ? address.port : listenPort;
    },
  };
}
