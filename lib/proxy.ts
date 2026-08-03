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
// The right-hand session is also where post-quantum confidentiality either
// happens or quietly does not. Node 24 on OpenSSL 3.5 offers X25519MLKEM768
// first with no configuration, so it usually happens; an origin on an older
// OpenSSL has no ML-KEM and the handshake falls back to x25519 without
// complaint. Every upstream leg is classified and counted, and `requirePq`
// turns the fallback into a refusal. See `pq.ts` for how the group is read and
// why the reading is proven at startup rather than trusted.
//
// Known limitation, stated where someone will find it: ALPN is forced to
// http/1.1 in both directions. Raw bytes are piped between two independent TLS
// sessions, so the application protocol has to match on both, and the upstream
// protocol is not known until after the browser's handshake has already had to
// commit. Mirroring it properly means probing the origin from SNICallback and
// answering ALPNCallback from cache — worth doing, not worth blocking on.
// HTTP/3 would not survive a TCP proxy regardless.

import { isIP } from "node:net";
import { createSecureContext, createServer, connect } from "node:tls";
import type { Server, TLSSocket } from "node:tls";
import type { LocalCa } from "./ca.ts";
import type { PinClient } from "./pins.ts";
import { pinFromPeer, pinMatches } from "./spki.ts";
import { describeKeyExchange } from "./pq.ts";

export type ProxyStats = {
  accepted: number;
  verified: number;
  refusedNoName: number;
  refusedNoPin: number;
  refusedBadPin: number;
  /** Origins turned away for negotiating a classical group, under requirePq. */
  refusedClassical: number;
  /** Upstream legs whose key exchange was a post-quantum hybrid. */
  pqSessions: number;
  /** Upstream legs that fell back to a classical group. */
  classicalSessions: number;
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
  /**
   * Refuse an origin whose key exchange was not post-quantum.
   *
   * Off by default, and it has to stay that way for now: an origin on
   * OpenSSL < 3.5 has no ML-KEM and would go dark the moment this flipped.
   * Turn it on once the grid is known to be on 3.5, using the counters below
   * to find out. The caller must only pass true when `probeDetector()` came
   * back usable — enforcing on a signal that has not been proven is worse
   * than not enforcing at all.
   */
  requirePq?: boolean;
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
  const requirePq = options.requirePq ?? false;
  const log = options.log ?? (() => {});
  const suffixes = options.tlds.map((t) => `.${t.replace(/^\.+/, "").toLowerCase()}`);

  const stats: ProxyStats = {
    accepted: 0, verified: 0,
    refusedNoName: 0, refusedNoPin: 0, refusedBadPin: 0, refusedClassical: 0,
    pqSessions: 0, classicalSessions: 0, upstreamErrors: 0,
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

  /**
   * Which host to open for a name: its own origin when the registry names one,
   * the gateway otherwise.
   *
   * A target may carry a port (`example.com:8443`) and may be an IPv6 literal,
   * which is why this is parsed rather than split on the first colon —
   * `2604:a880::1` has plenty of colons and no port.
   */
  function upstreamFor(
    allowed: { target?: string } | null,
    gatewayHost: string,
  ): { host: string; port?: number } {
    const target = allowed?.target?.trim();
    if (!target) return { host: gatewayHost };

    const bracketed = /^\[([^\]]+)\](?::(\d+))?$/.exec(target);
    if (bracketed) return { host: bracketed[1], port: bracketed[2] ? Number(bracketed[2]) : undefined };

    // Bare IPv6 literal: colons belong to the address, not to a port.
    if (isIP(target) === 6) return { host: target };

    const colon = target.lastIndexOf(":");
    if (colon > 0 && /^\d+$/.test(target.slice(colon + 1))) {
      return { host: target.slice(0, colon), port: Number(target.slice(colon + 1)) };
    }
    return { host: target };
  }

  async function verifyAndPipe(name: string, browser: TLSSocket) {
    const allowed = await options.pins.lookup(name);
    if (!allowed && !tofu) {
      stats.refusedNoPin++;
      browser.destroy();
      return;
    }

    // Straight to the origin when the registry says where it is, and only
    // through the gateway otherwise.
    //
    // Relaying through the gateway requires it to pass the connection through
    // by SNI (`ssl_preread`) rather than terminate it. Where it terminates —
    // which is what pit.moshcode.sh does today — every name presents the
    // gateway's own certificate, so the pin never matches and the proxy
    // correctly refuses every site. Three different names refused for the same
    // presented key is the signature of that.
    //
    // Dialling the target changes nothing about trust: the pin is still the
    // only thing that decides whether the connection survives, so a target
    // pointed somewhere hostile fails the same check as anything else. It only
    // removes a hop that has to be configured exactly right to work at all.
    const upstreamHost = upstreamFor(allowed, options.gatewayHost);
    const upstream = connect({
      host: upstreamHost.host,
      port: upstreamHost.port ?? gatewayPort,
      // The SNI the origin (or the gateway) routes on. It is also the identity
      // being pinned.
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

      // Identity is settled; now record what kind of key exchange carried it.
      // This is checked after the pin on purpose — an origin that failed
      // verification learns nothing about the policy it would have faced.
      const kx = describeKeyExchange(upstream);
      const kxLabel = kx.postQuantum ? "hybrid-pq" : `classical/${kx.group ?? "unknown"}`;

      if (kx.postQuantum) {
        stats.pqSessions++;
      } else {
        stats.classicalSessions++;
        if (requirePq) {
          stats.refusedClassical++;
          log(`refuse ${name}: key exchange was ${kxLabel}, post-quantum required`);
          upstream.destroy();
          browser.destroy();
          return;
        }
        // Not an error — the session is still confidential against everything
        // that exists today. It is recorded because a transcript captured now
        // is decryptable by a quantum adversary later, and the operator cannot
        // fix what nobody told them about.
        log(`warn ${name}: origin has no ML-KEM, fell back to ${kxLabel}`);
      }

      stats.verified++;
      log(`ok ${name} (${allowed?.source ?? "tofu"}) ${kx.protocol ?? "?"} ${kxLabel}`);

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
