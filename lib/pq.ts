// Whether the session that actually crosses the network is post-quantum.
//
// The proxy's whole claim is that the right-hand leg — proxy to origin, through
// the gateway's SNI passthrough — is the real one. That leg is TLS 1.3, and on
// Node 24 against OpenSSL 3.5 it already offers `X25519MLKEM768` first and
// sends a real ML-KEM key share in the first flight, with no configuration at
// all. Measured, not assumed:
//
//   supported_groups: X25519MLKEM768, x25519, secp256r1, x448, ...
//   key_share sent  : X25519MLKEM768(1216B), x25519(32B)
//
// So the leg is usually already quantum-safe against harvest-now-decrypt-later.
// The problem is the word "usually": an origin on OpenSSL 3.0–3.4 — which is
// what Ubuntu 22.04 and 24.04 still ship — has no ML-KEM, so the handshake
// silently falls back to plain x25519 and succeeds. Nothing anywhere says so.
// A guarantee nobody can observe is not a guarantee, it is a hope.
//
// ## How the group is read, and why it looks backwards
//
// Node exposes no binding for `SSL_get_negotiated_group()`. What it has is
// `getEphemeralKeyInfo()`, which goes through `SSL_get_peer_tmp_key` — and that
// call cannot represent a hybrid KEM, so it fails and Node reports `{}`. For a
// classical group it succeeds and reports the name. That inverts into a usable
// signal, on a TLS 1.3 client socket:
//
//   {}                              -> a PQ hybrid was negotiated
//   { type, name: "X25519", size }  -> a classical group was negotiated
//
// Inferring a positive from an absence is fragile on purpose-built code, and
// this is exactly that. If a future Node or OpenSSL teaches `SSL_get_peer_tmp_key`
// about ML-KEM, `{}` stops meaning "hybrid" and every session silently
// re-labels itself as classical — or worse, the reverse. So the inference is
// never trusted on faith: `probeDetector()` proves both halves of the mapping
// against real loopback handshakes at startup, and the caller refuses to
// enforce anything if the proof fails.
//
// TLS 1.3 has no static key exchange — every handshake is (EC)DHE or a PSK — so
// an empty result cannot mean "not ephemeral" here the way it could under 1.2.
// The proxy never passes a `session`, so there is no PSK resumption path to
// confuse it either.

import { createServer, connect } from "node:tls";
import type { TLSSocket } from "node:tls";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { promisify } from "node:util";

const run = promisify(execFile);

/** The hybrid group OpenSSL 3.5 puts first, and the one worth asking for. */
export const HYBRID_GROUP = "X25519MLKEM768";

/** A classical group that every build back to OpenSSL 1.1 has, for the control trial. */
const CLASSICAL_GROUP = "x25519";

export type KeyExchange = {
  /** True when the key exchange was a post-quantum hybrid. */
  postQuantum: boolean;
  /** The named group, when Node can name it. Null for a hybrid, by construction. */
  group: string | null;
  /** The negotiated protocol, carried through for logs. */
  protocol: string | null;
};

/**
 * Classify the key exchange on a **client** socket.
 *
 * Returns `postQuantum: false` for a server socket, where
 * `getEphemeralKeyInfo()` returns null and there is nothing to read — the
 * caller should only ever ask about the upstream leg.
 */
export function describeKeyExchange(socket: TLSSocket): KeyExchange {
  const protocol = socket.getProtocol();

  // Below 1.3 there is no hybrid group to negotiate in the first place, so the
  // question is settled before the key info is consulted.
  if (protocol !== "TLSv1.3") return { postQuantum: false, group: null, protocol };

  let info: ReturnType<TLSSocket["getEphemeralKeyInfo"]>;
  try {
    info = socket.getEphemeralKeyInfo();
  } catch {
    return { postQuantum: false, group: null, protocol };
  }

  // Server socket: nothing to say.
  if (!info) return { postQuantum: false, group: null, protocol };

  const name = (info as { name?: string }).name;
  if (typeof name === "string" && name.length > 0) {
    return { postQuantum: false, group: name, protocol };
  }

  // Empty object on a TLS 1.3 client socket — the hybrid case. See the header.
  return { postQuantum: true, group: null, protocol };
}

export type DetectorProbe = {
  /** Both halves of the mapping held. Enforcement is safe to switch on. */
  usable: boolean;
  /** Whether this build can negotiate the hybrid group at all. */
  hybridAvailable: boolean;
  /** Human-readable reason, always set — logged verbatim at startup. */
  detail: string;
};

/**
 * Prove the detector against real handshakes before relying on it.
 *
 * Two loopback sessions against an ephemeral self-signed certificate: one
 * forced to the hybrid group, one forced to a classical group. The mapping in
 * the header has to hold for both. Anything else — a build without ML-KEM, a
 * Node that learned to name hybrids, an openssl that will not mint a cert —
 * comes back `usable: false` with the reason, and the caller degrades to
 * observing instead of enforcing.
 *
 * Costs two handshakes and one keygen, once, at startup.
 */
export async function probeDetector(): Promise<DetectorProbe> {
  let dir: string | null = null;
  try {
    dir = await mkdtemp(join(tmpdir(), "moshpit-pq-probe-"));
    const { cert, key } = await ephemeralCert(dir);

    const hybrid = await handshake(cert, key, HYBRID_GROUP);
    if (!hybrid.ok) {
      return {
        usable: false,
        hybridAvailable: false,
        detail:
          `this build cannot negotiate ${HYBRID_GROUP} (${hybrid.error}) — ` +
          "needs Node 24+ against OpenSSL 3.5+",
      };
    }

    const classical = await handshake(cert, key, CLASSICAL_GROUP);
    if (!classical.ok) {
      return { usable: false, hybridAvailable: true, detail: `control handshake failed: ${classical.error}` };
    }

    // The mapping, both directions. Either half being wrong makes the signal
    // meaningless, and a meaningless signal must not gate traffic.
    if (!hybrid.kx.postQuantum) {
      return {
        usable: false,
        hybridAvailable: true,
        detail:
          `detector broken: a forced ${HYBRID_GROUP} session reported ` +
          `${classicalLabel(hybrid.kx)} instead of a hybrid`,
      };
    }
    if (classical.kx.postQuantum) {
      return {
        usable: false,
        hybridAvailable: true,
        detail: `detector broken: a forced ${CLASSICAL_GROUP} session reported a hybrid`,
      };
    }

    return {
      usable: true,
      hybridAvailable: true,
      detail: `verified: ${HYBRID_GROUP} reads as hybrid, ${classicalLabel(classical.kx)} reads as classical`,
    };
  } catch (error) {
    return { usable: false, hybridAvailable: false, detail: `probe failed: ${(error as Error)?.message ?? error}` };
  } finally {
    if (dir) await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

function classicalLabel(kx: KeyExchange): string {
  return kx.group ?? "an unnamed group";
}

/** One loopback TLS 1.3 session with the client pinned to a single group. */
async function handshake(
  cert: string,
  key: string,
  group: string,
): Promise<{ ok: true; kx: KeyExchange } | { ok: false; error: string }> {
  const server = createServer({ cert, key });
  try {
    server.on("tlsClientError", () => {});
    const port = await new Promise<number>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => {
        const address = server.address();
        resolve(typeof address === "object" && address ? address.port : 0);
      });
    });

    return await new Promise((resolve) => {
      const socket = connect({
        host: "127.0.0.1",
        port,
        ecdhCurve: group,
        // A throwaway certificate for a loopback probe. The probe is about the
        // key exchange, not about identity, and there is no identity here.
        rejectUnauthorized: false,
      });
      const timer = setTimeout(() => {
        socket.destroy();
        resolve({ ok: false, error: "timed out" });
      }, 5_000);

      socket.once("secureConnect", () => {
        clearTimeout(timer);
        const kx = describeKeyExchange(socket);
        socket.destroy();
        resolve({ ok: true, kx });
      });
      socket.once("error", (error: Error) => {
        clearTimeout(timer);
        socket.destroy();
        resolve({ ok: false, error: error.message });
      });
    });
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

/**
 * A throwaway certificate for the probe, from openssl for the same reason
 * `ca.ts` gives: there is no X.509 creation API in node:crypto, and this is not
 * the place to hand-roll one.
 */
async function ephemeralCert(dir: string): Promise<{ cert: string; key: string }> {
  const certPath = join(dir, "probe.crt");
  const keyPath = join(dir, "probe.key");
  const cnf = join(dir, "probe.cnf");

  await writeFile(cnf, `[ req ]
distinguished_name = dn
prompt             = no

[ dn ]
CN = moshpit-pq-probe
`);

  await run("openssl", [
    "req", "-x509", "-new", "-nodes",
    "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
    "-sha256", "-days", "1",
    "-keyout", keyPath, "-out", certPath,
    "-config", cnf,
  ]);

  return { cert: await readFile(certPath, "utf8"), key: await readFile(keyPath, "utf8") };
}
