// Is the leg that crosses the network actually post-quantum, and do we know?
//
// The detector in `pq.ts` infers "hybrid" from an *absence* — an empty
// `getEphemeralKeyInfo()` — so the tests that matter here are the ones that
// pin both halves of that mapping against real handshakes. If a future Node or
// OpenSSL changes what an empty result means, these fail loudly rather than
// letting the proxy relabel every session in silence.

import { after, describe, test } from "node:test";
import assert from "node:assert/strict";
import { createServer as createTlsServer, connect } from "node:tls";
import type { Server, TLSSocket } from "node:tls";
import { createLocalCa } from "../lib/ca.ts";
import { createPinClient } from "../lib/pins.ts";
import { createProxy } from "../lib/proxy.ts";
import { pinFromCertData } from "../lib/spki.ts";
import { describeKeyExchange, probeDetector, HYBRID_GROUP } from "../lib/pq.ts";
import { selfSigned, tempDir } from "./helpers.ts";

const cleanup: Array<() => Promise<void> | void> = [];
after(async () => {
  for (const fn of cleanup.reverse()) await fn();
});

/** An echo origin. `ecdhCurve` pins the groups it will accept, when given. */
async function startOrigin(cert: string, key: string, ecdhCurve?: string) {
  const server: Server = createTlsServer(
    { cert, key, ALPNProtocols: ["http/1.1"], ...(ecdhCurve ? { ecdhCurve } : {}) },
    (socket: TLSSocket) => {
      socket.on("data", (chunk) => socket.write(`echo:${chunk.toString()}`));
    },
  );
  server.on("tlsClientError", () => {});
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  cleanup.push(() => new Promise<void>((r) => server.close(() => r())));
  const address = server.address();
  return { port: typeof address === "object" && address ? address.port : 0, server };
}

async function startProxy(opts: {
  originPort: number;
  pins: Record<string, string[]>;
  requirePq?: boolean;
}) {
  const dir = await tempDir("moshpit-proxy-pq-");
  const ca = createLocalCa({ dir, tlds: ["moshpit"] });
  await ca.ensure();

  const proxy = createProxy({
    pins: createPinClient({
      overrides: opts.pins,
      fetchImpl: (async () => {
        throw new Error("no registry");
      }) as unknown as typeof fetch,
    }),
    ca,
    gatewayHost: "127.0.0.1",
    gatewayPort: opts.originPort,
    listenHost: "127.0.0.1",
    listenPort: 0,
    tlds: ["moshpit"],
    requirePq: opts.requirePq,
    connectTimeoutMs: 5_000,
  });

  const port = await proxy.listen();
  cleanup.push(() => proxy.close());
  return { proxy, port, rootPem: await ca.rootCertPem() };
}

function request(port: number, rootPem: string, servername: string, payload: string) {
  return new Promise<string>((resolve, reject) => {
    const socket = connect({
      host: "127.0.0.1", port, servername, ca: rootPem, ALPNProtocols: ["http/1.1"],
    });
    let settled = false;
    const fail = (error: Error) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(error);
    };
    socket.setTimeout(8_000, () => fail(new Error("timeout")));
    socket.once("secureConnect", () => socket.write(payload));
    socket.on("data", (chunk) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(chunk.toString());
    });
    socket.once("error", fail);
    socket.once("close", () => fail(new Error("closed with no data")));
  });
}

/** One client handshake against `port`, pinned to `group`, classified. */
async function classify(port: number, group?: string) {
  return new Promise<ReturnType<typeof describeKeyExchange>>((resolve, reject) => {
    const socket = connect({
      host: "127.0.0.1", port, rejectUnauthorized: false,
      ...(group ? { ecdhCurve: group } : {}),
    });
    socket.setTimeout(8_000, () => { socket.destroy(); reject(new Error("timeout")); });
    socket.once("secureConnect", () => {
      const kx = describeKeyExchange(socket);
      socket.destroy();
      resolve(kx);
    });
    socket.once("error", reject);
  });
}

describe("post-quantum detection", () => {
  test("the detector proves both halves of its own mapping", async () => {
    const probe = await probeDetector();
    // This build is Node 24 on OpenSSL 3.5, so the hybrid must be available.
    // If this fails on some future toolchain, the message says which half broke.
    assert.equal(probe.hybridAvailable, true, probe.detail);
    assert.equal(probe.usable, true, probe.detail);
  });

  test(`a session forced to ${HYBRID_GROUP} reads as post-quantum`, async () => {
    const dir = await tempDir();
    const origin = await selfSigned(dir, "hybrid.moshpit");
    const { port } = await startOrigin(origin.cert, origin.key);

    const kx = await classify(port, HYBRID_GROUP);
    assert.equal(kx.protocol, "TLSv1.3");
    assert.equal(kx.postQuantum, true);
  });

  test("a session forced to a classical group reads as classical, and is named", async () => {
    const dir = await tempDir();
    const origin = await selfSigned(dir, "classical.moshpit");
    const { port } = await startOrigin(origin.cert, origin.key);

    const kx = await classify(port, "x25519");
    assert.equal(kx.protocol, "TLSv1.3");
    assert.equal(kx.postQuantum, false);
    // Named, so a log line can say what actually happened instead of "not PQ".
    assert.equal(kx.group, "X25519");
  });

  test("an unconfigured client gets the hybrid — the default is already safe", async () => {
    const dir = await tempDir();
    const origin = await selfSigned(dir, "default.moshpit");
    const { port } = await startOrigin(origin.cert, origin.key);

    // No ecdhCurve anywhere: this is exactly how the proxy dials an origin.
    const kx = await classify(port);
    assert.equal(kx.postQuantum, true);
  });
});

describe("proxy post-quantum policy", () => {
  test("counts a post-quantum upstream leg", async () => {
    const dir = await tempDir();
    const origin = await selfSigned(dir, "pq.moshpit");
    const { port: originPort } = await startOrigin(origin.cert, origin.key);

    const { proxy, port, rootPem } = await startProxy({
      originPort,
      pins: { "pq.moshpit": [pinFromCertData(origin.cert)] },
    });

    assert.equal(await request(port, rootPem, "pq.moshpit", "hello"), "echo:hello");
    assert.equal(proxy.stats().pqSessions, 1);
    assert.equal(proxy.stats().classicalSessions, 0);
  });

  test("an origin without ML-KEM still passes, and is counted as classical", async () => {
    const dir = await tempDir();
    const origin = await selfSigned(dir, "old.moshpit");
    // Stands in for an origin on OpenSSL < 3.5: it will only do x25519.
    const { port: originPort } = await startOrigin(origin.cert, origin.key, "x25519");

    const { proxy, port, rootPem } = await startProxy({
      originPort,
      pins: { "old.moshpit": [pinFromCertData(origin.cert)] },
    });

    // Traffic is not broken by the fallback — that is the whole reason the
    // policy is off by default.
    assert.equal(await request(port, rootPem, "old.moshpit", "hello"), "echo:hello");
    assert.equal(proxy.stats().classicalSessions, 1);
    assert.equal(proxy.stats().pqSessions, 0);
    assert.equal(proxy.stats().refusedClassical, 0);
  });

  test("requirePq refuses an origin that fell back to a classical group", async () => {
    const dir = await tempDir();
    const origin = await selfSigned(dir, "strict.moshpit");
    const { port: originPort } = await startOrigin(origin.cert, origin.key, "x25519");

    const { proxy, port, rootPem } = await startProxy({
      originPort,
      pins: { "strict.moshpit": [pinFromCertData(origin.cert)] },
      requirePq: true,
    });

    await assert.rejects(request(port, rootPem, "strict.moshpit", "hello"));
    assert.equal(proxy.stats().refusedClassical, 1);
    assert.equal(proxy.stats().verified, 0);
  });

  test("requirePq lets a post-quantum origin through untouched", async () => {
    const dir = await tempDir();
    const origin = await selfSigned(dir, "strictok.moshpit");
    const { port: originPort } = await startOrigin(origin.cert, origin.key);

    const { proxy, port, rootPem } = await startProxy({
      originPort,
      pins: { "strictok.moshpit": [pinFromCertData(origin.cert)] },
      requirePq: true,
    });

    assert.equal(await request(port, rootPem, "strictok.moshpit", "hello"), "echo:hello");
    assert.equal(proxy.stats().verified, 1);
    assert.equal(proxy.stats().refusedClassical, 0);
  });
});
