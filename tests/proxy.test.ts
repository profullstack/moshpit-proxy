// End to end, against a real origin over real TLS.
//
// These are the tests that matter. Everything else checks a part; these check
// the claim — that a key the registry vouched for gets through, and one it did
// not is refused before a single request byte leaves the machine.

import { after, describe, test } from "node:test";
import assert from "node:assert/strict";
import { createServer as createTlsServer, connect } from "node:tls";
import type { Server, TLSSocket } from "node:tls";
import { createLocalCa } from "../lib/ca.ts";
import { createPinClient } from "../lib/pins.ts";
import { createProxy } from "../lib/proxy.ts";
import { pinFromCertData } from "../lib/spki.ts";
import { selfSigned, tempDir } from "./helpers.ts";

const cleanup: Array<() => Promise<void> | void> = [];
after(async () => {
  for (const fn of cleanup.reverse()) await fn();
});

/** An origin that echoes whatever it is sent, so the pipe can be observed. */
async function startOrigin(cert: string, key: string, port = 0): Promise<{ port: number; server: Server }> {
  const server = createTlsServer({ cert, key, ALPNProtocols: ["http/1.1"] }, (socket: TLSSocket) => {
    socket.on("data", (chunk) => socket.write(`echo:${chunk.toString()}`));
  });
  await new Promise<void>((resolve) => server.listen(port, "127.0.0.1", () => resolve()));
  cleanup.push(() => new Promise<void>((r) => server.close(() => r())));
  const address = server.address();
  return { port: typeof address === "object" && address ? address.port : 0, server };
}

async function startProxy(opts: {
  originPort: number;
  pins: Record<string, string[]>;
  tofu?: boolean;
}) {
  const dir = await tempDir("moshpit-proxy-");
  const ca = createLocalCa({ dir, tlds: ["moshpit"] });
  await ca.ensure();

  const proxy = createProxy({
    pins: createPinClient({
      overrides: opts.pins,
      tofu: opts.tofu,
      // No registry in these tests; overrides and TOFU are the only sources.
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
    tofu: opts.tofu,
    connectTimeoutMs: 5_000,
  });

  const port = await proxy.listen();
  cleanup.push(() => proxy.close());
  return { proxy, port, rootPem: await ca.rootCertPem() };
}

/** Speaks to the proxy the way a browser would: trusting only the local root. */
function request(port: number, rootPem: string, servername: string, payload: string) {
  return new Promise<string>((resolve, reject) => {
    const socket = connect({
      host: "127.0.0.1", port, servername, ca: rootPem, ALPNProtocols: ["http/1.1"],
    });
    let received = "";
    let settled = false;
    const fail = (error: Error) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(error);
    };
    const done = (value: string) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(value);
    };
    socket.setTimeout(8_000, () => fail(new Error("timeout")));
    socket.once("secureConnect", () => socket.write(payload));
    socket.on("data", (chunk) => {
      received += chunk.toString();
      done(received);
    });
    socket.once("error", fail);
    socket.once("close", () => fail(new Error("closed with no data")));
  });
}

describe("proxy", () => {
  test("passes traffic through when the origin key matches the pin", async () => {
    const dir = await tempDir();
    const origin = await selfSigned(dir, "good.moshpit");
    const { port: originPort } = await startOrigin(origin.cert, origin.key);

    const { proxy, port, rootPem } = await startProxy({
      originPort,
      pins: { "good.moshpit": [pinFromCertData(origin.cert)] },
    });

    assert.equal(await request(port, rootPem, "good.moshpit", "hello"), "echo:hello");
    assert.equal(proxy.stats().verified, 1);
    assert.equal(proxy.stats().refusedBadPin, 0);
  });

  test("refuses when the origin presents a different key", async () => {
    const dir = await tempDir();
    const origin = await selfSigned(dir, "swapped.moshpit");
    const impostor = await selfSigned(dir, "swapped.moshpit");
    const { port: originPort } = await startOrigin(origin.cert, origin.key);

    // The registry vouched for the impostor's key; the origin is serving its
    // own. That is exactly the substitution this whole design exists to catch.
    const { proxy, port, rootPem } = await startProxy({
      originPort,
      pins: { "swapped.moshpit": [pinFromCertData(impostor.cert)] },
    });

    await assert.rejects(request(port, rootPem, "swapped.moshpit", "hello"));
    assert.equal(proxy.stats().refusedBadPin, 1);
    assert.equal(proxy.stats().verified, 0);
  });

  test("refuses a name with no published key, rather than connecting anyway", async () => {
    const dir = await tempDir();
    const origin = await selfSigned(dir, "unpinned.moshpit");
    const { port: originPort } = await startOrigin(origin.cert, origin.key);

    const { proxy, port, rootPem } = await startProxy({ originPort, pins: {} });

    await assert.rejects(request(port, rootPem, "unpinned.moshpit", "hello"));
    assert.equal(proxy.stats().verified, 0);
  });

  test("refuses names outside the namespace", async () => {
    const dir = await tempDir();
    const origin = await selfSigned(dir, "elsewhere.com");
    const { port: originPort } = await startOrigin(origin.cert, origin.key);

    const { proxy, port, rootPem } = await startProxy({
      originPort,
      pins: { "elsewhere.com": [pinFromCertData(origin.cert)] },
    });

    await assert.rejects(request(port, rootPem, "elsewhere.com", "hello"));
    assert.ok(proxy.stats().refusedNoName > 0);
  });

  test("tofu accepts the first key and then holds it against a swap", async () => {
    const dir = await tempDir();
    const origin = await selfSigned(dir, "tofu.moshpit");
    const { port: originPort, server } = await startOrigin(origin.cert, origin.key);

    const { proxy, port, rootPem } = await startProxy({ originPort, pins: {}, tofu: true });

    assert.equal(await request(port, rootPem, "tofu.moshpit", "one"), "echo:one");
    assert.equal(proxy.stats().verified, 1);

    // Same name, same address, different key. Under TOFU the first key was
    // taken on faith; the second must not be.
    await new Promise<void>((r) => server.close(() => r()));
    const replacement = await selfSigned(dir, "tofu.moshpit");
    await startOrigin(replacement.cert, replacement.key, originPort);

    await assert.rejects(request(port, rootPem, "tofu.moshpit", "two"));
    assert.equal(proxy.stats().refusedBadPin, 1);
  });
});
