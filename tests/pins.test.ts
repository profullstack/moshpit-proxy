import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { createPinClient } from "../lib/pins.ts";

function stubFetch(handler: (name: string) => { status: number; body?: unknown }) {
  let calls = 0;
  const impl = (async (url: string | URL) => {
    calls++;
    const name = new URL(String(url)).searchParams.get("name") ?? "";
    const { status, body } = handler(name);
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => body,
    } as unknown as Response;
  }) as unknown as typeof fetch;
  return { impl, calls: () => calls };
}

describe("pin client", () => {
  test("returns pins the registry published", async () => {
    const { impl } = stubFetch(() => ({ status: 200, body: { name: "a.moshpit", pins: ["PIN1"] } }));
    const client = createPinClient({ fetchImpl: impl });

    assert.deepEqual(await client.lookup("a.moshpit"), {
      name: "a.moshpit", pins: ["PIN1"], source: "registry",
    });
  });

  test("caches, so a flood of connections is one lookup", async () => {
    const { impl, calls } = stubFetch(() => ({ status: 200, body: { pins: ["PIN1"] } }));
    const client = createPinClient({ fetchImpl: impl });

    await Promise.all(Array.from({ length: 20 }, () => client.lookup("a.moshpit")));
    assert.equal(calls(), 1);
  });

  test("coalesces concurrent lookups for the same name", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let calls = 0;
    const impl = (async () => {
      calls++;
      await gate;
      return { ok: true, status: 200, json: async () => ({ pins: ["PIN1"] }) } as unknown as Response;
    }) as unknown as typeof fetch;

    const client = createPinClient({ fetchImpl: impl });
    const all = Promise.all([client.lookup("a.moshpit"), client.lookup("a.moshpit")]);
    release();
    await all;

    assert.equal(calls, 1);
  });

  test("treats 400 and 404 as definite answers, not errors", async () => {
    for (const status of [400, 404]) {
      const { impl } = stubFetch(() => ({ status }));
      const client = createPinClient({ fetchImpl: impl });
      assert.equal(await client.lookup("nope.moshpit"), null);
    }
  });

  test("a registry outage yields null, never a stale accept", async () => {
    const impl = (async () => {
      throw new Error("registry down");
    }) as unknown as typeof fetch;
    const client = createPinClient({ fetchImpl: impl });

    assert.equal(await client.lookup("a.moshpit"), null);
    assert.equal(client.stats().errors, 1);
  });

  test("an empty pins array is 'no key', not 'any key'", async () => {
    const { impl } = stubFetch(() => ({ status: 200, body: { pins: [] } }));
    const client = createPinClient({ fetchImpl: impl });

    assert.equal(await client.lookup("a.moshpit"), null);
  });

  test("overrides win over the registry and skip it entirely", async () => {
    const { impl, calls } = stubFetch(() => ({ status: 200, body: { pins: ["FROM-REGISTRY"] } }));
    const client = createPinClient({
      fetchImpl: impl,
      overrides: { "A.MoshPit": "LOCAL" },
    });

    assert.deepEqual(await client.lookup("a.moshpit"), {
      name: "a.moshpit", pins: ["LOCAL"], source: "override",
    });
    assert.equal(calls(), 0);
  });

  test("multiple pins are kept, so a key can rotate without a flag day", async () => {
    const { impl } = stubFetch(() => ({ status: 200, body: { pins: ["OLD", "NEW"] } }));
    const client = createPinClient({ fetchImpl: impl });

    assert.deepEqual((await client.lookup("a.moshpit"))?.pins, ["OLD", "NEW"]);
  });

  test("tofu is off by default", async () => {
    const { impl } = stubFetch(() => ({ status: 404 }));
    const client = createPinClient({ fetchImpl: impl });

    assert.equal(await client.lookup("a.moshpit"), null);
  });

  test("tofu records the first key and holds it afterwards", async () => {
    const { impl } = stubFetch(() => ({ status: 404 }));
    const client = createPinClient({ fetchImpl: impl, tofu: true });

    assert.deepEqual(await client.lookup("a.moshpit"), {
      name: "a.moshpit", pins: [], source: "tofu",
    });

    client.remember("a.moshpit", "SEEN");
    assert.deepEqual((await client.lookup("a.moshpit"))?.pins, ["SEEN"]);
  });

  test("names are normalised", async () => {
    const { impl, calls } = stubFetch(() => ({ status: 200, body: { pins: ["PIN1"] } }));
    const client = createPinClient({ fetchImpl: impl });

    await client.lookup("A.MoshPit.");
    await client.lookup("a.moshpit");
    assert.equal(calls(), 1);
  });
});
