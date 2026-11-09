// The c0mpute edge, end to end against real sockets: a fake registry that
// signs with a real (openssl) CA, fake c0mpute gateways, and an https client
// that trusts only that CA, the way a browser with the Moshpit root does.

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createServer } from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { request as httpsRequest } from "node:https";
import { request as httpRequest } from "node:http";
import type { AddressInfo } from "node:net";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

import {
  CertStore,
  GatewayPool,
  SiteLookup,
  createEdgeHandler,
  fibonacciDelay,
  fibonacciDelays,
  LastGood,
  gatewaysFromNodes,
  normalizeGateway,
  normalizeHost,
  startEdge,
  upstreamUrl,
} from "../lib/c0mpute-edge.ts";
import { edgeConfig, hostPort } from "../bin/moshpit-c0mpute-edge.ts";
import { clientHelloSni, proxyHeaderLength } from "../lib/sni-front.ts";
import { connect as netConnect, createServer as createNetServer } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { tempDir } from "./helpers.ts";

const run = promisify(execFile);
const SITE = "0123456789abcdef0123";

function listen(handler: (req: IncomingMessage, res: ServerResponse) => void): Promise<{ server: Server; url: string }> {
  const server = createServer(handler);
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => {
    resolve({ server, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}` });
  }));
}

function body(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => { let s = ""; req.on("data", (d) => { s += d; }); req.on("end", () => resolve(s)); });
}

function fakeFetch(routes: Record<string, () => Response | Promise<Response>>): typeof fetch {
  return (async (input: string | URL | Request) => {
    const url = String(input);
    const route = routes[url];
    if (!route) throw new Error(`connect ECONNREFUSED ${url}`);
    return route();
  }) as typeof fetch;
}

/* ------------------------------------------------------------- pure */

test("names, gateways and upstream paths", () => {
  assert.equal(normalizeHost("Blue.Eggs"), "blue.eggs");
  assert.equal(normalizeHost("blue.eggs:443"), "blue.eggs");
  assert.equal(normalizeHost("blue.eggs."), "blue.eggs");
  assert.equal(normalizeHost("www.blue.eggs"), null, "the registry holds label.tld only");
  assert.equal(normalizeHost("127.0.0.1"), null);
  assert.equal(normalizeHost(undefined), null);

  assert.equal(normalizeGateway("http://1.2.3.4:7777/"), "http://1.2.3.4:7777");
  assert.equal(normalizeGateway("https://gw.example.org/x"), "https://gw.example.org");
  assert.equal(normalizeGateway("ftp://gw.example.org"), null);
  assert.equal(normalizeGateway("http://u:p@gw.example.org"), null);
  assert.equal(normalizeGateway(42), null);

  assert.deepEqual(gatewaysFromNodes({ nodes: [
    { id: "a", gateway: "http://1.2.3.4:7777" },
    { id: "b" },
    { id: "c", gateway: "javascript:alert(1)" },
    { id: "d", gateway: "http://1.2.3.4:7777/" },
  ] }), ["http://1.2.3.4:7777"]);
  assert.deepEqual(gatewaysFromNodes(null), []);

  assert.equal(upstreamUrl("http://g:7777", SITE, "/about?x=1"), `http://g:7777/s/${SITE}/about?x=1`);
  assert.equal(upstreamUrl("http://g:7777", SITE, "/"), `http://g:7777/s/${SITE}/`);
});

test("edge config reads the environment", () => {
  const c = edgeConfig({ C0MPUTE_GATEWAYS: "http://a:7777, http://b:7777", C0MPUTE_NODES_URL: "", EDGE_HTTP_PORT: "0" });
  assert.deepEqual(c.seeds, ["http://a:7777", "http://b:7777"]);
  assert.equal(c.nodesUrl, null, "empty disables discovery");
  assert.equal(c.httpPort, 0);
  assert.equal(edgeConfig({}).nodesUrl, "https://c0mpute.com/api/nodes");
  assert.equal(edgeConfig({}).httpsPort, 443);
  assert.equal(edgeConfig({}).proxyProtocol, false);
  assert.equal(edgeConfig({}).fallback, null);
  const behind = edgeConfig({ EDGE_PROXY_PROTOCOL: "1", EDGE_FALLBACK: "127.0.0.1:8444" });
  assert.equal(behind.proxyProtocol, true);
  assert.deepEqual(behind.fallback, { host: "127.0.0.1", port: 8444 });
  assert.deepEqual(hostPort("[::1]:443"), { host: "::1", port: 443 });
  assert.equal(hostPort("127.0.0.1"), null);
  assert.equal(hostPort("x:70000"), null);
});

/* ------------------------------------------------------- behind a router */

/** The first bytes a real TLS client sends for `servername`. */
function captureClientHello(servername?: string): Promise<Buffer> {
  return new Promise((resolve) => {
    const srv = createNetServer((sock) => {
      sock.once("data", (d: Buffer) => { resolve(d); sock.destroy(); srv.close(); });
    });
    srv.listen(0, "127.0.0.1", () => {
      const port = (srv.address() as AddressInfo).port;
      const c = tlsConnect({ host: "127.0.0.1", port, ...(servername ? { servername } : {}), rejectUnauthorized: false });
      c.on("error", () => {});
    });
  });
}

test("PROXY headers and the SNI are read off the front of a connection", async () => {
  const v1 = Buffer.from("PROXY TCP4 1.2.3.4 5.6.7.8 1111 443\r\nrest");
  assert.equal(proxyHeaderLength(v1), v1.indexOf("rest"));
  assert.equal(proxyHeaderLength(Buffer.from("PROXY TCP4 1.2")), -1, "need more");
  assert.equal(proxyHeaderLength(Buffer.from([0x16, 3, 1])), 0, "no header");
  const v2 = Buffer.concat([Buffer.from([0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a, 0x21, 0x11, 0, 12]), Buffer.alloc(12), Buffer.from("x")]);
  assert.equal(proxyHeaderLength(v2), 28);
  assert.equal(proxyHeaderLength(v2.subarray(0, 20)), -1);

  const hello = await captureClientHello("alt.2600");
  assert.equal(clientHelloSni(hello), "alt.2600");
  assert.equal(clientHelloSni(hello.subarray(0, 40)), undefined, "need more");
  assert.equal(clientHelloSni(await captureClientHello()), null, "no SNI");
  assert.equal(clientHelloSni(Buffer.from("GET / HTTP/1.1\r\n\r\n")), null, "not TLS");
});

test("behind an SNI router: c0mpute names terminate here, every other name is spliced to the fallback", async (t) => {
  const dir = await tempDir("moshpit-edge-front-");
  const ca = await makeCa(dir);
  const good = await listen((req, res) => {
    if (req.url === "/healthz") { res.writeHead(200); return res.end("ok"); }
    res.writeHead(200, { "content-type": "text/plain" });
    res.end(`gateway ${req.url}`);
  });
  const registry = await listen(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://x");
    if (url.pathname === "/api/moshpit/resolve") {
      const name = url.searchParams.get("name");
      return res.end(JSON.stringify({ name, c0mpute: name === "blue.eggs" ? SITE : null }));
    }
    if (req.method === "POST" && url.pathname === "/api/moshpit/tlds/eggs/certs") {
      const { label, csr } = JSON.parse(await body(req));
      res.writeHead(201, { "content-type": "application/json" });
      return res.end(JSON.stringify({ chain: await sign(dir, ca, `${label}.eggs`, csr) }));
    }
    res.writeHead(404); res.end("{}");
  });
  // The fallback records exactly what it was sent, then answers.
  const seen: Buffer[] = [];
  const fallback = createNetServer((sock) => {
    sock.once("data", (d: Buffer) => { seen.push(d); sock.end("FALLBACK"); });
  });
  await new Promise<void>((r) => fallback.listen(0, "127.0.0.1", () => r()));
  const fbPort = (fallback.address() as AddressInfo).port;

  const gateways = new GatewayPool({ seeds: [good.url] });
  await gateways.refresh();
  const sites = new SiteLookup({ registryBase: registry.url });
  const certs = new CertStore({ dir: join(dir, "certs"), registryBase: registry.url, apiKey: "k" });
  const edge = await startEdge({ sites, gateways, certs, host: "127.0.0.1", httpsPort: 0, httpPort: 0,
    proxyProtocol: true, fallback: { host: "127.0.0.1", port: fbPort } });
  const port = (edge.https.address() as AddressInfo).port;
  t.after(async () => {
    await edge.close();
    for (const s of [good.server, registry.server, fallback]) s.close();
  });
  const PROXY = "PROXY TCP4 203.0.113.9 127.0.0.1 40000 443\r\n";

  await t.test("a c0mpute name, after a PROXY header, gets its leaf and its site", async () => {
    const text = await new Promise<string>((resolve, reject) => {
      const raw = netConnect(port, "127.0.0.1", () => {
        raw.write(PROXY);
        const tls = tlsConnect({ socket: raw, servername: "blue.eggs", ca: ca.pem }, () => {
          tls.write("GET /x HTTP/1.1\r\nHost: blue.eggs\r\nConnection: close\r\n\r\n");
        });
        let out = "";
        tls.on("data", (d) => { out += d; });
        tls.on("end", () => resolve(out));
        tls.on("error", reject);
      });
    });
    assert.match(text, /^HTTP\/1\.1 200/);
    assert.match(text, new RegExp(`gateway /s/${SITE}/x`));
  });

  await t.test("any other name reaches the fallback byte for byte, PROXY header first", async () => {
    const hello = await captureClientHello("red.eggs");
    const reply = await new Promise<string>((resolve, reject) => {
      const raw = netConnect(port, "127.0.0.1", () => { raw.write(Buffer.concat([Buffer.from(PROXY), hello])); });
      let out = "";
      raw.on("data", (d) => { out += d; });
      raw.on("end", () => resolve(out));
      raw.on("error", reject);
    });
    assert.equal(reply, "FALLBACK");
    assert.equal(seen.length, 1);
    assert.ok(seen[0].equals(Buffer.concat([Buffer.from(PROXY), hello])), "PROXY header and ClientHello untouched");
  });
});

/* ------------------------------------------------------------ gateways */

test("the pool discovers, health-checks, and orders gateways", async () => {
  let clock = 1_000_000;
  const ok = () => new Response("{}", { status: 200 });
  const pool = new GatewayPool({
    seeds: ["http://seed:7777"],
    nodesUrl: "https://c0mpute.example/api/nodes",
    now: () => clock,
    fetchImpl: fakeFetch({
      "https://c0mpute.example/api/nodes": () => Response.json({ nodes: [{ gateway: "http://found:7777" }, { gateway: "http://dead:7777" }] }),
      "http://seed:7777/healthz": ok,
      "http://found:7777/healthz": ok,
      // dead has no route: connection refused
    }),
  });
  await pool.refresh();
  assert.equal(pool.size, 3);
  const picked = pool.pick(3);
  assert.equal(picked.length, 3);
  assert.equal(picked[2], "http://dead:7777", "a failing gateway goes last, not away");
  assert.deepEqual(new Set(picked.slice(0, 2)), new Set(["http://seed:7777", "http://found:7777"]));

  // Equally fast gateways take turns at the front.
  const fronts = new Set([pool.pick(1)[0], pool.pick(1)[0]]);
  assert.equal(fronts.size, 2, "rotates among the fastest");

  // A failure sends a gateway to the back until its back-off runs out.
  pool.failed("http://seed:7777");
  assert.notEqual(pool.pick(1)[0], "http://seed:7777");
  clock += 11_000;
  assert.ok(pool.pick(2).includes("http://seed:7777"), "back after its back-off");
  pool.succeeded("http://seed:7777");
});

test("a failed discovery keeps the gateways already known", async () => {
  const pool = new GatewayPool({
    seeds: ["http://seed:7777"],
    nodesUrl: "https://c0mpute.example/api/nodes",
    fetchImpl: fakeFetch({ "http://seed:7777/healthz": () => new Response("ok") }),
  });
  await pool.refresh();
  assert.deepEqual(pool.pick(), ["http://seed:7777"]);
});

/* --------------------------------------------------------------- sites */

test("site lookups come from the registry, cached, and survive an outage", async () => {
  let calls = 0;
  let down = false;
  let clock = 0;
  const lookup = new SiteLookup({
    registryBase: "https://pit.example",
    now: () => clock,
    fetchImpl: (async (input: string | URL | Request) => {
      calls++;
      if (down) throw new Error("ECONNREFUSED");
      const name = new URL(String(input)).searchParams.get("name");
      if (name === "blue.eggs") return Response.json({ name, c0mpute: SITE, target: "edge.example" });
      if (name === "evil.eggs") return Response.json({ name, c0mpute: "../../x" });
      return Response.json({ name, c0mpute: null });
    }) as typeof fetch,
  });
  assert.equal(await lookup.site("blue.eggs"), SITE);
  assert.equal(await lookup.site("BLUE.eggs"), SITE);
  assert.equal(calls, 1, "cached");
  assert.equal(await lookup.site("red.eggs"), null);
  assert.equal(await lookup.site("evil.eggs"), null, "only a real site id is believed");
  assert.equal(await lookup.site("not a name"), null);
  clock += 120_000;
  down = true;
  assert.equal(await lookup.site("blue.eggs"), SITE, "an outage keeps the last answer");
});

/* ------------------------------------------------------------- serving */

async function makeCa(dir: string) {
  const key = join(dir, "ca.key");
  const crt = join(dir, "ca.crt");
  await run("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
    "-keyout", key, "-out", crt, "-days", "2", "-subj", "/CN=Test Moshpit Root",
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"]);
  return { key, crt, pem: await readFile(crt, "utf8") };
}

async function sign(dir: string, ca: { key: string; crt: string; pem: string }, name: string, csr: string, days = 30) {
  const csrPath = join(dir, `${name}.${Date.now()}.csr`);
  const ext = join(dir, `${name}.ext`);
  const out = join(dir, `${name}.${Date.now()}.crt`);
  await writeFile(csrPath, csr);
  await writeFile(ext, `basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:${name},DNS:*.${name}\n`);
  await run("openssl", ["x509", "-req", "-in", csrPath, "-CA", ca.crt, "-CAkey", ca.key, "-CAcreateserial",
    "-out", out, "-days", String(days), "-extfile", ext]);
  return (await readFile(out, "utf8")) + ca.pem;
}

function get(port: number, name: string, path = "/", { ca, host = name, servername = name }: { ca: string; host?: string; servername?: string }) {
  return new Promise<{ status: number; headers: Record<string, unknown>; text: string }>((resolve, reject) => {
    const req = httpsRequest({ host: "127.0.0.1", port, path, servername, ca, headers: { host } }, (res) => {
      let text = "";
      res.on("data", (d) => { text += d; });
      res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, text }));
    });
    req.on("error", reject);
    req.end();
  });
}

test("https://<name> is served from a healthy gateway with a registry-signed leaf", async (t) => {
  const dir = await tempDir("moshpit-edge-");
  const ca = await makeCa(dir);

  // Two gateways: one broken (503 on everything), one serving the site.
  const broken = await listen((_req, res) => { res.writeHead(503); res.end("down"); });
  const good = await listen((req, res) => {
    if (req.url === "/healthz") { res.writeHead(200); return res.end("ok"); }
    const prefix = `/s/${SITE}`;
    if (!req.url?.startsWith(prefix)) { res.writeHead(404); return res.end("no such site"); }
    const path = req.url.slice(prefix.length);
    res.writeHead(200, { "content-type": "text/html", etag: '"v1"', "set-cookie": "leak=1" });
    res.end(`<h1>site ${SITE} at ${path}</h1>`);
  });

  // The registry: resolves blue.eggs to the site; signs only names with a site.
  const issued: string[] = [];
  const registry = await listen(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://x");
    if (url.pathname === "/api/moshpit/resolve") {
      const name = url.searchParams.get("name");
      return res.end(JSON.stringify({ name, c0mpute: name === "blue.eggs" ? SITE : null }));
    }
    if (req.method === "POST" && url.pathname === "/api/moshpit/tlds/eggs/certs") {
      if (req.headers.authorization !== "Bearer edge-key") { res.writeHead(401); return res.end("{}"); }
      const { label, csr } = JSON.parse(await body(req));
      if (label !== "blue") { res.writeHead(403); return res.end(JSON.stringify({ error: "not yours" })); }
      issued.push(label);
      const chain = await sign(dir, ca, `${label}.eggs`, csr);
      res.writeHead(201, { "content-type": "application/json" });
      return res.end(JSON.stringify({ chain }));
    }
    res.writeHead(404); res.end("{}");
  });

  const gateways = new GatewayPool({ seeds: [broken.url, good.url] });
  await gateways.refresh();
  const sites = new SiteLookup({ registryBase: registry.url });
  const certs = new CertStore({ dir: join(dir, "certs"), registryBase: registry.url, apiKey: "edge-key" });
  const edge = await startEdge({ sites, gateways, certs, host: "127.0.0.1", httpsPort: 0, httpPort: 0 });
  const port = (edge.https.address() as AddressInfo).port;
  t.after(async () => {
    await edge.close();
    for (const s of [broken.server, good.server, registry.server]) s.close();
  });

  await t.test("serves the site, mapping the path under /s/<site>/", async () => {
    const r = await get(port, "blue.eggs", "/about.html", { ca: ca.pem });
    assert.equal(r.status, 200);
    assert.equal(r.text, `<h1>site ${SITE} at /about.html</h1>`);
    assert.equal(r.headers.etag, '"v1"');
    assert.equal(r.headers["set-cookie"], undefined, "only static-site headers pass through");
    assert.equal(r.headers["x-c0mpute-gateway"], new URL(good.url).host);
  });

  await t.test("asks the CA once, then serves the leaf from disk and memory", async () => {
    await get(port, "blue.eggs", "/", { ca: ca.pem });
    await get(port, "blue.eggs", "/x", { ca: ca.pem });
    assert.deepEqual(issued, ["blue"]);
    const onDisk = await readFile(join(dir, "certs", "blue.eggs.crt"), "utf8");
    assert.match(onDisk, /BEGIN CERTIFICATE/);
  });

  await t.test("fails over past a broken gateway every time", async () => {
    for (let i = 0; i < 4; i++) {
      const r = await get(port, "blue.eggs", `/p${i}`, { ca: ca.pem });
      assert.equal(r.status, 200, `request ${i}`);
    }
  });

  await t.test("a name that is not a c0mpute site gets no certificate at all", async () => {
    await assert.rejects(get(port, "red.eggs", "/", { ca: ca.pem }));
    assert.deepEqual(issued, ["blue"], "and the CA was never asked");
  });

  await t.test("a Host that disagrees with the SNI is refused", async () => {
    const r = await get(port, "blue.eggs", "/", { ca: ca.pem, host: "red.eggs" });
    assert.equal(r.status, 421);
  });
});

test("plain http serves the same sites, GET and HEAD only, stale then 503 when no gateway answers", async (t) => {
  const sites = { site: async (name: string) => (name === "blue.eggs" ? SITE : null) };
  let failures = 0;
  const gateways = { pick: () => ["http://g1:7777", "http://g2:7777"], succeeded: () => {}, failed: () => { failures++; } };
  let up = true;
  const slept: number[] = [];
  const handler = createEdgeHandler({
    sites,
    gateways,
    sleep: async (ms) => { slept.push(ms); },
    fetchImpl: (async (input: string | URL | Request) => {
      if (!up) throw new Error("ECONNREFUSED");
      if (String(input).startsWith("http://g1")) return new Response("bad", { status: 502 });
      return new Response("hello", { status: 200, headers: { "content-type": "text/plain" } });
    }) as typeof fetch,
  });
  const srv = await listen((req, res) => { void handler(req, res); });
  t.after(() => srv.server.close());
  const port = Number(new URL(srv.url).port);
  const call = (method: string, host: string, path = "/") => new Promise<{ status: number; text: string; stale?: string }>((resolve, reject) => {
    const req = httpRequest({ host: "127.0.0.1", port, method, path, headers: { host } }, (res) => {
      let text = ""; res.on("data", (d) => { text += d; }); res.on("end", () => resolve({ status: res.statusCode ?? 0, text, ...(res.headers["x-c0mpute-stale"] ? { stale: String(res.headers["x-c0mpute-stale"]) } : {}) }));
    });
    req.on("error", reject); req.end();
  });

  assert.deepEqual(await call("GET", "blue.eggs"), { status: 200, text: "hello" });
  assert.equal(failures, 1, "g1's 502 counted against it");
  assert.equal((await call("HEAD", "blue.eggs")).text, "");
  assert.equal((await call("POST", "blue.eggs")).status, 405);
  assert.equal((await call("GET", "red.eggs")).status, 421, "not a c0mpute name: misdirected, not a missing page");
  assert.equal((await call("GET", "127.0.0.1")).status, 400);
  up = false;
  assert.deepEqual(await call("GET", "blue.eggs"), { status: 200, text: "hello", stale: "1" }, "the last good copy, marked stale");
  assert.deepEqual(slept, [500, 500, 1000, 1500], "retried on a Fibonacci schedule first");
  const miss = await call("GET", "blue.eggs", "/never-seen");
  assert.equal(miss.status, 503, "nothing kept: a graceful 503, not a bare 502");
  assert.match(miss.text, /back in a moment/);
});

test("a gateway that comes back mid-retry serves the request", async () => {
  let calls = 0;
  const handler = createEdgeHandler({
    sites: { site: async () => SITE },
    gateways: { pick: () => ["http://g1:7777"], succeeded: () => {}, failed: () => {} },
    sleep: async () => {},
    fetchImpl: (async () => {
      calls++;
      if (calls < 3) throw new Error("ECONNREFUSED");
      return new Response("back", { status: 200 });
    }) as typeof fetch,
  });
  const srv = await listen((req, res) => { void handler(req, res); });
  const port = Number(new URL(srv.url).port);
  const status = await new Promise<number>((resolve, reject) => {
    const req = httpRequest({ host: "127.0.0.1", port, path: "/", headers: { host: "blue.eggs" } }, (res) => { res.resume(); res.on("end", () => resolve(res.statusCode ?? 0)); });
    req.on("error", reject); req.end();
  });
  srv.server.close();
  assert.equal(status, 200);
  assert.equal(calls, 3);
});

test("fibonacci delays and the LRU of last good pages", () => {
  assert.deepEqual(fibonacciDelays(7, 100), [100, 100, 200, 300, 500, 800, 1300]);
  assert.deepEqual(fibonacciDelays(4, 5000, 9000), [5000, 5000, 9000, 9000]);
  assert.equal(fibonacciDelay(5, 5000, 300_000), 25_000);
  const lg = new LastGood({ maxEntryBytes: 4, maxBytes: 6 });
  lg.put("a", 200, {}, Buffer.from("aaa"));
  lg.put("b", 200, {}, Buffer.from("bbb"));
  lg.put("big", 200, {}, Buffer.from("too big"));
  assert.equal(lg.get("big"), null, "over the per-page cap: not kept");
  lg.get("a");
  lg.put("c", 200, {}, Buffer.from("ccc"));
  assert.equal(lg.get("b"), null, "least recently used went first");
  assert.ok(lg.get("a") && lg.get("c"));
});
