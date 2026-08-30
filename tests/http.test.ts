// Port 80, and what decides whether a name belongs to Moshpit at all.
//
// Proxy mode points names at loopback, so a browser reaches 80 or 443 and
// nothing can be arranged in between. Taking only 443 meant `http://` on every
// Moshpit name answered with whatever web server the machine already ran — on a
// desktop, nginx's welcome page, for a name that resolved perfectly.
import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:net";
import { connect } from "node:net";

import { hostFromHead, createHttpProxy } from "../lib/http.ts";
import { namespaceTest } from "../lib/proxy.ts";

/* ------------------------------------------------------------ the namespace */

test("the namespace is everything IANA does not delegate", () => {
  const serves = namespaceTest([]);
  // No configuration, and every ending works — including ones sold after this
  // build shipped, which a list could never cover.
  assert.equal(serves("chovy.hacker"), true);
  assert.equal(serves("alt.2600"), true);
  assert.equal(serves("blue.eggs"), true);
  assert.equal(serves("anything.soldtomorrow"), true);
});

test("real domains are not ours, however they are spelled", () => {
  const serves = namespaceTest([]);
  for (const real of ["google.com", "www.moshcode.sh", "a.b.co.uk", "GOOGLE.COM", "google.com."]) {
    assert.equal(serves(real), false, `${real} belongs to the internet`);
  }
});

test("a name with no ending is nobody's", () => {
  const serves = namespaceTest([]);
  assert.equal(serves("localhost"), false);
  assert.equal(serves(""), false);
});

test("an explicit list still narrows, for a deployment that wants only part", () => {
  const serves = namespaceTest(["hacker"]);
  assert.equal(serves("chovy.hacker"), true);
  assert.equal(serves("alt.2600"), false, "named endings are a whitelist, not an addition");
});

/* --------------------------------------------------------------- Host: parsing */

test("the Host header is read, and its port is ours not the origin's", () => {
  assert.equal(hostFromHead("GET / HTTP/1.1\r\nHost: chovy.hacker\r\n\r\n"), "chovy.hacker");
  assert.equal(hostFromHead("GET / HTTP/1.1\r\nHost: chovy.hacker:80\r\n\r\n"), "chovy.hacker");
  assert.equal(hostFromHead("GET / HTTP/1.1\r\nhost:  CHOVY.HACKER \r\n\r\n"), "chovy.hacker");
  assert.equal(hostFromHead("GET / HTTP/1.1\r\nHost: [::1]:80\r\n\r\n"), "::1");
});

test("a head with no Host yields nothing to forward under", () => {
  assert.equal(hostFromHead("GET / HTTP/1.0\r\n\r\n"), null);
  assert.equal(hostFromHead(""), null);
});

/* ------------------------------------------------------------ forwarding */

test("a Moshpit name is forwarded to its origin, bytes intact", async () => {
  // Stands in for the origin. The proxy must replay the request head it had to
  // read in order to find the Host, or the origin sees a truncated request.
  let seen = "";
  const origin = createServer((socket) => {
    socket.on("data", (chunk) => {
      seen += chunk.toString();
      if (seen.includes("\r\n\r\n")) socket.end("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi");
    });
  });
  await new Promise<void>((r) => origin.listen(0, "127.0.0.1", () => r()));
  const originPort = (origin.address() as { port: number }).port;

  const proxy = createHttpProxy({
    pins: { async lookup() { return { target: `127.0.0.1:${originPort}` }; } },
    gatewayHost: "127.0.0.1",
    listenHost: "127.0.0.1",
    listenPort: 0,
    inNamespace: namespaceTest([]),
  });
  const port = await proxy.listen();

  const body = await new Promise<string>((resolve) => {
    const client = connect({ host: "127.0.0.1", port }, () => {
      client.write("GET /page HTTP/1.1\r\nHost: chovy.hacker\r\nX-Kept: yes\r\n\r\n");
    });
    let got = "";
    client.on("data", (c) => { got += c.toString(); if (got.includes("hi")) { client.end(); resolve(got); } });
  });

  assert.match(body, /200 OK/);
  assert.match(seen, /GET \/page HTTP\/1\.1/, "the request line survives the peek");
  assert.match(seen, /X-Kept: yes/, "headers read while looking for Host are replayed, not eaten");

  await proxy.close();
  await new Promise<void>((r) => origin.close(() => r()));
});

test("a real domain is refused rather than proxied", async () => {
  // The proxy holds port 80 on the machine. Forwarding anything asked of it
  // would make it an open relay for the whole internet.
  const proxy = createHttpProxy({
    pins: { async lookup() { return null; } },
    gatewayHost: "127.0.0.1",
    listenHost: "127.0.0.1",
    listenPort: 0,
    inNamespace: namespaceTest([]),
  });
  const port = await proxy.listen();

  const reply = await new Promise<string>((resolve) => {
    const client = connect({ host: "127.0.0.1", port }, () => {
      client.write("GET / HTTP/1.1\r\nHost: google.com\r\n\r\n");
    });
    let got = "";
    client.on("data", (c) => { got += c.toString(); });
    client.on("end", () => resolve(got));
  });

  assert.match(reply, /421/);
  assert.equal(proxy.stats().refused, 1);
  await proxy.close();
});
