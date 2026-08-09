// The repair trigger a pin comparison cannot see.
//
// `moshpit-reconcile.sh` re-runs setup-origin.sh when a name's nginx block is
// missing or the served key is not the published one. Neither fires for the
// case that actually left every stock client refusing these names: a
// certificate marked CA:TRUE. It is the right key — the pin matches — and it is
// unusable, because an anchor marked CA:TRUE may issue for any name and so
// cannot be trusted directly.
//
// The repair reuses the key, so the pin does not move. That is what makes it
// free, and exactly why the existing checks stay silent: a box pulls the fix
// and then reconciles contentedly forever without applying it.
//
// The function is lifted out of the script and run against a real TLS server,
// rather than restated here — a restated pipeline would pass while the script
// probed something else entirely.

import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { createServer } from "node:tls";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { tempDir } from "./helpers.ts";

const run = promisify(execFile);
const script = fileURLToPath(new URL("../scripts/moshpit-reconcile.sh", import.meta.url));

/** A self-signed certificate for `name`, as a CA or as a plain leaf. */
async function certificate(dir: string, name: string, { ca }: { ca: boolean }) {
  const certPath = join(dir, `${name}-${ca}.crt`);
  const keyPath = join(dir, `${name}-${ca}.key`);
  await run("openssl", [
    "req", "-x509", "-new", "-nodes",
    "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
    "-sha256", "-days", "1", "-subj", `/CN=${name}`,
    "-addext", `subjectAltName=DNS:${name}`,
    "-addext", `basicConstraints=critical,CA:${ca ? "TRUE" : "FALSE"}`,
    "-keyout", keyPath, "-out", certPath,
  ]);
  return { cert: await readFile(certPath), key: await readFile(keyPath) };
}

/**
 * Serve a certificate on an ephemeral loopback port for the duration of a test.
 *
 * The socket is destroyed rather than ended, and every connection is dropped
 * before close. `openssl s_client` does not hang up when the server half-closes
 * — it waits for a close_notify it is never sent — so `server.close()` sits
 * waiting for a connection that is waiting for it, and the test run hangs with
 * no failure and no output.
 */
async function origin(t: any, creds: { cert: Buffer; key: Buffer }) {
  const server = createServer({ cert: creds.cert, key: creds.key }, (socket) => socket.destroy());
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  t.after(() => new Promise<void>((resolve) => {
    server.closeAllConnections?.();
    server.close(() => resolve());
  }));
  return `127.0.0.1:${(server.address() as { port: number }).port}`;
}

/**
 * Run the script's own `served_is_ca` against an address.
 *
 * Extracted from the file so the test cannot drift from what runs in
 * production: if the probe changes, this runs the changed one.
 */
async function servedIsCa(addr: string, name: string): Promise<boolean> {
  const body = await readFile(script, "utf8");
  const fn = /^served_is_ca\(\) \{\n[\s\S]*?^\}/m.exec(body);
  assert.ok(fn, "served_is_ca is no longer defined in moshpit-reconcile.sh");

  const dir = await tempDir("reconcile-probe-");
  const runner = join(dir, "probe.sh");
  await writeFile(runner, `#!/bin/sh\nset -eu\nORIGIN_ADDR="$1"\n${fn[0]}\nserved_is_ca "$2"\n`);

  try {
    await run("sh", [runner, addr, name]);
    return true;
  } catch {
    return false;   // grep -q found no CA:TRUE, so the function exited non-zero
  }
}

describe("reconcile — the CA:TRUE repair trigger", () => {
  test("a certificate marked CA:TRUE is spotted", async (t) => {
    const dir = await tempDir();
    const addr = await origin(t, await certificate(dir, "chovy.hacker", { ca: true }));
    assert.equal(await servedIsCa(addr, "chovy.hacker"), true);
  });

  test("the certificate the fix issues is not", async (t) => {
    // The other half: if this said yes, reconcile would re-issue on every pass
    // and reload nginx once a minute forever — the failure the script's own
    // header warns about.
    const dir = await tempDir();
    const addr = await origin(t, await certificate(dir, "chovy.hacker", { ca: false }));
    assert.equal(await servedIsCa(addr, "chovy.hacker"), false);
  });

  test("nothing listening is not a CA, so an unreachable origin is not re-issued forever", async () => {
    // Port 1 on loopback: reserved, never bound. A probe that cannot connect
    // must not report the dangerous shape — "no answer" is already covered by
    // the served-pin check above it, which produces a better message.
    assert.equal(await servedIsCa("127.0.0.1:1", "chovy.hacker"), false);
  });
});

describe("reconcile — the trigger is actually wired in", () => {
  test("served_is_ca is consulted in the decision chain, not merely defined", async () => {
    // A helper nothing calls is the most plausible way this regresses: the
    // tests above would still pass with the elif deleted.
    const body = await readFile(script, "utf8");
    assert.match(body, /elif served_is_ca "\$name"; then/);
    assert.match(body, /need="the certificate it serves is marked CA:TRUE/);
  });

  test("the probe address is what both certificate checks use", async () => {
    const body = await readFile(script, "utf8");
    // Hardcoding 127.0.0.1:443 back into either probe would make them
    // untestable and silently un-run here.
    assert.doesNotMatch(body, /-connect "127\.0\.0\.1:443"/);
    assert.equal((body.match(/-connect "\$ORIGIN_ADDR"/g) || []).length, 2);
  });
});
