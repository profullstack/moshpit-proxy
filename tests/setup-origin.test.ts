// What `setup-origin.sh` issues, and what it refuses to do.
//
// The script needs root and a running nginx to do its real job, so what is
// exercised here is the part that has to be right regardless: the shape of the
// certificate it mints, and the argument handling that runs before anything is
// written. Both are reachable without privileges — the validation runs before
// the root check, and the certificate flags are read out of the script itself
// and handed to the same openssl the script would call.

import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { opensslPin, tempDir } from "./helpers.ts";

const run = promisify(execFile);
const script = fileURLToPath(new URL("../scripts/setup-origin.sh", import.meta.url));

/** Run the script, returning its exit code and stderr rather than throwing. */
async function sh(args: string[], env: NodeJS.ProcessEnv = {}) {
  try {
    const { stdout, stderr } = await run("sh", [script, ...args], { env: { ...process.env, ...env } });
    return { code: 0, stdout, stderr };
  } catch (err: any) {
    return { code: err.code ?? 1, stdout: String(err.stdout || ""), stderr: String(err.stderr || "") };
  }
}

/**
 * The certificate extensions the script passes to openssl, read out of the
 * script rather than restated here.
 *
 * Restating them would produce a test that passes while the script mints
 * something else entirely — which is exactly the failure this file exists to
 * catch, since a CA:TRUE certificate is indistinguishable from a correct one
 * until someone trusts it.
 */
async function leafExtensions(): Promise<string[]> {
  const body = await readFile(script, "utf8");
  const flags = ["LEAF_EXT", "LEAF_USE", "LEAF_EKU"].map((name) => {
    const found = new RegExp(`^${name}='([^']+)'`, "m").exec(body);
    assert.ok(found, `${name} is no longer set in setup-origin.sh`);
    return found[1];
  });
  return flags.flatMap((ext) => ["-addext", ext]);
}

describe("setup-origin.sh — what it issues", () => {
  test("the certificate is not a CA, and says so critically", async () => {
    const dir = await tempDir();
    const crt = join(dir, "cert.pem");
    const key = join(dir, "key.pem");

    await run("openssl", [
      "req", "-x509", "-new", "-nodes",
      "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
      "-sha256", "-days", "30",
      "-subj", "/CN=chovy.hacker", "-addext", "subjectAltName=DNS:chovy.hacker",
      ...(await leafExtensions()),
      "-keyout", key, "-out", crt,
    ]);

    const { stdout } = await run("openssl", ["x509", "-in", crt, "-noout", "-text"]);

    // The property the whole thing turns on. This certificate is trusted
    // directly — it is its own anchor — and an anchor marked CA:TRUE may issue
    // for any name at all. The SAN bounds what it speaks for; it does not bound
    // what a key trusted as a CA can go on to sign.
    assert.match(stdout, /X509v3 Basic Constraints: critical\s*\n\s*CA:FALSE/);
    assert.doesNotMatch(stdout, /CA:TRUE/);

    // One name, so trusting it is a grant over one name.
    const sans = /X509v3 Subject Alternative Name:\s*\n\s*(.+)/.exec(stdout)?.[1] ?? "";
    assert.equal(sans.trim(), "DNS:chovy.hacker");
    assert.match(stdout, /TLS Web Server Authentication/);
  });

  test("it verifies as its own anchor, which is how a stock client accepts it", async () => {
    const dir = await tempDir();
    const crt = join(dir, "cert.pem");
    const key = join(dir, "key.pem");

    await run("openssl", [
      "req", "-x509", "-new", "-nodes",
      "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
      "-sha256", "-days", "30",
      "-subj", "/CN=seo.rank", "-addext", "subjectAltName=DNS:seo.rank",
      ...(await leafExtensions()),
      "-keyout", key, "-out", crt,
    ]);

    // CA:FALSE and "usable as a trust anchor" sound contradictory and are not:
    // a certificate found in the trust store is trusted as itself, and the
    // basicConstraints CA bit only governs whether it may certify *others*.
    // If this ever stopped holding, the local trust step would install a file
    // that changes nothing and report success.
    const { stdout } = await run("openssl", ["verify", "-CAfile", crt, crt]);
    assert.match(stdout, /OK/);
  });

  test("re-issuing from the same key does not move the pin", async () => {
    const dir = await tempDir();
    const key = join(dir, "key.pem");
    const first = join(dir, "first.pem");
    const second = join(dir, "second.pem");
    const ext = await leafExtensions();

    await run("openssl", [
      "req", "-x509", "-new", "-nodes",
      "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
      "-sha256", "-days", "30",
      "-subj", "/CN=alt.2600", "-addext", "subjectAltName=DNS:alt.2600",
      ...ext, "-keyout", key, "-out", first,
    ]);
    await run("openssl", [
      "req", "-x509", "-new", "-nodes", "-key", key,
      "-sha256", "-days", "60",
      "-subj", "/CN=alt.2600", "-addext", "subjectAltName=DNS:alt.2600",
      ...ext, "-out", second,
    ]);

    // This is what makes repairing an already-published CA:TRUE certificate
    // free: the pin is over the key, so re-issuing needs no registry change and
    // no flag day. Without it, fixing the certificate would break every client
    // holding the old pin.
    assert.equal(await opensslPin(second), await opensslPin(first));
  });
});

describe("setup-origin.sh — what it refuses", () => {
  test("a name that would escape the directories it writes to", async () => {
    // The name becomes a path under /etc/ssl, /etc/nginx and
    // /usr/local/share/ca-certificates, and the script runs as root.
    for (const bad of ["../../etc/evil.hacker", "a.b/../../x", "..hacker"]) {
      const { code, stderr } = await sh([bad, "--dry-run"]);
      assert.equal(code, 1, `${bad} was accepted`);
      assert.match(stderr, /is not a hostname/);
    }
  });

  test("a name with no dot in it", async () => {
    const { code, stderr } = await sh(["hacker", "--dry-run"]);
    assert.equal(code, 1);
    assert.match(stderr, /does not look like a Moshpit name/);
  });

  test("--all given after the name, where it would be silently ignored", async () => {
    const { code, stderr } = await sh(["good.hacker", "--all", "--dry-run"]);
    assert.equal(code, 1);
    assert.match(stderr, /--all goes first/);
  });

  test("--all with nothing to re-issue, rather than reporting success", async () => {
    const dir = await tempDir();
    const { code, stderr } = await sh(["--all", "--dry-run"], { MOSHPIT_CERTDIR: dir });
    assert.equal(code, 1);
    assert.match(stderr, /nothing to re-issue/);
  });
});

describe("setup-origin.sh — --all", () => {
  test("re-issues every name the box already has a key for", async () => {
    const dir = await tempDir();
    await run("sh", ["-c", `: > "${dir}/one.hacker.key"; : > "${dir}/two.rank.key"`]);

    const { code, stderr } = await sh(["--all", "--dry-run"], { MOSHPIT_CERTDIR: dir });
    assert.equal(code, 0);
    // Named from the keys on disk, so repairing a fleet is one command and
    // there is nothing to type and mistype.
    assert.match(stderr, /==> one\.hacker/);
    assert.match(stderr, /==> two\.rank/);
  });
});
