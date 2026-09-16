// The registry-signed path of setup-origin.sh, and the renewal script, without
// root, nginx or the network: a dry run says what it would ask the registry,
// --self-signed keeps the old behaviour, and moshpit-renew.sh only touches
// certificates the registry signed and only when they are about to run out.
import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { tempDir } from "./helpers.ts";

const run = promisify(execFile);
const setup = fileURLToPath(new URL("../scripts/setup-origin.sh", import.meta.url));
const renew = fileURLToPath(new URL("../scripts/moshpit-renew.sh", import.meta.url));

async function sh(script: string, args: string[], env: NodeJS.ProcessEnv = {}) {
  try {
    const { stdout, stderr } = await run("sh", [script, ...args], { env: { ...process.env, ...env } });
    return { code: 0, stdout, stderr };
  } catch (err: any) {
    return { code: err.code ?? 1, stdout: String(err.stdout || ""), stderr: String(err.stderr || "") };
  }
}

/** A certificate issued by `issuerCn` for `name` (self-signed when they match). */
async function cert(dir: string, name: string, { days = 30, issuerCn = name } = {}) {
  const key = join(dir, `${name}.key`);
  const crt = join(dir, `${name}.crt`);
  if (issuerCn === name) {
    await run("openssl", ["req", "-x509", "-new", "-nodes", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
      "-sha256", "-days", String(days), "-subj", `/CN=${name}`, "-keyout", key, "-out", crt]);
    return;
  }
  const caKey = join(dir, "issuer.key");
  const caCrt = join(dir, "issuer.crt");
  await run("openssl", ["req", "-x509", "-new", "-nodes", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
    "-sha256", "-days", "3650", "-subj", `/CN=${issuerCn}`, "-keyout", caKey, "-out", caCrt]);
  const csr = join(dir, `${name}.csr`);
  await run("openssl", ["req", "-new", "-nodes", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
    "-subj", `/CN=${name}`, "-keyout", key, "-out", csr]);
  await run("openssl", ["x509", "-req", "-in", csr, "-CA", caCrt, "-CAkey", caKey, "-CAcreateserial", "-days", String(days), "-out", crt]);
}

describe("setup-origin.sh — the registry-signed path", () => {
  test("a dry run with an API key says it would ask the registry to sign, and where", async () => {
    const r = await sh(setup, ["blue.eggs", "--dry-run", "--api-key", "k", "--registry", "https://registry.test"]);
    assert.equal(r.code, 0, r.stderr);
    assert.match(r.stderr + r.stdout, /asking the registry to sign blue\.eggs/);
    assert.match(r.stderr + r.stdout, /https:\/\/registry\.test\/api\/moshpit\/tlds\/eggs\/certs/);
  });

  test("--self-signed skips the registry even with a key", async () => {
    const r = await sh(setup, ["blue.eggs", "--dry-run", "--api-key", "k", "--self-signed"]);
    assert.equal(r.code, 0, r.stderr);
    assert.doesNotMatch(r.stderr + r.stdout, /asking the registry to sign/);
  });

  test("without a key nothing is asked of the registry, as before", async () => {
    const r = await sh(setup, ["blue.eggs", "--dry-run"]);
    assert.equal(r.code, 0, r.stderr);
    assert.doesNotMatch(r.stderr + r.stdout, /asking the registry to sign/);
  });
});

describe("moshpit-renew.sh", () => {
  test("says so and exits 0 when this box was never signed by the registry", async () => {
    const dir = await tempDir();
    const r = await sh(renew, [], { MOSHPIT_RENEW_ENV: join(dir, "absent.env") });
    assert.equal(r.code, 0);
    assert.match(r.stdout, /nothing here was signed by the registry/);
  });

  test("leaves self-signed and still-valid certificates alone, renews the one about to expire", async () => {
    const dir = await tempDir();
    const certdir = join(dir, "certs");
    await mkdir(certdir);
    await cert(certdir, "self.eggs");                              // self-signed: never touched
    await cert(certdir, "fresh.eggs", { days: 25, issuerCn: "Moshpit Issuing CA" });   // signed, fine
    await cert(certdir, "soon.eggs", { days: 3, issuerCn: "Moshpit Issuing CA" });     // signed, about to expire
    await writeFile(join(dir, "renew.env"), `MOSHPIT_API_KEY=k\nMOSHPIT_REGISTRY=https://registry.test\nMOSHPIT_CERTDIR=${certdir}\n`);
    // A stand-in for setup-origin.sh that records what it was asked to renew.
    const fake = join(dir, "fake-setup.sh");
    await writeFile(fake, `#!/bin/sh\necho "$1" >> "${join(dir, "renewed.txt")}"\n`);
    const r = await sh(renew, [], { MOSHPIT_RENEW_ENV: join(dir, "renew.env"), MOSHPIT_SETUP_ORIGIN: fake });
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /fresh\.eggs — fine/);
    assert.match(r.stdout, /soon\.eggs — renewing/);
    assert.doesNotMatch(r.stdout, /self\.eggs/);
    assert.equal((await readFile(join(dir, "renewed.txt"), "utf8")).trim(), "soon.eggs");
    assert.match(r.stdout, /1 renewed, 0 failed/);
  });
});
