import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import { createLocalCa } from "../lib/ca.ts";
import { tempDir } from "./helpers.ts";

const run = promisify(execFile);

describe("local CA", () => {
  test("root is constrained to the Moshpit namespace", async () => {
    const dir = await tempDir();
    const ca = createLocalCa({ dir, tlds: ["moshpit", "whatever"] });
    await ca.ensure();

    const { stdout } = await run("openssl", ["x509", "-in", ca.rootCertPath(), "-text", "-noout"]);

    // The constraint is the entire reason installing this root is a reasonable
    // thing to ask of someone. If it silently stopped being emitted, the whole
    // security story would change and nothing else would fail.
    assert.match(stdout, /X509v3 Name Constraints: critical/);
    assert.match(stdout, /DNS:\.moshpit/);
    assert.match(stdout, /DNS:\.whatever/);
    assert.match(stdout, /Excluded/);
    assert.match(stdout, /CA:TRUE/);
  });

  test("the root cannot certify a name outside the namespace", async () => {
    const dir = await tempDir();
    const ca = createLocalCa({ dir, tlds: ["moshpit"] });
    const leaf = await ca.certFor("evil.moshpit");

    // Rewrite the leaf to claim a clearnet name and check that verification
    // against this root rejects it. This is the property that makes the root
    // safe to install: holding the key is not enough to forge google.com.
    const forgedPath = join(dir, "forged.crt");
    const ext = join(dir, "forged.cnf");
    await writeFile(ext, [
      "basicConstraints = critical, CA:FALSE",
      "keyUsage = critical, digitalSignature",
      "extendedKeyUsage = serverAuth",
      "subjectAltName = DNS:www.google.com",
      "",
    ].join("\n"));
    await writeFile(join(dir, "forged.cnf.req"), "[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=www.google.com\n");
    await run("openssl", [
      "req", "-new", "-key", join(dir, "leaf.key"),
      "-out", join(dir, "forged.csr"), "-config", join(dir, "forged.cnf.req"),
    ]);
    await run("openssl", [
      "x509", "-req", "-in", join(dir, "forged.csr"),
      "-CA", ca.rootCertPath(), "-CAkey", join(dir, "ca.key"),
      "-CAcreateserial", "-days", "30", "-sha256",
      "-extfile", ext, "-out", forgedPath,
    ]);

    // openssl's wording for this is "permitted subtree violation" (error 47).
    await assert.rejects(
      run("openssl", ["verify", "-CAfile", ca.rootCertPath(), forgedPath]),
      /permitted subtree violation|excluded|name constraint/i,
    );
    assert.ok(leaf.cert.includes("BEGIN CERTIFICATE"));
  });

  test("mints a leaf that chains to the root and names the host in a SAN", async () => {
    const dir = await tempDir();
    const ca = createLocalCa({ dir, tlds: ["moshpit"] });

    const leaf = await ca.certFor("site.moshpit");
    const parsed = new X509Certificate(leaf.cert);

    assert.match(String(parsed.subjectAltName), /DNS:site\.moshpit/);
    assert.equal(parsed.checkHost("site.moshpit"), "site.moshpit");
    assert.match(leaf.key, /PRIVATE KEY/);

    const leafPath = join(dir, "verify-leaf.crt");
    await writeFile(leafPath, leaf.cert);
    const { stdout } = await run("openssl", ["verify", "-CAfile", ca.rootCertPath(), leafPath]);
    assert.match(stdout, /OK/);
  });

  test("multi-label names work, which a wildcard could not do", async () => {
    const dir = await tempDir();
    const ca = createLocalCa({ dir, tlds: ["moshpit"] });

    // `*.moshpit` is a wildcard directly beneath a TLD and is rejected by
    // every TLS stack, the same rule that makes `*.com` invalid. Minting per
    // name is what makes `deep.site.moshpit` reachable at all.
    const leaf = await ca.certFor("deep.site.moshpit");
    assert.equal(new X509Certificate(leaf.cert).checkHost("deep.site.moshpit"), "deep.site.moshpit");
  });

  test("a second request for the same name reuses the certificate", async () => {
    const dir = await tempDir();
    const ca = createLocalCa({ dir, tlds: ["moshpit"] });

    const first = await ca.certFor("stable.moshpit");
    const second = await ca.certFor("stable.moshpit");

    assert.equal(second.cert, first.cert);
  });

  test("concurrent first use does not race two roots into existence", async () => {
    const dir = await tempDir();
    const ca = createLocalCa({ dir, tlds: ["moshpit"] });

    const names = ["a.moshpit", "b.moshpit", "c.moshpit", "d.moshpit"];
    const leaves = await Promise.all(names.map((n) => ca.certFor(n)));

    // Every leaf must verify against the one root that ended up on disk.
    for (const [index, leaf] of leaves.entries()) {
      const path = join(dir, `concurrent-${index}.crt`);
      await writeFile(path, leaf.cert);
      const { stdout } = await run("openssl", ["verify", "-CAfile", ca.rootCertPath(), path]);
      assert.match(stdout, /OK/);
    }
  });

  test("fingerprint is stable and printable for the trust step", async () => {
    const dir = await tempDir();
    const ca = createLocalCa({ dir, tlds: ["moshpit"] });
    await ca.ensure();

    const fingerprint = await ca.fingerprint();
    assert.match(fingerprint, /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
    assert.equal(await ca.fingerprint(), fingerprint);
  });
});
