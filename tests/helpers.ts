// Shared fixtures: real certificates from real openssl, not stubs.
//
// The thing under test is "do we agree with openssl about what a key is", so a
// hand-built fake certificate would test the fake.

import { execFile } from "node:child_process";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { promisify } from "node:util";

const run = promisify(execFile);

export async function tempDir(prefix = "moshpit-test-"): Promise<string> {
  return mkdtemp(join(tmpdir(), prefix));
}

/** A self-signed leaf, standing in for an origin that answers for `name`. */
export async function selfSigned(dir: string, name: string): Promise<{
  certPath: string;
  keyPath: string;
  cert: string;
  key: string;
}> {
  const certPath = join(dir, `${name}.crt`);
  const keyPath = join(dir, `${name}.key`);
  const cnf = join(dir, `${name}.cnf`);

  await writeFile(cnf, `[ req ]
distinguished_name = dn
x509_extensions    = v3
prompt             = no

[ dn ]
CN = ${name}

[ v3 ]
basicConstraints = critical, CA:FALSE
keyUsage         = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName   = DNS:${name}
`);

  await run("openssl", [
    "req", "-x509", "-new", "-nodes",
    "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
    "-sha256", "-days", "30",
    "-keyout", keyPath, "-out", certPath,
    "-config", cnf, "-extensions", "v3",
  ]);

  return {
    certPath, keyPath,
    cert: await readFile(certPath, "utf8"),
    key: await readFile(keyPath, "utf8"),
  };
}

/**
 * The pin as openssl computes it, via the documented RFC 7469 pipeline.
 * Our implementation has to match this exactly or the published pins are wrong.
 */
export async function opensslPin(certPath: string): Promise<string> {
  // A shell pipeline rather than three execFile calls, because execFile has no
  // way to feed stdin and the intermediate values are binary.
  const { stdout } = await run("sh", ["-c",
    `openssl x509 -in "${certPath}" -pubkey -noout` +
    ` | openssl pkey -pubin -outform der` +
    ` | openssl dgst -sha256 -binary` +
    ` | base64 | tr -d '\\n'`,
  ]);
  return stdout.trim();
}
