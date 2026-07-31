// The local certificate authority, whose only job is to satisfy the browser.
//
// A browser will not speak to a name it cannot verify, and it has no way to
// check a registry pin — there is no extension API for certificate validation,
// in any browser. So something on this machine has to terminate TLS, do the
// real verification against the registry, and re-present the result in the one
// language the browser accepts. That is a certificate, which means a CA.
//
// Two things make this a much smaller ask than the shared root a public CA
// would need:
//
//   1. The key is generated here and never leaves. Nobody — including whoever
//      runs the registry — can use it against anyone else. Compromising the
//      Moshpit project's infrastructure does not forge certificates for you.
//   2. It carries a critical nameConstraints extension permitting only the
//      Moshpit TLDs and excluding every other name form. Even holding this key,
//      the worst reachable outcome is forging a name you already control. It
//      cannot mint google.com. That constraint is enforced by OpenSSL 1.1+,
//      NSS, Go, macOS and Windows, which between them cover the clients that
//      matter here.
//
// Certificates are built by shelling out to openssl rather than by assembling
// ASN.1 in TypeScript. There is no X.509 *creation* API in node:crypto, and a
// hand-rolled DER encoder is a bad thing to get subtly wrong in the one
// component whose whole purpose is being correct about certificates.

import { execFile } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { promisify } from "node:util";

const run = promisify(execFile);

export type Leaf = { cert: string; key: string };

export type LocalCa = {
  /** Creates the root if it is missing. Safe to call repeatedly. */
  ensure(): Promise<void>;
  /** A certificate for `name`, minted on first use and cached after. */
  certFor(name: string): Promise<Leaf>;
  rootCertPath(): string;
  rootCertPem(): Promise<string>;
  fingerprint(): Promise<string>;
};

export function createLocalCa(options: {
  dir: string;
  /** The namespaces this root is permitted to certify. Everything else is excluded. */
  tlds: string[];
  /** Leaf lifetime. Short because renewal is free and local. */
  leafDays?: number;
  rootDays?: number;
  opensslPath?: string;
}): LocalCa {
  const dir = options.dir;
  const leafDays = options.leafDays ?? 90;
  const rootDays = options.rootDays ?? 3650;
  const openssl = options.opensslPath ?? "openssl";
  const tlds = options.tlds.map((t) => t.replace(/^\.+/, "").toLowerCase()).filter(Boolean);

  const caKey = join(dir, "ca.key");
  const caCrt = join(dir, "ca.crt");
  const caSrl = join(dir, "ca.srl");
  const leafKey = join(dir, "leaf.key");
  const leafDir = join(dir, "leaves");

  const memo = new Map<string, Leaf>();
  let ensuring: Promise<void> | null = null;

  async function openssl_(args: string[], cwd?: string) {
    try {
      return await run(openssl, args, { cwd, maxBuffer: 8 * 1024 * 1024 });
    } catch (error) {
      const detail = (error as { stderr?: string })?.stderr ?? String(error);
      throw new Error(`openssl ${args[0]} failed: ${detail.trim()}`);
    }
  }

  async function buildRoot() {
    await mkdir(dir, { recursive: true, mode: 0o700 });
    await mkdir(leafDir, { recursive: true, mode: 0o700 });

    if (!existsSync(caCrt) || !existsSync(caKey)) {
      const cnf = join(dir, "ca.cnf");
      await writeFile(cnf, rootConfig(tlds), { mode: 0o600 });
      await openssl_([
        "req", "-x509", "-new", "-nodes",
        "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
        "-sha256", "-days", String(rootDays),
        "-keyout", caKey, "-out", caCrt,
        "-config", cnf, "-extensions", "v3_ca",
      ]);
      await run("chmod", ["600", caKey]).catch(() => {});
    }

    if (!existsSync(leafKey)) {
      // One key for every leaf. These certificates never leave this machine and
      // are never presented to anyone but the local browser, so per-name key
      // separation would buy nothing and cost a keygen per hostname.
      await openssl_([
        "genpkey", "-algorithm", "EC",
        "-pkeyopt", "ec_paramgen_curve:prime256v1",
        "-out", leafKey,
      ]);
      await run("chmod", ["600", leafKey]).catch(() => {});
    }
  }

  async function mint(name: string): Promise<Leaf> {
    const work = await mkdtemp(join(tmpdir(), "moshpit-leaf-"));
    try {
      const csr = join(work, "leaf.csr");
      const ext = join(work, "leaf.cnf");
      const out = join(work, "leaf.crt");
      const req = join(work, "req.cnf");

      await writeFile(req, reqConfig(name));
      await openssl_(["req", "-new", "-key", leafKey, "-out", csr, "-config", req]);
      await writeFile(ext, leafConfig(name));
      await openssl_([
        "x509", "-req", "-in", csr,
        "-CA", caCrt, "-CAkey", caKey,
        "-CAcreateserial", "-CAserial", caSrl,
        "-days", String(leafDays), "-sha256",
        "-extfile", ext, "-out", out,
      ]);

      const cert = await readFile(out, "utf8");
      const key = await readFile(leafKey, "utf8");
      await writeFile(join(leafDir, `${safeFile(name)}.crt`), cert, { mode: 0o600 });
      return { cert, key };
    } finally {
      await rm(work, { recursive: true, force: true });
    }
  }

  /** A cached leaf is reused only while it has real life left, not until it expires. */
  async function reuse(name: string): Promise<Leaf | null> {
    const path = join(leafDir, `${safeFile(name)}.crt`);
    if (!existsSync(path)) return null;
    try {
      const cert = await readFile(path, "utf8");
      const parsed = new X509Certificate(cert);
      const expiresAt = Date.parse(parsed.validTo);
      if (!Number.isFinite(expiresAt) || expiresAt - Date.now() < 7 * 86_400_000) return null;
      if (!parsed.checkHost(name)) return null;
      return { cert, key: await readFile(leafKey, "utf8") };
    } catch {
      return null;
    }
  }

  return {
    async ensure() {
      // Coalesced: several SNI callbacks can land before the root exists, and
      // two concurrent `openssl req` runs would race over the same output path.
      if (!ensuring) ensuring = buildRoot().catch((error) => {
        ensuring = null;
        throw error;
      });
      return ensuring;
    },

    async certFor(rawName: string) {
      const name = String(rawName ?? "").trim().toLowerCase().replace(/\.$/, "");
      if (!name) throw new Error("certFor requires a name");

      const cached = memo.get(name);
      if (cached) return cached;

      await this.ensure();
      const existing = await reuse(name);
      const leaf = existing ?? (await mint(name));
      memo.set(name, leaf);
      return leaf;
    },

    rootCertPath: () => caCrt,
    rootCertPem: () => readFile(caCrt, "utf8"),

    async fingerprint() {
      const pem = await readFile(caCrt, "utf8");
      return new X509Certificate(pem).fingerprint256;
    },
  };
}

/**
 * Permitting a DNS subtree implicitly excludes every other DNS name, but says
 * nothing about the other name forms — so IP, email, URI and directory names
 * are excluded explicitly. Without those a permitted-DNS-only root is still
 * able to certify, say, an IP address, which defeats the point.
 */
function rootConfig(tlds: string[]): string {
  const permitted = tlds.map((tld, i) => `permitted;DNS.${i} = .${tld}`).join("\n");
  return `[ req ]
distinguished_name = dn
x509_extensions    = v3_ca
prompt             = no

[ dn ]
CN = Moshpit Local CA
O  = Moshpit (local, this machine only)

[ v3_ca ]
basicConstraints     = critical, CA:TRUE, pathlen:0
keyUsage             = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
nameConstraints      = critical, @nc

[ nc ]
${permitted}
excluded;IP.0    = 0.0.0.0/0.0.0.0
excluded;IP.1    = ::/::
excluded;email.0 = .
excluded;URI.0   = .
excluded;DNS.0   = .invalid
`;
}

function reqConfig(name: string): string {
  return `[ req ]
distinguished_name = dn
prompt             = no

[ dn ]
CN = ${name}
`;
}

function leafConfig(name: string): string {
  // subjectAltName is what every browser actually reads; CN has been ignored
  // for this purpose since Chrome 58.
  return `basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth
subjectAltName         = DNS:${name}
subjectKeyIdentifier   = hash
`;
}

function safeFile(name: string): string {
  return name.replace(/[^a-z0-9._-]/gi, "_");
}
