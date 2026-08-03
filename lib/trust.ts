// Installing the local root, without ever making a person think about roots.
//
// The README used to end with a `certutil -d sql:$HOME/.pki/nssdb -A -t "C,,"`
// incantation and a hope. That is the actual adoption barrier: not that people
// distrust a local CA, but that nobody should have to parse that line to read a
// web page. Certificates cannot be removed from the stock-browser path — no
// extension API can validate a registry pin, which is the whole reason the CA
// exists — but the *step* can be removed, and that is what this file does.
//
// Three things this deliberately does not do:
//
//   - **Install silently.** Adding a root to someone's trust store without
//     telling them is what malware does. There is exactly one consent moment,
//     in plain language, and then never again. What is refused is the jargon,
//     not the disclosure.
//   - **Assume one store.** Chrome and Firefox do not share a trust store on
//     Linux, and Firefox carries its own NSS database on every platform. A
//     "successful" install that only covered Chrome is the failure people
//     actually hit.
//   - **Touch the real store from tests.** Every path and every command runner
//     is injectable, so the suite works against a temporary NSS database and
//     can never modify the machine running it.
//
// Idempotent by construction: `status()` is checked before `install()` writes,
// and installing twice is a no-op rather than a duplicate nickname.

import { execFile } from "node:child_process";
import { copyFileSync, existsSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { homedir, platform as osPlatform } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

/** The nickname the root is filed under. Stable — it is how we find it again. */
export const NICKNAME = "Moshpit Local CA";

export type StoreKind = "nss" | "macos-keychain" | "ca-certificates";

/**
 * Where a Linux distribution wants extra roots dropped, and what refreshes the
 * bundle afterwards. The file is written into `dir`; the command rebuilds
 * /etc/ssl/certs from it.
 *
 * This is the store `curl`, `wget`, `git` and Node read — none of which look at
 * NSS. Covering only browsers meant `curl <name>` failed with a self-signed
 * certificate error on a machine that had been "set up", which reads as the
 * whole scheme being broken rather than as one store having been missed.
 */
export const CA_CERTIFICATES_DIRS: Array<{ dir: string; refresh: string }> = [
  // Debian, Ubuntu and derivatives.
  { dir: "/usr/local/share/ca-certificates", refresh: "update-ca-certificates" },
  // Fedora, RHEL, CentOS, Rocky, Alma.
  { dir: "/etc/pki/ca-trust/source/anchors", refresh: "update-ca-trust" },
  // Arch, and openSUSE via p11-kit.
  { dir: "/etc/ca-certificates/trust-source/anchors", refresh: "update-ca-trust" },
];

export type Store = {
  /** Stable id, used in output and in tests. */
  id: string;
  kind: StoreKind;
  /** NSS database directory, or the keychain path. */
  path: string;
  /** What a person would call the thing this covers. */
  label: string;
  /** Whether writing here needs an administrator password. */
  needsRoot: boolean;
};

export type Runner = (file: string, args: string[]) => Promise<{ stdout: string; stderr: string }>;

export type TrustEnv = {
  platform: string;
  home: string;
  exists: (path: string) => boolean;
  listDir: (path: string) => string[];
  run: Runner;
  /** Empty string when the file cannot be read, so callers never have to catch. */
  readFile: (path: string) => string;
  copyFile: (from: string, to: string) => void;
  removeFile: (path: string) => void;
};

export function defaultEnv(overrides: Partial<TrustEnv> = {}): TrustEnv {
  return {
    platform: osPlatform(),
    home: homedir(),
    exists: existsSync,
    readFile: (path) => {
      try {
        return readFileSync(path, "utf8");
      } catch {
        return "";
      }
    },
    copyFile: (from, to) => copyFileSync(from, to),
    removeFile: (path) => rmSync(path, { force: true }),
    listDir: (path) => {
      try {
        return readdirSync(path);
      } catch {
        return [];
      }
    },
    run: async (file, args) => execFileAsync(file, args, { maxBuffer: 8 * 1024 * 1024 }),
    ...overrides,
  };
}

/**
 * Every trust store on this machine that a browser actually reads.
 *
 * Firefox is the reason this returns a list rather than a path. It ships its
 * own NSS database per profile on every platform, so a macOS install that only
 * touched the keychain leaves Firefox showing a security warning — which the
 * user reasonably reads as "this thing is broken".
 */
export function discoverStores(env: TrustEnv = defaultEnv()): Store[] {
  const stores: Store[] = [];

  if (env.platform === "darwin") {
    stores.push({
      id: "macos-system",
      kind: "macos-keychain",
      path: "/Library/Keychains/System.keychain",
      label: "Safari, Chrome and anything using the system store",
      needsRoot: true,
    });
  } else {
    // Chrome, Chromium and Edge share this one on Linux.
    const nssdb = join(env.home, ".pki", "nssdb");
    if (env.exists(nssdb)) {
      stores.push({
        id: "nss-chrome",
        kind: "nss",
        path: nssdb,
        label: "Chrome, Chromium and Edge",
        needsRoot: false,
      });
    }

    // The system bundle. First match wins: a machine has one of these, and
    // writing a root into a second distribution's directory would leave a file
    // nothing ever reads.
    const anchors = CA_CERTIFICATES_DIRS.find((candidate) => env.exists(candidate.dir));
    if (anchors) {
      stores.push({
        id: "ca-certificates",
        kind: "ca-certificates",
        path: anchors.dir,
        label: "curl, wget, git and anything using the system store",
        needsRoot: true,
      });
    }
  }

  for (const profile of firefoxProfiles(env)) {
    stores.push({
      id: `nss-firefox-${basename(profile)}`,
      kind: "nss",
      path: profile,
      label: `Firefox (${basename(profile)})`,
      needsRoot: false,
    });
  }

  return stores;
}

/**
 * Firefox profile directories holding an NSS database.
 *
 * The snap and flatpak locations are included because on current Ubuntu the
 * default Firefox is the snap, and a tool that silently covers only the
 * non-snap path looks like it worked and did nothing.
 */
function firefoxProfiles(env: TrustEnv): string[] {
  const roots =
    env.platform === "darwin"
      ? [join(env.home, "Library", "Application Support", "Firefox", "Profiles")]
      : [
          join(env.home, ".mozilla", "firefox"),
          join(env.home, "snap", "firefox", "common", ".mozilla", "firefox"),
          join(env.home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox"),
        ];

  const found: string[] = [];
  for (const root of roots) {
    if (!env.exists(root)) continue;
    for (const entry of env.listDir(root)) {
      const dir = join(root, entry);
      // cert9.db is the modern (sql:) NSS database. A profile without one has
      // never been launched, and writing to it would be pointless.
      if (env.exists(join(dir, "cert9.db"))) found.push(dir);
    }
  }
  return found;
}

function basename(path: string): string {
  const parts = path.split("/").filter(Boolean);
  return parts[parts.length - 1] ?? path;
}

export type Tooling = {
  /** Whether `certutil` is on PATH. Nothing NSS works without it. */
  certutil: boolean;
  /** The exact command to get it, for this distribution. */
  installHint: string;
  /** The package name alone, for an installer that offers to run it. */
  packageName: string;
  packageManager: string | null;
};

/**
 * Whether the NSS tooling is present, and precisely how to get it if not.
 *
 * Worth its own function because `certutil` missing is the common case, not the
 * edge case: `libnss3-tools` is not installed by default on Debian or Ubuntu,
 * so the documented command fails on a machine that *does* have the store it
 * points at. Telling someone "certutil: command not found" and stopping is how
 * a five-second setup becomes an abandoned one.
 */
export async function probeTooling(env: TrustEnv = defaultEnv()): Promise<Tooling> {
  let certutil = false;
  try {
    await env.run("certutil", ["-H"]);
    certutil = true;
  } catch (error) {
    // certutil exits non-zero for -H on some builds; only ENOENT means absent.
    certutil = (error as { code?: string }).code !== "ENOENT";
  }

  const { packageName, packageManager, installHint } = nssPackage(env);
  return { certutil, installHint, packageName, packageManager };
}

function nssPackage(env: TrustEnv): { packageName: string; packageManager: string | null; installHint: string } {
  if (env.platform === "darwin") {
    return { packageName: "nss", packageManager: "brew", installHint: "brew install nss" };
  }

  const id = osReleaseId(env);
  if (/debian|ubuntu|mint|pop|elementary|raspbian/.test(id)) {
    return {
      packageName: "libnss3-tools",
      packageManager: "apt-get",
      installHint: "sudo apt-get install -y libnss3-tools",
    };
  }
  if (/fedora|rhel|centos|rocky|alma/.test(id)) {
    return { packageName: "nss-tools", packageManager: "dnf", installHint: "sudo dnf install -y nss-tools" };
  }
  if (/arch|manjaro|endeavour/.test(id)) {
    return { packageName: "nss", packageManager: "pacman", installHint: "sudo pacman -S --noconfirm nss" };
  }
  if (/opensuse|suse/.test(id)) {
    return { packageName: "mozilla-nss-tools", packageManager: "zypper", installHint: "sudo zypper install -y mozilla-nss-tools" };
  }
  return {
    packageName: "nss-tools",
    packageManager: null,
    installHint: "install your distribution's NSS tools package (it provides `certutil`)",
  };
}

function osReleaseId(env: TrustEnv): string {
  try {
    if (!env.exists("/etc/os-release")) return "";
    const text = readFileSync("/etc/os-release", "utf8");
    const id = /^ID=(.*)$/m.exec(text)?.[1] ?? "";
    const like = /^ID_LIKE=(.*)$/m.exec(text)?.[1] ?? "";
    return `${id} ${like}`.replace(/"/g, "").toLowerCase();
  } catch {
    return "";
  }
}

/** The file this root is written as, inside a distribution's anchor directory. */
export const ANCHOR_FILENAME = "moshpit-local-ca.crt";

/**
 * Bundles a refresh command regenerates. Checked so "installed" means the
 * bundle actually contains the root, not merely that a file was dropped in a
 * directory — `update-ca-certificates` skips a file whose name does not end in
 * `.crt`, and exits zero while doing so.
 */
const SYSTEM_BUNDLES = [
  "/etc/ssl/certs/ca-certificates.crt",
  "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
  "/etc/ssl/ca-bundle.pem",
];

/** The base64 body of a PEM, which is what to look for inside a bundle. */
function pemBody(pem: string): string {
  return pem
    .split("\n")
    .filter((line) => line.trim() && !line.startsWith("-----"))
    .join("")
    .trim();
}

function inSystemBundle(env: TrustEnv, anchor: string): boolean {
  const body = pemBody(env.readFile(anchor));
  // A short or absent body would match everything; treat it as not installed.
  if (body.length < 64) return false;
  const needle = body.slice(0, 64);
  return SYSTEM_BUNDLES.some((bundle) => env.exists(bundle) && pemBody(env.readFile(bundle)).includes(needle));
}

export type StoreStatus = { store: Store; installed: boolean; detail: string };

/** Whether this root is already trusted in `store`. Never writes. */
export async function status(store: Store, env: TrustEnv = defaultEnv()): Promise<StoreStatus> {
  try {
    if (store.kind === "ca-certificates") {
      const anchor = join(store.path, ANCHOR_FILENAME);
      if (!env.exists(anchor)) return { store, installed: false, detail: "not present" };
      return inSystemBundle(env, anchor)
        ? { store, installed: true, detail: "already trusted" }
        : { store, installed: false, detail: "the file is there but the system bundle does not contain it" };
    }
    if (store.kind === "nss") {
      await env.run("certutil", ["-d", `sql:${store.path}`, "-L", "-n", NICKNAME]);
      return { store, installed: true, detail: "already trusted" };
    }
    const { stdout } = await env.run("security", ["find-certificate", "-c", NICKNAME, store.path]);
    return { store, installed: stdout.includes(NICKNAME), detail: stdout.includes(NICKNAME) ? "already trusted" : "not present" };
  } catch {
    return { store, installed: false, detail: "not present" };
  }
}

export type InstallResult = { store: Store; ok: boolean; changed: boolean; detail: string };

/**
 * Trust the root in one store, and prove it afterwards.
 *
 * The read-back is not ceremony. `certutil` can exit zero having written to a
 * database the browser does not read (a profile that was never launched, a
 * locked db), and an install that reports success while the browser still shows
 * a warning is worse than a clean failure.
 */
export async function install(
  store: Store,
  certPath: string,
  env: TrustEnv = defaultEnv(),
): Promise<InstallResult> {
  const before = await status(store, env);
  if (before.installed) return { store, ok: true, changed: false, detail: "already trusted" };

  try {
    if (store.kind === "ca-certificates") {
      const refresh = CA_CERTIFICATES_DIRS.find((c) => c.dir === store.path)?.refresh;
      if (!refresh) return { store, ok: false, changed: false, detail: `no refresh command known for ${store.path}` };
      // The .crt suffix is load-bearing on Debian: update-ca-certificates
      // ignores anything else in this directory, silently and successfully.
      env.copyFile(certPath, join(store.path, ANCHOR_FILENAME));
      await env.run(refresh, []);
    } else if (store.kind === "nss") {
      // "C,," — trusted to issue server certificates, and nothing else. Not
      // "CT,c,c" and not a mail or code-signing trust bit; this root has one job.
      await env.run("certutil", ["-d", `sql:${store.path}`, "-A", "-t", "C,,", "-n", NICKNAME, "-i", certPath]);
    } else {
      await env.run("security", [
        "add-trusted-cert", "-d", "-r", "trustRoot", "-k", store.path, certPath,
      ]);
    }
  } catch (error) {
    return { store, ok: false, changed: false, detail: reason(error) };
  }

  const after = await status(store, env);
  return after.installed
    ? { store, ok: true, changed: true, detail: "trusted" }
    : { store, ok: false, changed: false, detail: "the store accepted the write but does not show it" };
}

/** Remove the root from one store. Absent is success — this has to be re-runnable. */
export async function uninstall(store: Store, env: TrustEnv = defaultEnv()): Promise<InstallResult> {
  const before = await status(store, env);
  if (!before.installed) return { store, ok: true, changed: false, detail: "was not present" };

  try {
    if (store.kind === "ca-certificates") {
      const refresh = CA_CERTIFICATES_DIRS.find((c) => c.dir === store.path)?.refresh;
      env.removeFile(join(store.path, ANCHOR_FILENAME));
      // Without the refresh the anchor is gone but the bundle still trusts it,
      // which is the worst of the three states.
      if (refresh) await env.run(refresh, []);
    } else if (store.kind === "nss") {
      await env.run("certutil", ["-d", `sql:${store.path}`, "-D", "-n", NICKNAME]);
    } else {
      await env.run("security", ["delete-certificate", "-c", NICKNAME, store.path]);
    }
  } catch (error) {
    return { store, ok: false, changed: false, detail: reason(error) };
  }

  const after = await status(store, env);
  return after.installed
    ? { store, ok: false, changed: false, detail: "still present after removal" }
    : { store, ok: true, changed: true, detail: "removed" };
}

function reason(error: unknown): string {
  const err = error as { code?: string; stderr?: string; message?: string };
  if (err.code === "ENOENT") return "certutil is not installed";
  const stderr = (err.stderr ?? "").trim();
  return stderr || err.message || String(error);
}
