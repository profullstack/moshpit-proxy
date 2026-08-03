// Two defects found by installing this on a real machine and watching it fail.
//
// 1. The proxy relayed every connection through the gateway, which only works
//    if the gateway passes TLS through by SNI. pit.moshcode.sh terminates it,
//    so every name presented the gateway's own certificate and the proxy
//    refused all of them — correctly, and uselessly. Three different names
//    refused for one identical presented key is the signature.
//
// 2. `moshpit-trust` covered browsers and not the system CA store, so `curl`
//    still failed on a machine that had been "set up".
import assert from "node:assert/strict";
import test from "node:test";

import { createPinClient } from "../lib/pins.ts";
import {
  ANCHOR_FILENAME,
  CA_CERTIFICATES_DIRS,
  NICKNAME,
  defaultEnv,
  discoverStores,
  install,
  status,
  uninstall,
  type TrustEnv,
} from "../lib/trust.ts";

// ---- the target the registry publishes reaches the pin client ----

const registryReturning = (body: unknown) =>
  createPinClient({
    base: "https://registry.test",
    fetchImpl: (async () => new Response(JSON.stringify(body), {
      status: 200, headers: { "content-type": "application/json" },
    })) as typeof fetch,
  });

test("a name's target is carried through, so the origin can be dialled directly", async () => {
  const client = registryReturning({ name: "a.hacker", pins: ["AAA="], target: "origin.example:8443" });
  const found = await client.lookup("a.hacker");
  assert.equal(found?.target, "origin.example:8443");
});

test("a name with no target has no target key at all", async () => {
  // Not `target: undefined` — an own property set to undefined is not
  // deep-equal to an absent one, and that difference broke a passing test.
  const client = registryReturning({ name: "a.hacker", pins: ["AAA="] });
  const found = await client.lookup("a.hacker");
  assert.equal(Object.hasOwn(found as object, "target"), false);
});

test("a blank target is treated as no target, not as an empty host", async () => {
  const client = registryReturning({ name: "a.hacker", pins: ["AAA="], target: "   " });
  assert.equal(Object.hasOwn((await client.lookup("a.hacker")) as object, "target"), false);
});

// ---- the system CA store ----

function fakeLinux(overrides: Partial<TrustEnv> = {}): { env: TrustEnv; files: Map<string, string>; ran: string[] } {
  const files = new Map<string, string>();
  const ran: string[] = [];
  const env: TrustEnv = {
    ...defaultEnv(),
    platform: "linux",
    home: "/home/nobody",
    exists: (p) => files.has(p),
    listDir: () => [],
    readFile: (p) => files.get(p) ?? "",
    copyFile: (from, to) => files.set(to, files.get(from) ?? ""),
    removeFile: (p) => { files.delete(p); },
    run: async (file) => { ran.push(file); return { stdout: "", stderr: "" }; },
    ...overrides,
  };
  return { env, files, ran };
}

const PEM = `-----BEGIN CERTIFICATE-----\n${"QUJDRA".repeat(20)}\n-----END CERTIFICATE-----\n`;

test("the system store is discovered on Linux, and is the one curl reads", () => {
  const { env, files } = fakeLinux();
  files.set("/usr/local/share/ca-certificates", "");
  const store = discoverStores(env).find((s) => s.kind === "ca-certificates");
  assert.ok(store, "a Linux machine must offer the store curl, wget and git use");
  assert.equal(store.needsRoot, true, "writing a system root needs an administrator");
  assert.match(store.label, /curl/);
});

test("only one distribution's anchor directory is used", () => {
  const { env, files } = fakeLinux();
  for (const c of CA_CERTIFICATES_DIRS) files.set(c.dir, "");
  const found = discoverStores(env).filter((s) => s.kind === "ca-certificates");
  assert.equal(found.length, 1,
    "writing into a second distribution's directory leaves a file nothing reads");
});

test("installing writes a .crt anchor and refreshes the bundle", async () => {
  const { env, files, ran } = fakeLinux();
  files.set("/usr/local/share/ca-certificates", "");
  files.set("/ca.crt", PEM);
  files.set("/etc/ssl/certs/ca-certificates.crt", "");

  // The refresh is what puts the root in the bundle; model that.
  const withRefresh: TrustEnv = {
    ...env,
    run: async (file) => {
      ran.push(file);
      if (file === "update-ca-certificates") {
        files.set("/etc/ssl/certs/ca-certificates.crt", files.get(`/usr/local/share/ca-certificates/${ANCHOR_FILENAME}`) ?? "");
      }
      return { stdout: "", stderr: "" };
    },
  };

  const store = discoverStores(env).find((s) => s.kind === "ca-certificates")!;
  const result = await install(store, "/ca.crt", withRefresh);

  assert.equal(result.ok, true, result.detail);
  assert.ok(files.has(`/usr/local/share/ca-certificates/${ANCHOR_FILENAME}`),
    "the filename must end in .crt — update-ca-certificates ignores anything else, silently");
  assert.ok(ran.includes("update-ca-certificates"), "an anchor nothing rebuilt is not trusted");
});

test("a refresh that does not reach the bundle is reported as a failure", async () => {
  // The exact shape of the bug this replaces: the write succeeds, the command
  // exits zero, and nothing trusts the root. Reporting success there is worse
  // than failing.
  const { env, files } = fakeLinux();
  files.set("/usr/local/share/ca-certificates", "");
  files.set("/ca.crt", PEM);
  files.set("/etc/ssl/certs/ca-certificates.crt", "unrelated content");

  const store = discoverStores(env).find((s) => s.kind === "ca-certificates")!;
  const result = await install(store, "/ca.crt", env);

  assert.equal(result.ok, false, "an install nothing trusts must not report success");
  assert.equal(result.changed, false);
  // The post-install read-back is what catches this, and it is shared with the
  // other store kinds. The bundle-specific wording is status()'s job, asserted
  // separately below — that is what someone runs to find out why.
  assert.match(result.detail, /does not show it/);
});

test("uninstalling removes the anchor and rebuilds, in that order", async () => {
  const { env, files, ran } = fakeLinux();
  files.set("/usr/local/share/ca-certificates", "");
  files.set(`/usr/local/share/ca-certificates/${ANCHOR_FILENAME}`, PEM);
  files.set("/etc/ssl/certs/ca-certificates.crt", PEM);

  const store = discoverStores(env).find((s) => s.kind === "ca-certificates")!;
  assert.equal((await status(store, env)).installed, true, "precondition: it is trusted");

  const result = await uninstall(store, env);
  assert.equal(result.ok, true, result.detail);
  assert.equal(files.has(`/usr/local/share/ca-certificates/${ANCHOR_FILENAME}`), false);
  assert.ok(ran.includes("update-ca-certificates"),
    "an anchor removed without a rebuild leaves the bundle still trusting it");
});

test("status is honest when the file is present but the bundle is not rebuilt", async () => {
  const { env, files } = fakeLinux();
  files.set("/usr/local/share/ca-certificates", "");
  files.set(`/usr/local/share/ca-certificates/${ANCHOR_FILENAME}`, PEM);
  files.set("/etc/ssl/certs/ca-certificates.crt", "something else entirely");

  const store = discoverStores(env).find((s) => s.kind === "ca-certificates")!;
  const state = await status(store, env);
  assert.equal(state.installed, false);
  assert.match(state.detail, /bundle/);
});

test("the nickname is unchanged, so an older install is still found", () => {
  assert.equal(NICKNAME, "Moshpit Local CA");
});
