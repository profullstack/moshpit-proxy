// Setting up trust stores, without ever touching this machine's trust stores.
//
// Every path and every command runner is injected, so the suite can assert what
// `certutil` would have been asked to do without asking it. That matters more
// than usual here: a test that got this wrong would silently modify the trust
// store of whoever ran it, and a test suite must never be a thing you have to
// undo afterwards.
//
// The one real-`certutil` test is opt-in by availability and skips cleanly when
// the tool is absent — which is the common case, since `libnss3-tools` is not
// installed by default on Debian or Ubuntu.

import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import {
  NICKNAME, defaultEnv, discoverStores, install, probeTooling, status, uninstall,
  type Store, type TrustEnv,
} from "../lib/trust.ts";
import { selfSigned, tempDir } from "./helpers.ts";

/** An env whose filesystem is a set of paths and whose exec is a script. */
function fakeEnv(opts: {
  platform?: string;
  home?: string;
  paths?: string[];
  dirs?: Record<string, string[]>;
  run?: TrustEnv["run"];
}): TrustEnv {
  const paths = new Set(opts.paths ?? []);
  return {
    platform: opts.platform ?? "linux",
    home: opts.home ?? "/home/tester",
    exists: (p) => paths.has(p),
    listDir: (p) => opts.dirs?.[p] ?? [],
    run: opts.run ?? (async () => ({ stdout: "", stderr: "" })),
  };
}

const ENOENT = Object.assign(new Error("spawn certutil ENOENT"), { code: "ENOENT" });

describe("trust store discovery", () => {
  test("finds the Chrome store on Linux when it exists", () => {
    const stores = discoverStores(fakeEnv({ paths: ["/home/tester/.pki/nssdb"] }));
    assert.equal(stores.length, 1);
    assert.equal(stores[0]!.id, "nss-chrome");
    assert.equal(stores[0]!.kind, "nss");
    assert.equal(stores[0]!.needsRoot, false);
  });

  test("returns nothing when no browser store exists", () => {
    assert.deepEqual(discoverStores(fakeEnv({})), []);
  });

  test("finds Firefox profiles, and only ones that have been launched", () => {
    // `fresh` has no cert9.db: the profile directory exists but Firefox has
    // never run, so writing there would look like success and do nothing.
    const root = "/home/tester/.mozilla/firefox";
    const stores = discoverStores(fakeEnv({
      paths: [root, join(root, "abc.default"), join(root, "abc.default", "cert9.db"), join(root, "fresh")],
      dirs: { [root]: ["abc.default", "fresh"] },
    }));
    assert.equal(stores.length, 1);
    assert.equal(stores[0]!.id, "nss-firefox-abc.default");
  });

  test("covers the snap Firefox, which is the default on current Ubuntu", () => {
    const snap = "/home/tester/snap/firefox/common/.mozilla/firefox";
    const stores = discoverStores(fakeEnv({
      paths: [snap, join(snap, "x.default"), join(snap, "x.default", "cert9.db")],
      dirs: { [snap]: ["x.default"] },
    }));
    assert.equal(stores.length, 1);
    assert.ok(stores[0]!.label.startsWith("Firefox"));
  });

  test("macOS gets the system keychain, and it needs a password", () => {
    const stores = discoverStores(fakeEnv({ platform: "darwin" }));
    assert.equal(stores[0]!.kind, "macos-keychain");
    assert.equal(stores[0]!.needsRoot, true);
    // The Linux-only Chrome NSS path must not appear on macOS.
    assert.ok(!stores.some((s) => s.id === "nss-chrome"));
  });

  test("macOS still picks up Firefox, which never uses the keychain", () => {
    const root = "/home/tester/Library/Application Support/Firefox/Profiles";
    const stores = discoverStores(fakeEnv({
      platform: "darwin",
      paths: [root, join(root, "p1"), join(root, "p1", "cert9.db")],
      dirs: { [root]: ["p1"] },
    }));
    assert.equal(stores.length, 2);
    assert.ok(stores.some((s) => s.kind === "macos-keychain"));
    assert.ok(stores.some((s) => s.id === "nss-firefox-p1"));
  });
});

describe("tooling probe", () => {
  test("reports certutil missing rather than letting it fail later", async () => {
    const tooling = await probeTooling(fakeEnv({ run: async () => { throw ENOENT; } }));
    assert.equal(tooling.certutil, false);
  });

  test("a non-zero exit is not the same as absent", async () => {
    // Some certutil builds exit non-zero for -H. That is not "not installed".
    const tooling = await probeTooling(fakeEnv({
      run: async () => { throw Object.assign(new Error("usage"), { code: 1 }); },
    }));
    assert.equal(tooling.certutil, true);
  });

  test("names the package for this distribution", async () => {
    const tooling = await probeTooling(defaultEnv({ run: async () => { throw ENOENT; } }));
    // Whatever the distro, the hint has to be runnable and mention a manager.
    assert.ok(tooling.installHint.length > 0);
    assert.ok(tooling.packageName.length > 0);
  });

  test("macOS points at brew, not apt", async () => {
    const tooling = await probeTooling(fakeEnv({ platform: "darwin", run: async () => { throw ENOENT; } }));
    assert.match(tooling.installHint, /brew/);
  });
});

const nssStore: Store = {
  id: "nss-test", kind: "nss", path: "/tmp/fake-nssdb",
  label: "Test browser", needsRoot: false,
};

describe("installing", () => {
  /** A store that starts empty and remembers what was added. */
  function stateful() {
    const calls: string[][] = [];
    let present = false;
    const run: TrustEnv["run"] = async (file, args) => {
      calls.push([file, ...args]);
      if (args.includes("-L")) {
        if (!present) throw new Error("PR_FILE_NOT_FOUND_ERROR");
        return { stdout: NICKNAME, stderr: "" };
      }
      if (args.includes("-A")) present = true;
      if (args.includes("-D")) present = false;
      return { stdout: "", stderr: "" };
    };
    return { calls, run, isPresent: () => present };
  }

  test("adds the root and proves it afterwards", async () => {
    const s = stateful();
    const result = await install(nssStore, "/tmp/ca.crt", fakeEnv({ run: s.run }));
    assert.equal(result.ok, true);
    assert.equal(result.changed, true);
    assert.equal(s.isPresent(), true);
  });

  test("asks for server-trust only, not every trust bit", async () => {
    const s = stateful();
    await install(nssStore, "/tmp/ca.crt", fakeEnv({ run: s.run }));
    const add = s.calls.find((c) => c.includes("-A"));
    assert.ok(add, "expected an add call");
    // "C,," — trusted to issue server certificates and nothing else. Not
    // "CT,c,c", which would also trust it for mail and code signing.
    assert.equal(add![add!.indexOf("-t") + 1], "C,,");
    assert.equal(add![add!.indexOf("-n") + 1], NICKNAME);
    assert.ok(add!.includes(`sql:${nssStore.path}`));
  });

  test("running twice changes nothing the second time", async () => {
    const s = stateful();
    const env = fakeEnv({ run: s.run });
    const first = await install(nssStore, "/tmp/ca.crt", env);
    const second = await install(nssStore, "/tmp/ca.crt", env);

    assert.equal(first.changed, true);
    assert.equal(second.changed, false);
    assert.equal(second.ok, true);
    // Exactly one write, however many times it is run.
    assert.equal(s.calls.filter((c) => c.includes("-A")).length, 1);
  });

  test("a write that the store does not show is a failure, not a success", async () => {
    // certutil can exit zero having written somewhere the browser will not
    // read. Reporting success there is worse than reporting nothing.
    const env = fakeEnv({
      run: async (_file, args) => {
        if (args.includes("-L")) throw new Error("PR_FILE_NOT_FOUND_ERROR");
        return { stdout: "", stderr: "" };
      },
    });
    const result = await install(nssStore, "/tmp/ca.crt", env);
    assert.equal(result.ok, false);
    assert.match(result.detail, /accepted the write but does not show it/);
  });

  test("a missing certutil is reported as such, not as a generic failure", async () => {
    const env = fakeEnv({ run: async () => { throw ENOENT; } });
    const result = await install(nssStore, "/tmp/ca.crt", env);
    assert.equal(result.ok, false);
    assert.match(result.detail, /certutil is not installed/);
  });
});

describe("uninstalling", () => {
  test("removes it, and removing again is still success", async () => {
    let present = true;
    const env = fakeEnv({
      run: async (_file, args) => {
        if (args.includes("-L")) {
          if (!present) throw new Error("not found");
          return { stdout: NICKNAME, stderr: "" };
        }
        if (args.includes("-D")) present = false;
        return { stdout: "", stderr: "" };
      },
    });

    const first = await uninstall(nssStore, env);
    assert.equal(first.ok, true);
    assert.equal(first.changed, true);

    const second = await uninstall(nssStore, env);
    assert.equal(second.ok, true);
    assert.equal(second.changed, false);
  });
});

describe("against real certutil", { skip: await certutilMissing() }, () => {
  test("adds and removes a root in a throwaway NSS database", async () => {
    const dir = await tempDir("moshpit-nssdb-");
    const env = defaultEnv();
    await env.run("certutil", ["-d", `sql:${dir}`, "-N", "--empty-password"]);

    const ca = await selfSigned(dir, "probe.moshpit");
    const store: Store = { id: "real", kind: "nss", path: dir, label: "throwaway", needsRoot: false };

    assert.equal((await status(store, env)).installed, false);

    const added = await install(store, ca.certPath, env);
    assert.equal(added.ok, true, added.detail);
    assert.equal((await status(store, env)).installed, true);

    const removed = await uninstall(store, env);
    assert.equal(removed.ok, true, removed.detail);
    assert.equal((await status(store, env)).installed, false);
  });
});

async function certutilMissing(): Promise<boolean | string> {
  const { certutil, installHint } = await probeTooling(defaultEnv());
  return certutil ? false : `certutil not installed (${installHint})`;
}
