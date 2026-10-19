// What `moshpit-host.sh` refuses, and what it would do.
//
// The real run makes accounts and nginx blocks as root, so what is exercised here is
// everything before that: validation and --dry-run both run without privileges.

import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const run = promisify(execFile);
const script = fileURLToPath(new URL("../scripts/moshpit-host.sh", import.meta.url));

async function sh(args: string[]) {
  try {
    const { stdout, stderr } = await run("sh", [script, ...args], { env: { ...process.env, MOSHPIT_HOST_TARGET: "dev3.example.com" } });
    return { code: 0, stdout, stderr };
  } catch (err: any) {
    return { code: err.code ?? 1, stdout: String(err.stdout || ""), stderr: String(err.stderr || "") };
  }
}

describe("moshpit-host.sh", () => {
  test("dry run names the folder and the setup-origin call", async () => {
    const r = await sh(["alice", "shop.alice", "--dry-run"]);
    assert.equal(r.code, 0, r.stderr);
    assert.match(r.stdout, /folder\s+\/home\/alice\/apps\/shop\.alice\/public/);
    assert.match(r.stdout, /setup-origin\.sh shop\.alice --webroot \/home\/alice\/apps\/shop\.alice\/public .*--target dev3\.example\.com/);
  });

  test("refuses a bad account, a non-name, and the relay address", async () => {
    for (const [args, why] of [
      [["Alice", "shop.alice"], /not a valid account name/],
      [["alice", "shopalice"], /not a Moshpit name/],
      [["alice", "shop..alice"], /not a Moshpit name/],
      [["alice", "shop.alice.pit.world"], /relay's address/],
      [["alice", "shop.alice", "--key", "not a key"], /does not look like one SSH public key/],
    ] as const) {
      const r = await sh([...args, "--dry-run"]);
      assert.notEqual(r.code, 0);
      assert.match(r.stderr, why);
    }
  });

  test("refuses a real run without root", { skip: process.getuid?.() === 0 }, async () => {
    const r = await sh(["alice", "shop.alice"]);
    assert.notEqual(r.code, 0);
    assert.match(r.stderr, /run as root/);
  });
});
