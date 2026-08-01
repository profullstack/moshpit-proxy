#!/usr/bin/env node
// One command, no vocabulary. The word "certificate" appears nowhere a user reads.
//
// This exists because the honest barrier to Moshpit was never that people
// distrust a locally-generated root — it is that nobody should have to read
// `certutil -d sql:$HOME/.pki/nssdb -A -t "C,,"` to open a web page. The
// mechanism cannot go away for stock browsers; the ceremony can.
//
// There is still exactly one consent moment. Adding a root to someone's trust
// store without telling them is what malware does, and "the user didn't have to
// think about it" is not a reason to skip asking. What gets removed is the
// jargon, not the disclosure.

import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import { createLocalCa } from "../lib/ca.ts";
import { loadConfig } from "../lib/config.ts";
import {
  defaultEnv, discoverStores, install, probeTooling, status, uninstall,
  type Store,
} from "../lib/trust.ts";

const argv = new Set(process.argv.slice(2));
const wantsHelp = argv.has("--help") || argv.has("-h");
const assumeYes = argv.has("--yes") || argv.has("-y");
const wantsRemove = argv.has("--uninstall") || argv.has("--remove");
const wantsStatus = argv.has("--status");

if (wantsHelp) {
  console.log(`moshpit-trust — let this computer's browsers open Moshpit sites

  moshpit-trust              set it up (asks first)
  moshpit-trust --yes        set it up without asking
  moshpit-trust --status     show what is set up, change nothing
  moshpit-trust --uninstall  undo it

Run this once. It only affects ${namespaceLabel()} and cannot affect any other website.`);
  process.exit(0);
}

function namespaceLabel(): string {
  const tlds = loadConfig().tlds.map((t) => `.${t}`);
  return tlds.length === 1 ? tlds[0]! : `${tlds.slice(0, -1).join(", ")} and ${tlds.at(-1)}`;
}

const config = loadConfig();
const env = defaultEnv();
const stores = discoverStores(env);

if (stores.length === 0) {
  console.error("No browsers found on this computer that need setting up.");
  console.error("If you use Firefox, launch it once first — it creates its storage on first run.");
  process.exit(1);
}

// ---------------------------------------------------------------- status

if (wantsStatus) {
  const rows = await Promise.all(stores.map((s) => status(s, env)));
  for (const row of rows) {
    console.log(`  ${row.installed ? "✓" : "·"} ${row.store.label} — ${row.detail}`);
  }
  const ready = rows.filter((r) => r.installed).length;
  console.log(
    ready === rows.length
      ? `\nAll set. Try https://scrambled.${config.tlds[0] ?? "moshpit"}`
      : `\n${ready} of ${rows.length} set up. Run \`moshpit-trust\` to finish.`,
  );
  process.exit(0);
}

// ------------------------------------------------------------- uninstall

if (wantsRemove) {
  const results = await Promise.all(stores.map((s) => uninstall(s, env)));
  for (const r of results) console.log(`  ${r.ok ? "✓" : "✗"} ${r.store.label} — ${r.detail}`);
  const failed = results.filter((r) => !r.ok);
  console.log(failed.length ? "\nSome entries could not be removed." : "\nRemoved. Moshpit sites will stop opening.");
  process.exit(failed.length ? 1 : 0);
}

// --------------------------------------------------------------- install

// The tooling check comes before the consent prompt on purpose: asking someone
// to agree to something and *then* failing on a missing package wastes the one
// moment of attention this command gets.
const tooling = await probeTooling(env);
const needsCertutil = stores.some((s) => s.kind === "nss");
if (needsCertutil && !tooling.certutil) {
  console.error(`Missing a small system package that browsers need for this.

  ${tooling.installHint}

Then run \`moshpit-trust\` again.`);
  process.exit(1);
}

const needsRoot = stores.some((s) => s.needsRoot);

if (!assumeYes) {
  if (!stdin.isTTY) {
    console.error("Nothing to read an answer from. Re-run with --yes if you already know what this does.");
    process.exit(1);
  }
  console.log(`
  Moshpit needs to add a security key to this
  computer so your browser trusts ${namespaceLabel()} sites.
  It only works for ${namespaceLabel()} and cannot affect any
  other website.
`);
  for (const store of stores) console.log(`  · ${store.label}`);
  if (needsRoot) console.log("\n  You will be asked for your password.");

  const rl = createInterface({ input: stdin, output: stdout });
  const answer = (await rl.question("\n  Continue? [Y/n] ")).trim().toLowerCase();
  rl.close();
  if (answer && !/^y(es)?$/.test(answer)) {
    console.log("\n  Cancelled. Nothing was changed.");
    process.exit(1);
  }
}

// The root has to exist before it can be trusted. Creating it here means the
// setup command works on a machine that has never started the proxy.
const ca = createLocalCa({ dir: `${config.dir}/ca`, tlds: config.tlds });
await ca.ensure();

// Serially, not in parallel: these prompt for a password, and two prompts
// racing for the same terminal is how a setup step becomes unusable.
const results: Array<Awaited<ReturnType<typeof install>>> = [];
for (const store of stores) results.push(await install(store, ca.rootCertPath(), env));

console.log("");
for (const r of results) {
  const mark = r.ok ? "✓" : "✗";
  console.log(`  ${mark} ${r.store.label}${r.changed ? "" : ` — ${r.detail}`}`);
}

const failed = results.filter((r) => !r.ok);
if (failed.length === results.length) {
  console.error("\n  Setup did not work. Nothing on this computer was changed.");
  process.exit(1);
}

const sample = `https://scrambled${config.tlds[0] ? `.${config.tlds[0]}` : ""}`;
if (failed.length) {
  console.log(`\n  Mostly ready — ${failed.length} browser(s) could not be set up.`);
} else {
  console.log(`\n  ✓ Ready. Try ${sample}`);
}

// Said last because it is the thing that actually blocks a page from loading,
// and a person who just ran a setup command will read the final line.
console.log("  Moshpit sites need the resolver and proxy running too: `moshpit-proxy`");

process.exit(failed.length ? 1 : 0);

export type { Store };
