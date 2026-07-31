// Configuration, all of it from the environment, same as the resolver.
//
// The defaults assume the common case: a person on their own laptop who ran
// the installer, is pointing at the public gateway, and wants the safe
// behaviour without reading any of this.

import { homedir } from "node:os";
import { join } from "node:path";
import { readFileSync } from "node:fs";

export type Config = {
  listenHost: string;
  listenPort: number;
  gatewayHost: string;
  gatewayPort: number;
  registryBase: string;
  dir: string;
  tlds: string[];
  tofu: boolean;
  overrides: Record<string, string[]>;
  logging: boolean;
};

export function loadConfig(env: Record<string, string | undefined> = process.env): Config {
  const dir = env.MOSHPIT_PROXY_DIR || join(homedir(), ".moshpit");
  return {
    listenHost: env.MOSHPIT_PROXY_HOST || "127.0.0.1",
    // 8443 rather than 443 so the default needs no privileges. The installer
    // is what moves it to 443, together with the resolver that points names
    // at loopback in the first place.
    listenPort: intOr(env.MOSHPIT_PROXY_PORT, 8443),
    gatewayHost: env.MOSHPIT_GATEWAY_HOST || "pit.moshcode.sh",
    gatewayPort: intOr(env.MOSHPIT_GATEWAY_PORT, 443),
    registryBase: env.MOSHPIT_REGISTRY_BASE || "https://pit.moshcode.sh",
    dir,
    tlds: (env.MOSHPIT_PROXY_TLDS || "moshpit")
      .split(",").map((t) => t.trim().replace(/^\.+/, "").toLowerCase()).filter(Boolean),
    // Off unless asked for, and asked for loudly. TOFU turns the first
    // connection into an act of faith; it exists so a grid can come up before
    // the registry serves pins, not because it is good.
    tofu: truthy(env.MOSHPIT_PROXY_TOFU),
    overrides: loadOverrides(env.MOSHPIT_PROXY_PINS || join(dir, "pins.json")),
    logging: truthy(env.MOSHPIT_PROXY_LOG ?? "1"),
  };
}

/** `{ "foo.moshpit": ["base64…"] }` — missing or malformed is simply no overrides. */
function loadOverrides(path: string): Record<string, string[]> {
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
    const out: Record<string, string[]> = {};
    for (const [name, value] of Object.entries(parsed)) {
      const list = (Array.isArray(value) ? value : [value])
        .filter((v): v is string => typeof v === "string" && v.length > 0);
      if (list.length) out[name.toLowerCase()] = list;
    }
    return out;
  } catch {
    return {};
  }
}

function intOr(value: string | undefined, fallback: number): number {
  const parsed = Number.parseInt(value ?? "", 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function truthy(value: string | undefined): boolean {
  if (value === undefined) return false;
  return /^(1|true|yes|on)$/i.test(value.trim());
}
