// Which keys a Moshpit name is allowed to present.
//
// Deliberately the same shape as the resolver's registry client — bounded
// timeouts, a cache in front, coalesced lookups, failures that return null
// instead of throwing — because it is the same registry and it fails the same
// ways. What differs is what a failure means. The resolver can fall back to
// clearnet when the registry is slow; this cannot fall back to anything. An
// unknown pin is a refused connection, because the alternative is connecting
// to a key nobody vouched for, which is the exact thing being bought here.
//
// Registry contract:
//   GET {base}/api/moshpit/pins?name=foo.moshpit
//     200 -> { "name": "foo.moshpit", "pins": ["base64…", "base64…"] }
//     400 -> not a Moshpit name at all (a definite no, cached like an answer)
//     404 -> registered but no key published yet (also a definite no)
// An array rather than a single value so a site can publish its next key
// before it starts serving it. Rotation without a flag day is the difference
// between a pinning scheme people use and one they turn off.

export type PinSource = "override" | "registry" | "tofu";
export type PinLookup = { name: string; pins: string[]; source: PinSource };

export type PinClient = {
  lookup(name: string): Promise<PinLookup | null>;
  /** Records a first-seen key. Only ever called when TOFU is enabled. */
  remember(name: string, pin: string): void;
  stats(): { hits: number; misses: number; errors: number; entries: number };
  clear(): void;
};

type Entry = { value: PinLookup | null; expires: number };

export const DEFAULT_REGISTRY_BASE = "https://pit.moshcode.sh";

export function createPinClient(options: {
  base?: string;
  /** Pins that win over the registry. For bootstrapping and for private grids. */
  overrides?: Record<string, string[] | string>;
  /** How long a pin is trusted. Longer than a DNS answer: keys change rarely. */
  ttlMs?: number;
  /** How long a failure is remembered, so an outage is not amplified into a flood. */
  errorTtlMs?: number;
  timeoutMs?: number;
  maxEntries?: number;
  /** Trust-on-first-use. Off by default; it is a rollout aid, not a security model. */
  tofu?: boolean;
  fetchImpl?: typeof fetch;
  now?: () => number;
} = {}): PinClient {
  const base = (options.base ?? DEFAULT_REGISTRY_BASE).replace(/\/+$/, "");
  const ttlMs = options.ttlMs ?? 300_000;
  const errorTtlMs = options.errorTtlMs ?? 5_000;
  const timeoutMs = options.timeoutMs ?? 2_000;
  const maxEntries = options.maxEntries ?? 10_000;
  const tofu = options.tofu ?? false;
  const fetchImpl = options.fetchImpl ?? fetch;
  const now = options.now ?? Date.now;

  const overrides = new Map<string, string[]>();
  for (const [name, pins] of Object.entries(options.overrides ?? {})) {
    const list = (Array.isArray(pins) ? pins : [pins]).map((p) => p.trim()).filter(Boolean);
    if (list.length) overrides.set(normalise(name), list);
  }

  const learned = new Map<string, string[]>();
  const cache = new Map<string, Entry>();
  const inflight = new Map<string, Promise<PinLookup | null>>();
  const stats = { hits: 0, misses: 0, errors: 0 };

  function remember(name: string, value: PinLookup | null, ttl: number) {
    // Insertion-ordered Map, so the first key is the oldest — good enough
    // eviction for entries that all expire within minutes anyway.
    if (cache.size >= maxEntries) {
      const oldest = cache.keys().next();
      if (!oldest.done) cache.delete(oldest.value);
    }
    cache.set(name, { value, expires: now() + ttl });
  }

  async function fetchName(name: string): Promise<PinLookup | null> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const url = `${base}/api/moshpit/pins?name=${encodeURIComponent(name)}`;
      const res = await fetchImpl(url, { signal: controller.signal, headers: { accept: "application/json" } });

      // Both of these are the registry saying "no key here" rather than "ask me
      // again later", so they are cached for as long as a real answer would be.
      if (res.status === 400 || res.status === 404) {
        remember(name, null, ttlMs);
        return null;
      }
      if (!res.ok) throw new Error(`registry responded ${res.status}`);

      const json = (await res.json()) as { name?: unknown; pins?: unknown };
      const pins = Array.isArray(json?.pins)
        ? json.pins.filter((p): p is string => typeof p === "string" && p.length > 0)
        : [];
      if (!pins.length) {
        remember(name, null, ttlMs);
        return null;
      }

      const value: PinLookup = {
        name: typeof json.name === "string" ? json.name : name,
        pins,
        source: "registry",
      };
      remember(name, value, ttlMs);
      return value;
    } catch {
      stats.errors++;
      remember(name, null, errorTtlMs);
      return null;
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    async lookup(rawName: string) {
      const name = normalise(rawName);
      if (!name) return null;

      // Overrides are consulted before the cache so that editing them and
      // restarting is enough; there is no stale-pin puzzle to debug.
      const override = overrides.get(name);
      if (override) return { name, pins: override, source: "override" as const };

      const hit = cache.get(name);
      if (hit && hit.expires > now()) {
        stats.hits++;
        if (hit.value) return hit.value;
        // Fall through to TOFU below rather than returning the cached null,
        // so a key learned since the miss is still usable.
      } else {
        stats.misses++;
      }

      if (!hit || hit.expires <= now()) {
        const existing = inflight.get(name);
        const promise = existing ?? fetchName(name).finally(() => inflight.delete(name));
        if (!existing) inflight.set(name, promise);
        const answer = await promise;
        if (answer) return answer;
      }

      if (tofu) {
        const seen = learned.get(name);
        // An empty list is the signal to accept and record whatever answers.
        return { name, pins: seen ?? [], source: "tofu" };
      }
      return null;
    },

    remember(rawName: string, pin: string) {
      if (!tofu) return;
      const name = normalise(rawName);
      if (!name || !pin) return;
      if (!learned.has(name)) learned.set(name, [pin]);
    },

    stats: () => ({ ...stats, entries: cache.size }),
    clear: () => {
      cache.clear();
      inflight.clear();
      learned.clear();
    },
  };
}

function normalise(name: string): string {
  return String(name ?? "").trim().toLowerCase().replace(/\.$/, "");
}
