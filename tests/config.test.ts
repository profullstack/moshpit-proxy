import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { loadConfig } from "../lib/config.ts";

describe("config", () => {
  test("rejects malformed and out-of-range port values", () => {
    for (const value of ["443junk", "1.5", "0", "-1", "65536", "Infinity"]) {
      const config = loadConfig({
        MOSHPIT_PROXY_DIR: "unused",
        MOSHPIT_PROXY_PORT: value,
        MOSHPIT_GATEWAY_PORT: value,
      });

      assert.equal(config.listenPort, 8443, `listen port should reject ${value}`);
      assert.equal(config.gatewayPort, 443, `gateway port should reject ${value}`);
    }
  });

  test("accepts trimmed ports across the full valid range", () => {
    const config = loadConfig({
      MOSHPIT_PROXY_DIR: "unused",
      MOSHPIT_PROXY_PORT: " 1 ",
      MOSHPIT_GATEWAY_PORT: "65535",
    });

    assert.equal(config.listenPort, 1);
    assert.equal(config.gatewayPort, 65_535);
  });
});
