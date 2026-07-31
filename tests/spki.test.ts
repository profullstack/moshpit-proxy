import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { pinFromCertData, pinMatches } from "../lib/spki.ts";
import { opensslPin, selfSigned, tempDir } from "./helpers.ts";

describe("spki pins", () => {
  test("agrees with openssl's own pin pipeline", async () => {
    const dir = await tempDir();
    const origin = await selfSigned(dir, "agree.moshpit");

    assert.equal(pinFromCertData(origin.cert), await opensslPin(origin.certPath));
  });

  test("reads DER as well as PEM", async () => {
    const dir = await tempDir();
    const origin = await selfSigned(dir, "der.moshpit");
    const der = await readFile(origin.certPath);

    // Same certificate, two encodings, one pin.
    assert.equal(pinFromCertData(der), pinFromCertData(origin.cert));
  });

  test("different keys produce different pins", async () => {
    const dir = await tempDir();
    const a = await selfSigned(dir, "a.moshpit");
    const b = await selfSigned(dir, "b.moshpit");

    assert.notEqual(pinFromCertData(a.cert), pinFromCertData(b.cert));
  });

  test("matching is exact", () => {
    assert.equal(pinMatches("abc", ["abc"]), true);
    assert.equal(pinMatches("abc", ["zzz", "abc"]), true);
    assert.equal(pinMatches("abc", []), false);
    assert.equal(pinMatches("abc", ["ab"]), false);
    assert.equal(pinMatches("abc", ["abcd"]), false);
  });
});
