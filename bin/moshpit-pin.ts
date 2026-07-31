#!/usr/bin/env node
// Print the pin for a certificate, so a site operator can publish it.
//
//   moshpit-pin ./cert.pem          from a file (DER or PEM)
//   moshpit-pin scrambled.eggs:443  from whatever a live server presents
//
// The second form is the one people actually use, and it is also the one to be
// careful with: it reports what is being served *right now*, over a connection
// that is itself unverified. Run it against your own origin, from somewhere you
// trust the path, at the moment you deploy the key.

import { readFile } from "node:fs/promises";
import { connect } from "node:tls";
import { pinFromCertData, pinFromPeer } from "../lib/spki.ts";

const target = process.argv[2];
if (!target) {
  console.error("usage: moshpit-pin <cert-file | host[:port]>");
  process.exit(2);
}

const looksLikeHost = /^[a-z0-9.-]+(:\d+)?$/i.test(target) && !target.includes("/");

if (looksLikeHost && !(await exists(target))) {
  const [host, port = "443"] = target.split(":");
  const socket = connect({
    host,
    port: Number(port),
    servername: host,
    rejectUnauthorized: false,
  });
  socket.setTimeout(10_000, () => {
    console.error(`timed out connecting to ${host}:${port}`);
    process.exit(1);
  });
  socket.once("secureConnect", () => {
    const pin = pinFromPeer(socket);
    socket.destroy();
    if (!pin) {
      console.error("server presented no certificate");
      process.exit(1);
    }
    report(host, pin);
  });
  socket.once("error", (error) => {
    console.error(`connect failed: ${error.message}`);
    process.exit(1);
  });
} else {
  const data = await readFile(target);
  const text = data.toString("utf8");
  report(target, pinFromCertData(text.includes("-----BEGIN") ? text : data));
}

function report(name: string, pin: string) {
  console.log(pin);
  console.error("");
  console.error(`publish for ${name}:`);
  console.error(`  { "pins": ["${pin}"] }`);
  console.error("");
  console.error("keep the previous pin listed alongside it while rotating.");
}

async function exists(path: string): Promise<boolean> {
  try {
    await readFile(path);
    return true;
  } catch {
    return false;
  }
}
