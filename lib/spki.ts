// The pin: SHA-256 over a certificate's SubjectPublicKeyInfo, base64.
//
// The public key rather than the whole certificate, on purpose. A site can
// renew, re-issue, or fix a typo in its subject without the registry entry
// going stale, and the only question a pin is actually asking — "is this the
// same key I was promised" — is untouched by any of that.
//
// This is the RFC 7469 pin format, so
//   openssl x509 -in cert.pem -pubkey -noout |
//     openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
// prints the same string. An operator can check ours against theirs without
// taking our word for it.
//
// Worth stating plainly because it is the whole reason this design survives a
// quantum adversary: a normal certificate chain is authenticated by RSA or
// ECDSA signatures, which Shor's algorithm breaks. A pin is authenticated by a
// hash. Grover's only halves preimage resistance, so SHA-256 still leaves ~128
// bits — no ML-DSA needed, no chain to bloat.

import { X509Certificate, createHash } from "node:crypto";

/** Pins are compared as opaque strings; this is the only place they are made. */
export function pinFromSpkiDer(spki: Uint8Array): string {
  return createHash("sha256").update(spki).digest("base64");
}

export function pinFromCertificate(cert: X509Certificate): string {
  const spki = cert.publicKey.export({ type: "spki", format: "der" }) as Buffer;
  return pinFromSpkiDer(spki);
}

/** Accepts DER or PEM; `X509Certificate` sniffs which by looking for the header. */
export function pinFromCertData(data: Uint8Array | string): string {
  return pinFromCertificate(new X509Certificate(data as Buffer | string));
}

/**
 * The peer's pin, read off a connected TLS socket.
 *
 * Three ways in because the runtimes disagree about which they expose: Bun and
 * Node both grew `getPeerX509Certificate` late, and `getPeerCertificate().raw`
 * is the one that has been there all along. Returns null rather than throwing
 * when there is no peer certificate at all, which the caller must treat as a
 * verification failure — not as "no pin required".
 */
export function pinFromPeer(socket: {
  getPeerX509Certificate?: () => X509Certificate | undefined;
  getPeerCertificate?: (detailed?: boolean) => { raw?: Uint8Array } | undefined;
}): string | null {
  try {
    const x509 = socket.getPeerX509Certificate?.();
    if (x509) return pinFromCertificate(x509);
  } catch {
    // Fall through to the older accessor.
  }
  try {
    const raw = socket.getPeerCertificate?.(false)?.raw;
    if (raw && raw.length) return pinFromCertData(raw);
  } catch {
    // Nothing else to try.
  }
  return null;
}

/** Constant-time-ish membership test. Pins are public, but the habit is cheap. */
export function pinMatches(presented: string, allowed: readonly string[]): boolean {
  let hit = false;
  for (const candidate of allowed) {
    if (candidate.length === presented.length && candidate === presented) hit = true;
  }
  return hit;
}
