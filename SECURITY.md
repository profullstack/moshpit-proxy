# Security

Report vulnerabilities to **anthony@profullstack.com**. Please don't open a
public issue for anything that lets someone impersonate a Moshpit name or read
traffic they shouldn't.

## Trust model

This software asks you to install a root certificate authority. That is a large
thing to ask, so here is exactly what you are agreeing to.

**The root key is generated on your machine and never leaves it.** It is written
to `~/.moshpit/ca/ca.key` with mode 600. Nobody else — including whoever
operates the Moshpit registry or gateway — has a copy. Compromising Moshpit's
infrastructure does not let anyone forge certificates for you.

**The root is scoped by a critical `nameConstraints` extension** that permits
only the configured Moshpit TLDs and excludes every other name form (IP, email,
URI, and all other DNS subtrees). Even with the key in hand, the worst reachable
outcome is forging a name inside a namespace you already opted into. It cannot
mint a certificate for `google.com`.

That claim is tested, not asserted. `tests/ca.test.ts` signs a `www.google.com`
certificate with the root and requires that openssl reject it with
`permitted subtree violation`. If that test ever passes silently, the security
story has changed and the tests should fail loudly. Please report it if it
doesn't.

**What the proxy verifies.** The origin's certificate is checked against the
`SHA-256(SubjectPublicKeyInfo)` pin the registry published for that name. The
chain, the issuer, and the expiry are deliberately not consulted — no CA has
ever heard of these names. `rejectUnauthorized: false` appears in `lib/proxy.ts`
for exactly this reason: it disables chain verification, and the pin check that
replaces it is stricter. A name with no published pin is refused, not connected
to.

## In scope

- Any path that lets a key other than the pinned one complete a connection
- Any way to make the local CA sign outside its name constraints
- Request bytes reaching an unverified origin (the browser socket is paused
  until the pin check passes — a way around that is a real bug)
- Pin confusion between names, or cache poisoning in `lib/pins.ts`
- Injection into the generated nginx map via a registry-controlled value

## Known and accepted

These are documented tradeoffs, not vulnerabilities. Reports are still welcome
if you think one is worse than described.

- **TOFU** (`MOSHPIT_PROXY_TOFU=1`) accepts the first key seen for a name. It is
  off by default and exists to bring a grid up before the registry serves pins.
  With it on, the first connection is unauthenticated.
- **ALPN is forced to `http/1.1`.** A downgrade from HTTP/2, not from TLS.
- **Android 7+** does not trust user-installed CAs for app traffic; **iOS**
  needs a second toggle beyond installing the profile. Both mean the proxy
  protects less than you might assume on mobile.
- **The gateway sees SNI.** Under topology B it holds no key and cannot read
  traffic, but it learns which name each client asked for.

## Cryptographic posture

Key exchange is whatever the TLS stack negotiates; with OpenSSL 3.5+ that
includes `X25519MLKEM768`, which is post-quantum. Authentication rests on
SHA-256 preimage resistance rather than on RSA or ECDSA signatures, so it does
not fall to Shor's algorithm — Grover's leaves roughly 128 bits. If you find a
place where a signature is load-bearing for identity, that is worth reporting.
