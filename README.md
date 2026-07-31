# moshpit-proxy

Registry-pinned TLS for Moshpit names. The origin's key is checked against what
the registry published for that name — not against a certificate authority,
because no certificate authority will ever vouch for `.moshpit`.

## Why not just get a certificate

You can't, and it isn't a matter of persuasion. The CA/Browser Forum Baseline
Requirements banned certificates for non-IANA names: issuance stopped in
November 2015 and existing ones were revoked by October 2016. A CA in a browser
root store that issued for `.moshpit` would be distrusted for doing it. The rule
is the penalty.

So the trust has to come from somewhere else. It comes from the registry, which
already knows who owns each name — a stronger claim than domain validation ever
made, since it proves registry ownership rather than momentary control of a
socket.

## The three topologies, and which one this implements

| | Gateway sees | |
|---|---|---|
| A. Gateway terminates TLS | everything | simplest, but the gateway is a designed-in MITM |
| **B. Gateway SNI-passthrough** | **hostname only** | **implemented here** |
| C. Registry returns origin IP | nothing | leaks origin IPs, breaks NAT'd sites |

A central terminating gateway and end-to-end encryption are mutually exclusive.
This is topology B: nginx routes on the SNI without a private key, so the
session that terminates at the origin is genuinely end-to-end.

## Clients

### TronBrowser — the path with none of this

[tronbrowser.dev](https://tronbrowser.dev) has built-in Moshpit support. It
resolves names and verifies registry pins natively, so it needs **no DNS
configuration, no local proxy, and no root certificate**. Nothing in this
package is required to browse Moshpit from TronBrowser.

Everything below exists for stock browsers, which cannot be taught to check a
registry pin — there is no certificate-validation API in any browser extension
model.

### Stock browsers — this proxy

```
browser --TLS--> proxy --TLS--> gateway (ssl_preread) --TCP--> origin
        local CA        registry-pinned key
```

The right-hand session is the real one. The left-hand session exists only to say
the result in the one language a browser accepts.

```sh
npm start                      # or: node bin/moshpit-proxy.ts
```

Pair it with [`moshpit-dns`](../moshpit-dns), which points `.moshpit` names at
loopback.

| Variable | Default | |
|---|---|---|
| `MOSHPIT_PROXY_PORT` | `8443` | 443 needs privileges; the installer moves it |
| `MOSHPIT_PROXY_HOST` | `127.0.0.1` | |
| `MOSHPIT_GATEWAY_HOST` | `pit.moshcode.sh` | |
| `MOSHPIT_REGISTRY_BASE` | `https://pit.moshcode.sh` | |
| `MOSHPIT_PROXY_TLDS` | `moshpit` | comma-separated |
| `MOSHPIT_PROXY_PINS` | `~/.moshpit/pins.json` | overrides, win over the registry |
| `MOSHPIT_PROXY_TOFU` | off | see below |
| `MOSHPIT_PROXY_DIR` | `~/.moshpit` | |

## Trusting the local root

The proxy generates a root on first run at `~/.moshpit/ca/ca.crt` and prints its
fingerprint. Two things make installing it a much smaller ask than a shared CA:

1. **The key never leaves this machine.** Compromising Moshpit's infrastructure
   does not forge certificates for you.
2. **It carries a critical `nameConstraints` extension** permitting only the
   Moshpit TLDs and excluding every other name form. Even holding the key, the
   worst reachable outcome is forging a name you already control.

That second property is tested, not asserted — `tests/ca.test.ts` signs a
`www.google.com` certificate with the root and checks that openssl rejects it
with `permitted subtree violation`.

```sh
# Linux (NSS: Chrome, Firefox)
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "Moshpit Local CA" -i ~/.moshpit/ca/ca.crt
# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.moshpit/ca/ca.crt
```

Node, Python and Java keep their own trust stores — `NODE_EXTRA_CA_CERTS`,
`certifi`, `cacerts` respectively. Installing into the OS store does not cover
them.

## Publishing a pin (site operators)

```sh
npx moshpit-pin ./origin.crt        # from a file
npx moshpit-pin scrambled.eggs:443  # from what a live server presents
```

Publish the result at [app.moshcode.sh/pit/dns](https://app.moshcode.sh/pit/dns).
Keep the previous pin listed alongside the new one while rotating — the client
accepts any pin in the list, so a key can change without a flag day.

The pin is `SHA-256(SubjectPublicKeyInfo)`, base64 — the RFC 7469 format, so
`openssl x509 -pubkey | openssl pkey -pubin -outform der | openssl dgst -sha256`
prints the same string. `tests/spki.test.ts` asserts we agree with openssl.

## Gateway

`nginx/moshpit-gateway.conf` — there is no `ssl_certificate` directive anywhere
in it, which is the point. Requires `ngx_stream_module` with `ssl_preread`
(already compiled into stock Debian/Ubuntu nginx).

```sh
node scripts/gen-upstreams.ts   # writes the SNI->origin map, reloads nginx
```

The map is regenerated on a timer rather than looked up per connection, so the
registry is not on the path of every TCP handshake.

## Post-quantum status

- **Key exchange** — `X25519MLKEM768`, free from OpenSSL 3.5+ and on by default
  in current Chrome and Firefox. This is the leg that matters, because
  harvest-now-decrypt-later only threatens confidentiality.
- **Authentication** — a normal certificate chain is authenticated by RSA or
  ECDSA signatures, which Shor's algorithm breaks. A pin is authenticated by a
  hash; Grover's only halves preimage resistance, so SHA-256 still leaves ~128
  bits. **The pinning design is already post-quantum on the authentication side,
  with no ML-DSA and no chain bloat.**

Because both ends of the trust decision are ours, server keys can move to ML-DSA
whenever we like — no CA, no root program, no CA/B ballot. Browsers don't
support PQ signatures in TLS yet, but the proxy terminates for the browser, so
the proxy↔origin leg can run ML-DSA before the public web can.

## Why Node and not Bun

The rest of the Moshpit stack is Bun. This is not, and the reason is specific
rather than aesthetic. Bun 1.3.14 cannot do dynamic SNI:

- `tls.createServer({ SNICallback })` — **the callback is never invoked.** Bun
  silently serves the default certificate instead, or fails the handshake if
  there isn't one.
- `new TLSSocket(sock, { isServer: true, secureContext })` — never completes the
  handshake, so peeking the ClientHello and wrapping the socket by hand doesn't
  work either.
- A single wildcard certificate is not a way out: `*.moshpit` is a wildcard
  directly beneath a TLD and every TLS stack rejects it, by the same rule that
  makes `*.com` invalid.
- `getPeerCertificate()` returns a stub with no `raw`, so there is nothing to
  compute a pin from.

A proxy that mints a certificate per name needs all of the above. Node 24
supports every part of it and runs the TypeScript directly via type stripping,
so there is no build step. If Bun's `node:tls` catches up, this moves back.

## Known limitations

- **ALPN is forced to `http/1.1`.** Raw bytes are piped between two independent
  TLS sessions, so the protocol must match on both ends, and the origin's choice
  isn't known until after the browser's handshake has committed. Mirroring it
  properly means probing the origin from `SNICallback` and answering
  `ALPNCallback` from cache. HTTP/3 would not survive a TCP proxy regardless.
- **iOS** needs the profile installed *and* a second toggle under Settings →
  General → About → Certificate Trust Settings.
- **Android 7+** does not trust user-installed CAs for app traffic by default.
  Browsers generally honour them; apps won't.
- **TOFU is off by default.** `MOSHPIT_PROXY_TOFU=1` accepts the first key seen
  for a name and holds it against later substitution. It is a rollout aid for
  bringing up a grid before the registry serves pins — not a security model.

## Tests

```sh
npm test        # node --test tests/*.test.ts
```

27 tests. The ones that matter are in `tests/proxy.test.ts`: they stand up a
real origin over real TLS and check that a vouched-for key gets through and a
substituted one is refused before any request byte leaves the machine.
