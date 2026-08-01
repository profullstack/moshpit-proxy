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

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/profullstack/moshpit-proxy/main/install.sh | sh
```

Installs under `~/.local`, needs no root for the code, and finishes by setting up
your browsers — asking once, in plain language, before it changes anything:

```
  Moshpit needs to add a security key to this
  computer so your browser trusts .moshpit sites.
  It only works for .moshpit and cannot affect any
  other website.

  Continue? [Y/n]
```

`--no-trust` installs the code only. `--uninstall` removes both.

Already have the code? `moshpit-trust` does the browser setup on its own, and
`moshpit-trust --status` says what is set up without changing anything. It is
idempotent — running it twice is a no-op, not a duplicate.

> **Nothing in this section applies to [TronBrowser](https://tronbrowser.dev)**,
> which verifies registry pins natively. No setup, no proxy, no local root.

## Trusting the local root

`moshpit-trust` automates everything below; this section is what it does and why,
for anyone who would rather do it by hand or wants to know what changed.

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
# Linux (NSS: Chrome, Chromium, Edge)
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "Moshpit Local CA" -i ~/.moshpit/ca/ca.crt
# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.moshpit/ca/ca.crt
```

`C,,` is server-trust only — not code signing, not mail.

**Firefox is not covered by either command.** It carries its own NSS database per
profile on every platform, including macOS, so the keychain does nothing for it:

```sh
certutil -d sql:~/.mozilla/firefox/<profile> -A -t "C,," -n "Moshpit Local CA" -i ~/.moshpit/ca/ca.crt
```

On current Ubuntu the default Firefox is the snap, whose profiles live under
`~/snap/firefox/common/.mozilla/firefox/` instead. `moshpit-trust` covers the
snap and flatpak paths as well, which is most of why doing this by hand tends to
half-work.

`certutil` itself is not installed by default on Debian or Ubuntu — the command
above fails on a machine that *does* have the store it points at. Install
`libnss3-tools` (Debian/Ubuntu), `nss-tools` (Fedora/RHEL) or `nss` (Arch, brew).

Node, Python and Java keep their own trust stores — `NODE_EXTRA_CA_CERTS`,
`certifi`, `cacerts` respectively. Installing into the OS store does not cover
them, and neither does `moshpit-trust`.

## Serving a name (site operators)

On the box that will host the name — a VPS, a droplet, anything with a public
address:

```sh
sudo sh scripts/setup-origin.sh chovy.hacker
```

Generates a key and self-signed certificate, writes an nginx server block from
`nginx/moshpit-origin.conf`, reloads, connects back to itself to prove the name
now answers with the key it just made, and prints the pin to publish. `--dry-run`
shows what it would do.

Self-signed is the design, not a shortcut: no CA will issue for a Moshpit TLD, so
identity comes from the registry rather than an issuer. Nothing about the
certificate is checked except the key, so an expensive one and this one are worth
exactly the same here.

**The failure this is built to prevent:** a name with no matching server block
falls through to nginx's default vhost, which answers with a certificate for some
other name entirely. The browser reports an invalid certificate and the site looks
broken, when what is broken is one missing `server_name`. The script connects back
and checks, rather than trusting that a clean `nginx -t` means the name resolves
to the right block.

Nothing is proxied on the server side. `moshpit-proxy` runs on the *visitor's*
machine — it is the thing that checks the pin on behalf of a browser that cannot.

## Publishing a pin (site operators)

```sh
npx moshpit-pin ./origin.crt        # from a file
npx moshpit-pin scrambled.eggs:443  # from what a live server presents
```

`setup-origin.sh` prints this for you. Until the pin is published every client
refuses the name — there is no TOFU and no unauthenticated mode, because the pin
stands exactly where a certificate authority would.

Publish the result at [app.moshcode.sh/pit](https://app.moshcode.sh/pit) — sign
in, open the **Yours** tab, and use **Key pins** on the TLD.

Not `/pit/dns`, which this file used to say. That page is the instructions for
pointing a *machine's resolver* at Moshpit — it has no pin form on it, so the
old link sent operators somewhere they could never finish the job.

The same page is where a name's **points at** target lives, which is the other
half of making a name reachable.

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

### It is on by default, and that is measured

The proxy configures no groups at all — the origin leg uses Node's defaults.
On Node 24 against OpenSSL 3.5 those defaults already put the hybrid first and
send a real ML-KEM key share in the first flight. Read off the wire from the
ClientHello the proxy actually sends:

```
supported_groups: X25519MLKEM768, x25519, secp256r1, x448, secp384r1, ...
key_share sent  : X25519MLKEM768(1216B), x25519(32B)
```

### The gap was that nobody could tell when it didn't happen

An origin on OpenSSL 3.0–3.4 — what Ubuntu 22.04 and 24.04 still ship — has no
ML-KEM, so the handshake silently falls back to `x25519` and succeeds. The
session is fine against every adversary that exists today and decryptable by one
that doesn't yet. Nothing said so, which made the guarantee unobservable.

Every upstream leg is now classified and counted:

```
[proxy] ok scrambled.eggs (registry) TLSv1.3 hybrid-pq
[proxy] warn old.eggs: origin has no ML-KEM, fell back to classical/X25519
...
[proxy] 41 post-quantum, 3 classical
```

`MOSHPIT_PROXY_REQUIRE_PQ=1` turns the fallback into a refusal. **Leave it off
until the counters say the grid is ready** — switching it on today takes every
pre-3.5 origin offline.

Node exposes no binding for `SSL_get_negotiated_group()`, so the group is read
through `getEphemeralKeyInfo()`, which cannot represent a hybrid KEM and returns
`{}` for one while naming any classical group. That is an inference from an
absence, so it is never trusted on faith: two loopback handshakes at startup
prove both halves of the mapping, the result is printed, and enforcement refuses
to engage if the proof fails. See `lib/pq.ts`.

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

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Apache rather than MIT for a specific reason: this is protocol code meant to be
reimplemented — TronBrowser performs the same pin verification independently —
and Apache-2.0 carries an explicit patent grant where MIT is silent. Implement
the pin scheme however you like; the NOTICE covers naming.

Security policy and the trust model behind the local CA: [SECURITY.md](SECURITY.md).

## Resolving Moshpit names on a machine (`systemd/`)

`systemd/moshpit-dns.service` and `systemd/00-moshpit.conf` are the deployed
resolver setup, kept here because they were previously configured by hand on
each box and existed in no repository.

```sh
cp systemd/moshpit-dns.service /etc/systemd/system/
cp systemd/00-moshpit.conf     /etc/systemd/resolved.conf.d/
systemctl daemon-reload && systemctl enable --now moshpit-dns
systemctl restart systemd-resolved
```

The bridge runs as this machine's **primary** resolver, with no list of Moshpit
endings anywhere. That is not a shortcut — a per-TLD list cannot be made to work:

- **It does not scale.** `moshcode dns install --write` emits every claimed
  ending as a routing domain — 5,661 of them on one line. systemd-resolved caps
  search domains near 1090 and drops the rest alphabetically, logging thousands
  of `Failed to add search domain '~zoology': Argument list too long`. Endings
  past the cut are configured on disk and absent from the resolver.
- **Curating the list does not fix it either.** A routing domain selects a
  *scope*, and a scope tries its servers in order. With an upstream resolver in
  the same scope, `.hacker` goes there first, comes back NXDOMAIN, and
  systemd-resolved treats that as final — the bridge is never asked.

Sending every query to the bridge removes both problems. It answers Moshpit
names from the registry and forwards everything else upstream (`mode=clearnet`:
the ordinary internet owns any name it can answer; the registry is a backfill).

The drop-in is named `00-` so it is read first: systemd-resolved appends `DNS=`
in filename order and uses the first server, rotating only on *failure* — never
on NXDOMAIN. So any pre-existing resolvers stay listed as a genuine fallback for
if the bridge stops, rather than shadowing it.

**Do not set `MOSHPIT_DNS_CATCHALL=1` here.** It parks every unresolved name on
the registry's parking address, which on a machine's own resolver means
`github.com` resolves to a parking page. Correct startup logs say `mode=clearnet`.
If clearnet names start resolving to a `69.46.46.x` address, check for a stray
`moshcode dns start` bound to `127.0.0.1:5354` — a loopback bind beats the
service's `0.0.0.0` bind and wins every local query.
