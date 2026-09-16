#!/bin/sh
# Put a Moshpit name on this box: key, certificate, nginx block, and the pin.
#
#   sudo sh scripts/setup-origin.sh chovy.hacker
#
# Generates a self-signed key pair for the name, writes an nginx server block
# from nginx/moshpit-origin.conf, reloads, then connects back to itself and
# proves the name now answers with the key it just made. Trusts the result on
# this machine, so the box that serves the name can also open it. Ends by
# printing the pin to publish.
#
# Re-run it whenever you like. The key is reused, so the pin does not move and
# the registry needs to hear nothing about it -- which is what makes repairing
# an already-published certificate free:
#
#   sudo sh scripts/setup-origin.sh --all      # every name this box serves
#
# The registry signs. pit.moshcode.sh runs a certificate authority for the
# names it holds (moshcode apps/pwa/docs/moshpit-ca.md): with MOSHPIT_API_KEY
# set this sends it a CSR for the name and serves the chain it returns, so any
# client that trusts the pit's root -- TronBrowser, a box that ran `moshcode dns
# enable` -- accepts the name with no pin lookup and no per-name import. The
# leaf lasts 30 days; a timer this script installs renews it. The pin is still
# published (the key is the same), so clients that check pins keep working.
#
#   MOSHPIT_API_KEY=... sh setup-origin.sh chovy.hacker --target dev.profullstack.com
#
# Without a key, or with --self-signed, the certificate is self-signed as it
# always was: identity then comes from the registry publishing
# SHA-256(SubjectPublicKeyInfo) and clients checking the key against it, and
# the script prints the pin and where to paste it. Get a key at
# app.moshcode.sh/settings.
set -eu

NAME="${1:-}"
CERTDIR="${MOSHPIT_CERTDIR:-/etc/ssl/moshpit}"
SITEDIR="${MOSHPIT_SITEDIR:-/etc/nginx/sites-available}"
ENABLEDIR="${MOSHPIT_ENABLEDIR:-/etc/nginx/sites-enabled}"
WEBROOT="${MOSHPIT_WEBROOT:-/var/www/$NAME}"
DAYS="${MOSHPIT_DAYS:-825}"
TEMPLATE="${MOSHPIT_TEMPLATE:-$(dirname "$0")/../nginx/moshpit-origin.conf}"
API_KEY="${MOSHPIT_API_KEY:-}"
REGISTRY="${MOSHPIT_REGISTRY:-https://app.moshcode.sh}"
SELF_SIGNED="${MOSHPIT_SELF_SIGNED:-0}"
RENEW_ENV="${MOSHPIT_RENEW_ENV:-/etc/moshpit/renew.env}"
TARGET=""
DRY_RUN=0
TRUST_LOCAL=1

RED=''; BOLD=''; DIM=''; OFF=''
if [ -t 2 ]; then RED=$(printf '\033[31m'); BOLD=$(printf '\033[1m'); DIM=$(printf '\033[2m'); OFF=$(printf '\033[0m'); fi
say()  { printf '%s\n' "$*" >&2; }
step() { printf '%s==>%s %s\n' "$BOLD" "$OFF" "$*" >&2; }
warn() { printf '%swarning:%s %s\n' "$RED" "$OFF" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$RED" "$OFF" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() {
  cat >&2 <<EOF
usage: setup-origin.sh <name|--all> [options]

  --all              re-issue every name this box already has a key for
  --no-trust         do not trust the certificate on this machine
  --self-signed      keep the self-signed certificate; do not ask the registry to sign
  --dry-run          write nothing, print what would happen
  --days <n>         certificate lifetime  (default: $DAYS)
  --webroot <dir>    site files            (default: /var/www/<name>)
  --api-key <token>  publish the pin instead of printing it for a human
  --target <addr>    also set the name's "points at" (needs --api-key)
  --registry <url>   registry base         (default: $REGISTRY)

An IPv4 literal is refused by the registry by design -- point a name at an
IPv6 address or a hostname. A hostname is how a name reaches IPv4 clients,
since the address behind it is resolved normally.

environment: MOSHPIT_CERTDIR, MOSHPIT_SITEDIR, MOSHPIT_ENABLEDIR, MOSHPIT_WEBROOT,
             MOSHPIT_API_KEY, MOSHPIT_REGISTRY, MOSHPIT_SELF_SIGNED, MOSHPIT_RENEW_ENV
EOF
}

# Before the name is consumed, or `--help` is read as the name and the script
# dies telling you that `--help` is not a Moshpit name.
case "$NAME" in -h|--help) usage; exit 0 ;; esac

# `--all` re-issues every name this box already serves, which is what makes
# repairing a fleet of CA:TRUE certificates one command rather than one command
# per name — and the names are already on disk, so there is nothing to type and
# nothing to get wrong. Every key is reused, so no pin moves and the registry
# does not need to hear about any of this.
#
# Done by re-invoking rather than by looping the body: each name gets the same
# validation, the same nginx reload and the same proof-of-serving it would get
# on its own, instead of a second code path that drifts from the first.
if [ "$NAME" = "--all" ]; then
  shift
  found=0
  for _key in "$CERTDIR"/*.key; do
    [ -f "$_key" ] || continue          # no match: the glob stayed literal
    _name=$(basename "$_key" .key)
    found=$((found + 1))
    step "$_name"
    sh "$0" "$_name" "$@" || die "$_name failed — stopping before the rest"
  done
  [ "$found" != "0" ] || die "no keys in $CERTDIR — nothing to re-issue (name a site instead of --all)"
  exit 0
fi

shift 2>/dev/null || true
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --no-trust) TRUST_LOCAL=0 ;;
    --self-signed) SELF_SIGNED=1 ;;
    --all)     die "--all goes first: sh $0 --all [options]" ;;
    --days)    DAYS="${2:?--days needs a number}"; shift ;;
    --webroot) WEBROOT="${2:?--webroot needs a path}"; shift ;;
    --api-key) API_KEY="${2:?--api-key needs a token}"; shift ;;
    --target)  TARGET="${2:?--target needs an address or hostname}"; shift ;;
    --registry) REGISTRY="${2:?--registry needs a base URL}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
  shift
done

[ -n "$NAME" ] || die "usage: setup-origin.sh <name>   (e.g. chovy.hacker)"
case "$NAME" in
  *.*) ;;
  *) die "'$NAME' does not look like a Moshpit name" ;;
esac
# The name becomes a path -- under $CERTDIR, under $SITEDIR, and (below) under
# /usr/local/share/ca-certificates. A `/` or a `..` in it would write somewhere
# nobody asked for, as root. Nothing legal is lost by refusing them: a hostname
# is letters, digits, dots and dashes.
case "$NAME" in
  *[!a-zA-Z0-9.-]* | .* | *..*)
    die "'$NAME' is not a hostname — letters, digits, dots and dashes only" ;;
esac
have openssl || die "openssl is required"

# Caught here rather than after the certificate exists, so a typo does not leave
# a half-configured name behind.
if [ -n "$TARGET" ] && [ -z "$API_KEY" ]; then
  die "--target needs --api-key (or MOSHPIT_API_KEY) — the target is set through the registry API"
fi
case "$TARGET" in
  *://*) die "--target takes a bare address or hostname, not a URL" ;;
  # An IPv4 literal is refused by the registry by design; saying so here saves a
  # round trip and explains the fix, which the API's own error does not.
  [0-9]*.[0-9]*.[0-9]*.[0-9]*)
    die "--target will not accept an IPv4 literal — use a hostname that resolves to it (the registry stores IPv6 or hostnames)" ;;
esac
[ -f "$TEMPLATE" ] || die "template not found: $TEMPLATE"

if [ "$DRY_RUN" = "0" ] && [ "$(id -u)" != "0" ]; then
  die "needs root to write $CERTDIR and reload nginx (try: sudo sh $0 $NAME)"
fi

# ------------------------------------------------------------------ warn early

# nginx built against OpenSSL below 3.5 has no ML-KEM, and the Groups line in
# the template will stop it from starting. Better to say so now than to hand
# someone a failed reload and a live site that went down with it.
if have nginx; then
  ssl_ver=$(nginx -V 2>&1 | grep -o 'OpenSSL [0-9][0-9.]*' | head -1 | cut -d' ' -f2 || true)
  case "$ssl_ver" in
    3.5*|3.6*|3.7*|3.8*|3.9*|4.*) ;;
    "") warn "could not read nginx's OpenSSL version; if the reload fails, remove the ssl_conf_command line" ;;
    *)  warn "nginx is built against OpenSSL $ssl_ver — no ML-KEM below 3.5."
        warn "the post-quantum line will be commented out; the site still works." ;;
  esac
fi

# ------------------------------------------------------------------ key + cert

step "generating a key and certificate for $NAME"
if [ "$DRY_RUN" = "0" ]; then
  mkdir -p "$CERTDIR"
  chmod 700 "$CERTDIR"
fi

CRT="$CERTDIR/$NAME.crt"
KEY="$CERTDIR/$NAME.key"

# `openssl req -x509` defaults to basicConstraints=CA:TRUE, and that default is
# actively harmful here. This certificate is meant to be trusted directly — it
# is its own anchor, which is the whole point of a pinned self-signed origin —
# and a trust anchor marked CA:TRUE may issue for *any* name. The SAN limits
# what this certificate speaks for; it does not limit what a key trusted as a CA
# can go on to sign. So a client that trusted a CA:TRUE origin certificate would
# be handing that key authority over google.com, not over one Moshpit name.
#
# CA:FALSE plus a single-name SAN is the shape that makes direct trust a small,
# bounded grant: it vouches for this name and can vouch for nothing else.
# `moshcode dns trust` refuses the CA:TRUE shape for exactly this reason.
LEAF_EXT='basicConstraints=critical,CA:FALSE'
LEAF_USE='keyUsage=critical,digitalSignature,keyEncipherment'
LEAF_EKU='extendedKeyUsage=serverAuth'

if [ -f "$KEY" ]; then
  # Reusing the key is the point: the pin is over the key, so a certificate can
  # be regenerated as often as you like and the published pin stays valid. It is
  # also what makes fixing an already-issued CA:TRUE certificate free — re-run
  # this and the pin the registry publishes does not move.
  say "  ${DIM}key already exists — reusing it so the published pin stays valid${OFF}"
  if [ "$DRY_RUN" = "0" ]; then
    openssl req -x509 -new -nodes -key "$KEY" -sha256 -days "$DAYS" \
      -subj "/CN=$NAME" -addext "subjectAltName=DNS:$NAME" \
      -addext "$LEAF_EXT" -addext "$LEAF_USE" -addext "$LEAF_EKU" -out "$CRT"
  fi
else
  if [ "$DRY_RUN" = "0" ]; then
    openssl req -x509 -new -nodes \
      -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
      -sha256 -days "$DAYS" \
      -subj "/CN=$NAME" -addext "subjectAltName=DNS:$NAME" \
      -addext "$LEAF_EXT" -addext "$LEAF_USE" -addext "$LEAF_EKU" \
      -keyout "$KEY" -out "$CRT"
    chmod 600 "$KEY"
  fi
fi

# ------------------------------------------------ a certificate from the pit

# The self-signed certificate above is the fallback; this replaces it with one
# the registry signed, when there is a key to ask with and the registry has a
# CA. Same key, so the pin does not move. The chain (leaf, issuer, root) is
# written over $CRT: nginx's ssl_certificate takes a chain file, and serving
# the intermediate is what lets a client that holds only the root verify.
SIGNED=0
if [ "$SELF_SIGNED" = "0" ] && [ -n "$API_KEY" ]; then
  step "asking the registry to sign $NAME"
  _tld="${NAME#*.}"
  _label="${NAME%%.*}"
  if [ "$DRY_RUN" = "1" ]; then
    say "  ${DIM}(dry run) would POST a CSR to $REGISTRY/api/moshpit/tlds/$_tld/certs and serve the chain it returns${OFF}"
  elif ! have curl; then
    warn "curl is required to ask the registry for a certificate — keeping the self-signed one"
  else
    _ca=$(curl -sS --max-time 10 "$REGISTRY/api/moshpit/ca" 2>/dev/null || true)
    case "$_ca" in
      *'"enabled":true'*)
        # One line per PEM line, escaped for JSON by hand: the CSR is base64
        # and dashes, nothing else, so a newline is the only character at issue.
        _csr=$(openssl req -new -key "$KEY" -subj "/CN=$NAME" 2>/dev/null | awk '{printf "%s\\n", $0}')
        _resp=$(curl -sS --max-time 30 -X POST "$REGISTRY/api/moshpit/tlds/$_tld/certs" \
          -H "authorization: Bearer $API_KEY" -H "content-type: application/json" \
          -d "{\"label\":\"$_label\",\"csr\":\"$_csr\"}" -w '\n%{http_code}' 2>&1 || true)
        _code=$(printf '%s' "$_resp" | tail -n1)
        _body=$(printf '%s' "$_resp" | sed '$d')
        case "$_code" in
          201)
            printf '%s' "$_body" | sed -n 's/.*"chain":"\([^"]*\)".*/\1/p' | sed 's/\\n/\
/g' > "$CRT.new"
            if [ "$(grep -c 'BEGIN CERTIFICATE' "$CRT.new" 2>/dev/null)" -ge 2 ] \
               && openssl x509 -in "$CRT.new" -noout -checkhost "$NAME" 2>/dev/null | grep -q 'match'; then
              mv "$CRT.new" "$CRT"
              chmod 644 "$CRT"
              SIGNED=1
              _until=$(openssl x509 -in "$CRT" -noout -enddate 2>/dev/null | sed 's/notAfter=//')
              say "  ${DIM}signed by the pit — serving the chain from $CRT, until $_until${OFF}"
              printf '%s' "$_body" | sed -n 's/.*"root":"\([^"]*\)".*/\1/p' | sed 's/\\n/\
/g' > "$CERTDIR/moshpit-root-ca.crt"
              # What the renewal timer needs, root-only, never in the site dir.
              mkdir -p "$(dirname "$RENEW_ENV")"
              ( umask 077; printf 'MOSHPIT_API_KEY=%s\nMOSHPIT_REGISTRY=%s\nMOSHPIT_CERTDIR=%s\n' "$API_KEY" "$REGISTRY" "$CERTDIR" > "$RENEW_ENV" )
            else
              rm -f "$CRT.new"
              warn "the registry's answer did not parse as a chain for $NAME — keeping the self-signed certificate"
            fi ;;
          503)
            say "  ${DIM}the registry has no CA configured — keeping the self-signed certificate${OFF}" ;;
          *)
            warn "the registry refused to sign $NAME ($_code): $_body"
            warn "keeping the self-signed certificate; the pin below still covers it" ;;
        esac ;;
      *)
        say "  ${DIM}the registry publishes no CA yet — keeping the self-signed certificate${OFF}" ;;
    esac
  fi
fi

# ------------------------------------------------------------------ nginx

step "writing the nginx server block"
CONF="$SITEDIR/$NAME"
if [ "$DRY_RUN" = "0" ]; then
  mkdir -p "$SITEDIR" "$ENABLEDIR" "$WEBROOT"
  sed -e "s|NAME|$NAME|g" -e "s|/var/www/$NAME|$WEBROOT|g" "$TEMPLATE" > "$CONF"

  case "$ssl_ver" in
    3.5*|3.6*|3.7*|3.8*|3.9*|4.*|"") ;;
    *) sed -i 's|^\( *\)ssl_conf_command Groups|\1# ssl_conf_command Groups|' "$CONF" ;;
  esac

  [ -e "$ENABLEDIR/$NAME" ] || ln -s "$CONF" "$ENABLEDIR/$NAME"
  [ -f "$WEBROOT/index.html" ] || printf '<!doctype html><meta charset=utf-8><title>%s</title><h1>%s</h1><p>served over Moshpit.\n' "$NAME" "$NAME" > "$WEBROOT/index.html"

  nginx -t || die "nginx rejected the config — nothing was reloaded, the old site is still up"
  nginx -s reload || die "nginx reload failed"
fi

# ------------------------------------------------------------------ prove it

# Not ceremony. nginx will happily reload with a block that never matches, and
# the failure mode is the default vhost answering with someone else's
# certificate — which is exactly the bug this script exists to fix. So ask the
# running server what it actually presents for this name.
if [ "$DRY_RUN" = "0" ]; then
  # Adding a block to a box that already serves other sites can silently steal
  # the default vhost. nginx picks the first-parsed server for a listen address
  # when nothing is marked `default_server`, and files in sites-enabled are
  # parsed in filename order -- so `chovy.hacker` sorts ahead of `userdirs.conf`
  # and becomes the default. Every request with no SNI or an unmatched Host then
  # gets this name's self-signed certificate instead of whatever the box used to
  # answer with, which looks like the *other* sites broke.
  #
  # Found by doing exactly this to a live server.
  if [ "$(nginx -T 2>/dev/null | grep -c 'listen.*443.*default_server')" = "0" ]; then
    warn "no server block on this box marks itself \`default_server\` for 443."
    warn "adding $NAME may have taken over as the default vhost, so requests"
    warn "with no SNI or an unmatched Host now get its self-signed certificate."
    warn "fix by marking the intended default, e.g. \`listen 443 ssl default_server;\`"
  fi

  step "checking what the server now presents for $NAME"

  # Retried, because `nginx -s reload` returns as soon as the signal is sent,
  # not when the new workers are serving. The old workers finish their existing
  # connections first, so a check fired immediately gets answered by the config
  # from *before* the reload — which looks exactly like the default-vhost bug
  # this is here to catch. Found the hard way: the first live run of this script
  # reported a name mismatch that had already been fixed.
  presented=""
  attempt=1
  while [ "$attempt" -le 5 ]; do
    presented=$(echo | openssl s_client -connect 127.0.0.1:443 -servername "$NAME" 2>/dev/null \
      | openssl x509 -noout -subject 2>/dev/null || true)
    case "$presented" in
      *"$NAME"*) break ;;
    esac
    sleep 1
    attempt=$((attempt + 1))
  done

  case "$presented" in
    *"$NAME"*) say "  ${DIM}$presented${OFF}" ;;
    "")        warn "could not read a certificate back from 127.0.0.1:443" ;;
    *)         warn "after 5 tries the server still answers '$NAME' with: $presented"
               warn "another server block is matching first — check for a default_server" ;;
  esac
fi

# ------------------------------------------------------- trust it on this box

# The machine that serves a Moshpit name is also, usually, a machine somebody
# browses it from — and until now `curl https://<name>` on the origin itself
# failed to verify, which reads as "this site is broken" rather than "no CA will
# ever sign for this ending".
#
# The pinned-TLS proxy is the general answer to that, but it cannot be the
# answer *here*: it works by owning port 443 on loopback, and on an origin nginx
# already has 443. Two listeners cannot share it — a second bind gets EADDRINUSE
# — so on this one class of machine the proxy can never be on the path.
#
# Trusting the certificate directly needs no port and no proxy, and CA:FALSE
# above is what makes it a bounded grant: it vouches for this one name and can
# vouch for nothing else. The file name matches what `moshcode dns trust`
# writes, so the two agree instead of each leaving a copy the other ignores.
if [ "$TRUST_LOCAL" = "1" ] && [ "$DRY_RUN" = "0" ]; then
  step "trusting $NAME on this machine"

  # Read back what is on disk rather than believing the variables above. This is
  # the one step that installs a trust anchor, and a certificate that is not the
  # bounded shape must not be installed merely because this run meant to write
  # one. An older CA:TRUE certificate arriving here is precisely the case to
  # refuse: trusted as an anchor, its key could vouch for any name at all.
  if [ "$SIGNED" = "1" ]; then
    # Signed by the pit: the thing to trust here is its root, once, the same
    # file and name `moshcode dns enable` installs. The leaf is ordinary.
    case "$(uname -s)" in
      Darwin)
        if security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$CERTDIR/moshpit-root-ca.crt" 2>/dev/null; then
          say "  ${DIM}Moshpit Root CA trusted in the system keychain${OFF}"
        else
          warn "could not add the Moshpit Root CA to the system keychain"
        fi ;;
      *)
        if have update-ca-certificates; then
          if mkdir -p /usr/local/share/ca-certificates \
             && cp "$CERTDIR/moshpit-root-ca.crt" /usr/local/share/ca-certificates/moshpit-root-ca.crt \
             && update-ca-certificates >/dev/null 2>&1; then
            say "  ${DIM}Moshpit Root CA trusted in the system store — curl https://$NAME verifies here now${OFF}"
          else
            warn "could not install the Moshpit Root CA into the system trust store"
          fi
        else
          warn "no update-ca-certificates here — skipping local trust"
        fi ;;
    esac
  elif openssl x509 -in "$CRT" -noout -ext basicConstraints 2>/dev/null | grep -q 'CA:FALSE'; then
    case "$(uname -s)" in
      Darwin)
        if security add-trusted-cert -d -r trustRoot \
             -k /Library/Keychains/System.keychain "$CRT" 2>/dev/null; then
          say "  ${DIM}trusted in the system keychain${OFF}"
        else
          warn "could not add $NAME to the system keychain"
        fi ;;
      *)
        if have update-ca-certificates; then
          if mkdir -p /usr/local/share/ca-certificates \
             && cp "$CRT" "/usr/local/share/ca-certificates/moshpit-$NAME.crt" \
             && update-ca-certificates >/dev/null 2>&1; then
            say "  ${DIM}trusted in the system store — curl https://$NAME verifies here now${OFF}"
          else
            warn "could not install $NAME into the system trust store"
          fi
        else
          warn "no update-ca-certificates here — skipping local trust for $NAME"
        fi ;;
    esac
  else
    warn "$CRT is not CA:FALSE, so it was not trusted on this machine."
    warn "a certificate trusted as a CA can vouch for any name, not just $NAME."
    warn "re-run this script to re-issue it — the key is reused, so the pin does not change."
  fi
fi

# ------------------------------------------------------------- renewal

# A 30-day leaf without a renewal is an outage with a date on it. The timer
# runs moshpit-renew.sh daily, which re-runs this script for any registry-signed
# name within ten days of expiry. Installed here, by the run that made the
# first signed certificate, rather than left as a step for someone to remember.
if [ "$SIGNED" = "1" ] && [ "$DRY_RUN" = "0" ] && have systemctl; then
  _units="$(dirname "$0")/../systemd"
  if [ -f "$_units/moshpit-renew.timer" ] && [ ! -f /etc/systemd/system/moshpit-renew.timer ]; then
    step "installing the renewal timer"
    if cp "$_units/moshpit-renew.service" "$_units/moshpit-renew.timer" /etc/systemd/system/ 2>/dev/null \
       && systemctl daemon-reload 2>/dev/null && systemctl enable --now moshpit-renew.timer >/dev/null 2>&1; then
      say "  ${DIM}moshpit-renew.timer — daily; renews within ten days of expiry${OFF}"
    else
      warn "could not enable moshpit-renew.timer — the certificate for $NAME expires in 30 days unless this is re-run"
    fi
  fi
fi

# ------------------------------------------------------------------ the pin

step "the pin to publish"
if [ "$DRY_RUN" = "0" ]; then
  PIN=$(openssl x509 -in "$CRT" -pubkey -noout \
    | openssl pkey -pubin -outform der \
    | openssl dgst -sha256 -binary \
    | openssl base64 -A)
else
  PIN="(dry run — no key was generated)"
fi

TLD="${NAME#*.}"
LABEL="${NAME%%.*}"

# ------------------------------------------------------- publish it, or don't

# `/api/moshpit` accepts a bearer token as well as a cookie session, so the last
# step does not have to be a human in a browser. Without a key this prints the
# pin and where to paste it, which is all it ever did.
if [ -n "$API_KEY" ] && [ "$DRY_RUN" = "0" ]; then
  have curl || die "curl is required to publish (or drop --api-key and paste it yourself)"

  # `-w` appends the status on its own line so the body stays intact; the API
  # explains its own failures, and swallowing that is how the dashboard turned
  # "you do not own this" into a form that silently did nothing.
  api() {
    _method="$1"; _path="$2"; _body="$3"
    curl -sS -X "$_method" "$REGISTRY$_path" \
      -H "authorization: Bearer $API_KEY" \
      -H "content-type: application/json" \
      -d "$_body" -w '\n%{http_code}' 2>&1
  }
  ok_status() { case "$1" in 2*) return 0 ;; *) return 1 ;; esac; }
  report() {
    _what="$1"; _out="$2"
    _code=$(printf '%s' "$_out" | tail -n1)
    _body=$(printf '%s' "$_out" | sed '$d')
    if ok_status "$_code"; then
      say "  ${DIM}$_what — ok ($_code)${OFF}"
      return 0
    fi
    warn "$_what failed ($_code): $_body"
    return 1
  }

  if [ -n "$TARGET" ]; then
    step "pointing $NAME at $TARGET"
    report "target" "$(api PUT "/api/moshpit/tlds/$TLD/names" \
      "{\"label\":\"$LABEL\",\"target\":\"$TARGET\"}")" || true
  fi

  step "publishing the pin"
  # 409 means this exact pin is already published under a different kind, which
  # is a real mistake worth surfacing rather than a retry.
  report "pin" "$(api POST "/api/moshpit/tlds/$TLD/pins" \
    "{\"label\":\"$LABEL\",\"pin\":\"$PIN\",\"kind\":\"tls\",\"note\":\"setup-origin.sh\"}")" || true

  # Read it back. A 201 means the write was accepted; only a read proves the
  # thing clients actually query now returns it.
  step "confirming the registry serves it"
  published=$(curl -sS "$REGISTRY/api/moshpit/tlds/$TLD/pins?label=$LABEL" 2>/dev/null || true)
  case "$published" in
    *"$PIN"*) say "  ${DIM}$NAME is published and verifiable${OFF}" ;;
    *)        warn "the registry does not list this pin yet: $published"
              warn "clients will keep refusing $NAME until it does" ;;
  esac
else
  cat >&2 <<EOF

  ${BOLD}$NAME${OFF}
  $PIN

  Publish it at https://app.moshcode.sh/pit
  ${DIM}or re-run with MOSHPIT_API_KEY set and this happens by itself —
  get a key at ${REGISTRY}/settings${OFF}

  Until you do, every client refuses this name — that is the design, not a
  fault. There is no trust-on-first-use and no unauthenticated mode, because
  the pin is the only thing standing where a certificate authority would be.

  ${DIM}Rotating later? Publish the new pin alongside the old one, switch the
  server, then drop the old one. Clients accept any pin in the list.${OFF}
EOF
fi
