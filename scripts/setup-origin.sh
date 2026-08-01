#!/bin/sh
# Put a Moshpit name on this box: key, certificate, nginx block, and the pin.
#
#   sudo sh scripts/setup-origin.sh chovy.hacker
#
# Generates a self-signed key pair for the name, writes an nginx server block
# from nginx/moshpit-origin.conf, reloads, then connects back to itself and
# proves the name now answers with the key it just made. Ends by printing the
# pin to publish.
#
# Self-signed is the design, not a shortcut. No CA will issue for a Moshpit TLD,
# so identity comes from the registry publishing SHA-256(SubjectPublicKeyInfo)
# for the name and clients checking the key they were handed against it. Which
# means the last step is not optional: until the pin is published, every client
# refuses the name rather than trusting it on sight.
#
# With MOSHPIT_API_KEY set, that last step stops being manual:
#
#   MOSHPIT_API_KEY=... sh setup-origin.sh chovy.hacker --target dev.profullstack.com
#
# publishes the pin and sets the target over the registry API, so the whole of
# "serve this name" is one command. Get a key at app.moshcode.sh/settings.
# Without the key nothing changes -- it prints the pin and tells you where to
# paste it, exactly as before.
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
TARGET=""
DRY_RUN=0

RED=''; BOLD=''; DIM=''; OFF=''
if [ -t 2 ]; then RED=$(printf '\033[31m'); BOLD=$(printf '\033[1m'); DIM=$(printf '\033[2m'); OFF=$(printf '\033[0m'); fi
say()  { printf '%s\n' "$*" >&2; }
step() { printf '%s==>%s %s\n' "$BOLD" "$OFF" "$*" >&2; }
warn() { printf '%swarning:%s %s\n' "$RED" "$OFF" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$RED" "$OFF" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() {
  cat >&2 <<EOF
usage: setup-origin.sh <name> [options]

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
             MOSHPIT_API_KEY, MOSHPIT_REGISTRY
EOF
}

# Before the name is consumed, or `--help` is read as the name and the script
# dies telling you that `--help` is not a Moshpit name.
case "$NAME" in -h|--help) usage; exit 0 ;; esac

shift 2>/dev/null || true
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
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

if [ -f "$KEY" ]; then
  # Reusing the key is the point: the pin is over the key, so a certificate can
  # be regenerated as often as you like and the published pin stays valid.
  say "  ${DIM}key already exists — reusing it so the published pin stays valid${OFF}"
  if [ "$DRY_RUN" = "0" ]; then
    openssl req -x509 -new -nodes -key "$KEY" -sha256 -days "$DAYS" \
      -subj "/CN=$NAME" -addext "subjectAltName=DNS:$NAME" -out "$CRT"
  fi
else
  if [ "$DRY_RUN" = "0" ]; then
    openssl req -x509 -new -nodes \
      -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
      -sha256 -days "$DAYS" \
      -subj "/CN=$NAME" -addext "subjectAltName=DNS:$NAME" \
      -keyout "$KEY" -out "$CRT"
    chmod 600 "$KEY"
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
