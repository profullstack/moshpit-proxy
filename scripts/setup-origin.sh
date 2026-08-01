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
set -eu

NAME="${1:-}"
CERTDIR="${MOSHPIT_CERTDIR:-/etc/ssl/moshpit}"
SITEDIR="${MOSHPIT_SITEDIR:-/etc/nginx/sites-available}"
ENABLEDIR="${MOSHPIT_ENABLEDIR:-/etc/nginx/sites-enabled}"
WEBROOT="${MOSHPIT_WEBROOT:-/var/www/$NAME}"
DAYS="${MOSHPIT_DAYS:-825}"
TEMPLATE="${MOSHPIT_TEMPLATE:-$(dirname "$0")/../nginx/moshpit-origin.conf}"
DRY_RUN=0

RED=''; BOLD=''; DIM=''; OFF=''
if [ -t 2 ]; then RED=$(printf '\033[31m'); BOLD=$(printf '\033[1m'); DIM=$(printf '\033[2m'); OFF=$(printf '\033[0m'); fi
say()  { printf '%s\n' "$*" >&2; }
step() { printf '%s==>%s %s\n' "$BOLD" "$OFF" "$*" >&2; }
warn() { printf '%swarning:%s %s\n' "$RED" "$OFF" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$RED" "$OFF" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

shift 2>/dev/null || true
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --days)    DAYS="${2:?--days needs a number}"; shift ;;
    --webroot) WEBROOT="${2:?--webroot needs a path}"; shift ;;
    -h|--help)
      cat >&2 <<EOF
usage: setup-origin.sh <name> [options]

  --dry-run          write nothing, print what would happen
  --days <n>         certificate lifetime  (default: $DAYS)
  --webroot <dir>    site files            (default: /var/www/<name>)

environment: MOSHPIT_CERTDIR, MOSHPIT_SITEDIR, MOSHPIT_ENABLEDIR, MOSHPIT_WEBROOT
EOF
      exit 0 ;;
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
  step "checking what the server now presents for $NAME"
  presented=$(echo | openssl s_client -connect 127.0.0.1:443 -servername "$NAME" 2>/dev/null \
    | openssl x509 -noout -subject 2>/dev/null || true)
  case "$presented" in
    *"$NAME"*) say "  ${DIM}$presented${OFF}" ;;
    "")        warn "could not read a certificate back from 127.0.0.1:443" ;;
    *)         warn "the server answered '$NAME' with: $presented"
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

cat >&2 <<EOF

  ${BOLD}$NAME${OFF}
  $PIN

  Publish it at https://app.moshcode.sh/pit/dns

  Until you do, every client refuses this name — that is the design, not a
  fault. There is no trust-on-first-use and no unauthenticated mode, because
  the pin is the only thing standing where a certificate authority would be.

  ${DIM}Rotating later? Publish the new pin alongside the old one, switch the
  server, then drop the old one. Clients accept any pin in the list.${OFF}
EOF
