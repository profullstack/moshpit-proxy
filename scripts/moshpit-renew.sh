#!/bin/sh
# Renew the certificates the registry signed for this box, before they run out.
#
# setup-origin.sh asks the pit for a 30-day leaf and installs moshpit-renew.timer
# to run this daily. For every name under $CERTDIR whose certificate was signed
# by the registry (issuer is not the name itself) and expires within
# MOSHPIT_RENEW_DAYS (10), it re-runs setup-origin.sh with the key it kept, which
# asks for a fresh leaf, writes the chain, and reloads nginx. A self-signed name
# is asked about again on every run (a failed signing must not stick), unless
# $CERTDIR/<name>.self-signed marks it as self-signed on purpose.
#
# Needs the API key setup-origin.sh saved at $RENEW_ENV (root-only). Without
# that file this does nothing and says so, which is the state of a box that
# never had a registry-signed certificate.
set -eu

RENEW_ENV="${MOSHPIT_RENEW_ENV:-/etc/moshpit/renew.env}"
if [ ! -f "$RENEW_ENV" ]; then
  echo "moshpit-renew: no $RENEW_ENV — nothing here was signed by the registry"
  exit 0
fi
# shellcheck disable=SC1090
. "$RENEW_ENV"
CERTDIR="${MOSHPIT_CERTDIR:-/etc/ssl/moshpit}"
REGISTRY="${MOSHPIT_REGISTRY:-https://app.moshcode.sh}"
API_KEY="${MOSHPIT_API_KEY:-}"
DAYS="${MOSHPIT_RENEW_DAYS:-10}"
SETUP="${MOSHPIT_SETUP_ORIGIN:-$(dirname "$0")/setup-origin.sh}"

[ -n "$API_KEY" ] || { echo "moshpit-renew: $RENEW_ENV has no MOSHPIT_API_KEY"; exit 1; }
[ -f "$SETUP" ] || { echo "moshpit-renew: $SETUP is missing"; exit 1; }

renewed=0
failed=0
for crt in "$CERTDIR"/*.crt; do
  [ -f "$crt" ] || continue
  name=$(basename "$crt" .crt)
  case "$name" in moshpit-root-ca|moshpit-*) continue ;; esac
  [ -f "$CERTDIR/$name.key" ] || continue
  issuer=$(openssl x509 -in "$crt" -noout -issuer 2>/dev/null || true)
  case "$issuer" in
    *"CN=$name"|*"CN = $name")
      # Self-signed on a box that has a registry key almost always means one
      # signing attempt failed (registry down, CA fetch timed out) and the name
      # fell back. Skipping it here left it self-signed forever, and pit.world
      # answered 502 for it. Ask again. A name meant to stay self-signed says
      # so with an empty $CERTDIR/<name>.self-signed.
      if [ -f "$CERTDIR/$name.self-signed" ]; then continue; fi
      echo "moshpit-renew: $name — self-signed, asking the registry to sign it"
      if MOSHPIT_API_KEY="$API_KEY" MOSHPIT_REGISTRY="$REGISTRY" MOSHPIT_CERTDIR="$CERTDIR" \
         sh "$SETUP" "$name" --no-trust \
         && ! openssl x509 -in "$crt" -noout -issuer 2>/dev/null | grep -Eq "CN ?= ?$name\$"; then
        renewed=$((renewed + 1))
      else
        echo "moshpit-renew: $name — still self-signed"
        failed=$((failed + 1))
      fi
      continue ;;
  esac
  if openssl x509 -in "$crt" -noout -checkend $((DAYS * 86400)) >/dev/null 2>&1; then
    echo "moshpit-renew: $name — fine ($(openssl x509 -in "$crt" -noout -enddate | sed 's/notAfter=//'))"
    continue
  fi
  echo "moshpit-renew: $name — renewing"
  if MOSHPIT_API_KEY="$API_KEY" MOSHPIT_REGISTRY="$REGISTRY" MOSHPIT_CERTDIR="$CERTDIR" \
     sh "$SETUP" "$name" --no-trust; then
    renewed=$((renewed + 1))
  else
    echo "moshpit-renew: $name — renewal failed"
    failed=$((failed + 1))
  fi
done
echo "moshpit-renew: $renewed renewed, $failed failed"
[ "$failed" = "0" ]
