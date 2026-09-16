#!/bin/sh
# Renew the certificates the registry signed for this box, before they run out.
#
# setup-origin.sh asks the pit for a 30-day leaf and installs moshpit-renew.timer
# to run this daily. For every name under $CERTDIR whose certificate was signed
# by the registry (issuer is not the name itself) and expires within
# MOSHPIT_RENEW_DAYS (10), it re-runs setup-origin.sh with the key it kept, which
# asks for a fresh leaf, writes the chain, and reloads nginx. Self-signed names
# are left alone: their certificates last years and have nothing to renew from.
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
    *"CN=$name"*|*"CN = $name"*) continue ;;   # self-signed: nothing to renew from
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
