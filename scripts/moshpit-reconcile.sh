#!/bin/sh
# Serve every Moshpit name pointed at this box, without anybody touching it.
#
# `setup-origin.sh` turned serving one name into one command. This turns it
# into none: it asks the registry which names point here, and configures the
# ones that are not configured yet. Point a name at this host in the dashboard
# and it is being served a minute later — no ssh, no command, no remembering
# that a pin has to be published or the name stays refused.
#
#   sh scripts/moshpit-reconcile.sh                 # act
#   sh scripts/moshpit-reconcile.sh --dry-run       # say what it would do
#   sh scripts/moshpit-reconcile.sh --once          # exit non-zero on any failure
#
# Config, read from /etc/moshpit/reconcile.conf (override with MOSHPIT_CONF):
#
#   MOSHPIT_API_KEY=mck_...              # publishes pins; from /settings
#   MOSHPIT_ENDINGS="hacker rank 2600"   # the endings this box answers for
#   MOSHPIT_HOST=dev.profullstack.com    # what a name must point at to count
#   MOSHPIT_REGISTRY=https://app.moshcode.sh
#
# ENDINGS is listed rather than discovered on purpose. `GET /api/moshpit/tlds`
# returns 200 of the ~5,700 claimed endings — the default page size — so
# discovery would silently serve a subset and look like it had covered
# everything. A box that serves three endings should say so in one line.
#
# Idempotent, and quiet when there is nothing to do: a name is reconfigured
# only when its nginx block is missing or the pin the registry publishes is not
# the key this box actually serves. Without that check every run would reload
# nginx, and a timer would reload it forever.
set -eu

CONF="${MOSHPIT_CONF:-/etc/moshpit/reconcile.conf}"
[ -f "$CONF" ] && . "$CONF"

REGISTRY="${MOSHPIT_REGISTRY:-https://app.moshcode.sh}"
API_KEY="${MOSHPIT_API_KEY:-}"
ENDINGS="${MOSHPIT_ENDINGS:-}"
HOST="${MOSHPIT_HOST:-}"
ENABLEDIR="${MOSHPIT_ENABLEDIR:-/etc/nginx/sites-enabled}"
SETUP="${MOSHPIT_SETUP:-$(dirname "$0")/setup-origin.sh}"
DRY_RUN=0
FAILURES=0

BOLD=''; DIM=''; RED=''; OFF=''
if [ -t 2 ]; then BOLD=$(printf '\033[1m'); DIM=$(printf '\033[2m'); RED=$(printf '\033[31m'); OFF=$(printf '\033[0m'); fi
say()  { printf '%s\n' "$*" >&2; }
step() { printf '%s==>%s %s\n' "$BOLD" "$OFF" "$*" >&2; }
warn() { printf '%swarning:%s %s\n' "$RED" "$OFF" "$*" >&2; FAILURES=$((FAILURES + 1)); }
die()  { printf '%serror:%s %s\n' "$RED" "$OFF" "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --once) : ;;  # accepted for the systemd unit; the script is always one pass
    -h|--help) sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
  shift
done

[ -n "$API_KEY" ] || die "no MOSHPIT_API_KEY — set it in $CONF (get one at $REGISTRY/settings)"
[ -n "$ENDINGS" ] || die "no MOSHPIT_ENDINGS — list the endings this box serves in $CONF"
[ -n "$HOST" ]    || die "no MOSHPIT_HOST — set what a name must point at to count as ours"
[ -f "$SETUP" ]   || die "cannot find setup-origin.sh at $SETUP (set MOSHPIT_SETUP)"

# The addresses HOST has right now. A name may point at the hostname or at a
# literal, and both mean this box — comparing only the string would skip names
# pointed at the address and leave them silently unserved.
OURS="$HOST
$(getent ahosts "$HOST" 2>/dev/null | awk '{print $1}' | sort -u)"

points_here() {
  case "$1" in "") return 1 ;; esac
  for ours in $OURS; do
    [ "$1" = "$ours" ] && return 0
  done
  return 1
}

# The pin this box serves for a name, computed the same way the registry's
# publisher computes it. Empty when nothing is listening for that name.
served_pin() {
  echo | openssl s_client -connect "127.0.0.1:443" -servername "$1" 2>/dev/null \
    | openssl x509 -pubkey -noout 2>/dev/null \
    | openssl pkey -pubin -outform der 2>/dev/null \
    | openssl dgst -sha256 -binary 2>/dev/null \
    | openssl enc -base64 2>/dev/null
}

published_pin() {
  curl -fsS --max-time 15 "$REGISTRY/api/moshpit/tlds/$2/pins?label=$1" 2>/dev/null \
    | grep -o '"pin":"[^"]*"' | head -1 | cut -d'"' -f4
}

# One field out of a flat JSON object. Enough for these payloads, and it keeps
# this a POSIX shell script with no runtime to install on an origin box.
json_field() { grep -o "\"$1\":\"[^\"]*\"" | head -1 | cut -d'"' -f4; }

reconcile_name() {
  name="$1"; label="$2"; tld="$3"

  need=""
  [ -f "$ENABLEDIR/$name" ] || need="no nginx block"
  if [ -z "$need" ]; then
    serving="$(served_pin "$name")"
    publish="$(published_pin "$label" "$tld")"
    if [ -z "$serving" ]; then
      need="nothing is served for it"
    elif [ -z "$publish" ]; then
      need="no pin published"
    elif [ "$serving" != "$publish" ]; then
      # The published pin is what clients enforce, so a mismatch refuses the
      # name outright. Worth naming both, because the usual cause is a
      # certificate regenerated without republishing.
      need="published pin does not match what is served ($publish vs $serving)"
    fi
  fi

  if [ -z "$need" ]; then
    say "  ${DIM}$name — already served${OFF}"
    return 0
  fi

  step "$name — $need"
  if [ "$DRY_RUN" = "1" ]; then
    say "  ${DIM}would run: setup-origin.sh $name --target $HOST${OFF}"
    return 0
  fi

  if MOSHPIT_API_KEY="$API_KEY" sh "$SETUP" "$name" --target "$HOST" --registry "$REGISTRY" >&2; then
    say "  ${DIM}$name — now served${OFF}"
  else
    warn "$name — setup-origin.sh failed; leaving it alone and carrying on"
  fi
}

RECORDS="$(mktemp)"
trap 'rm -f "$RECORDS"' EXIT INT TERM

step "reconciling against $REGISTRY as $HOST"

for tld in $ENDINGS; do
  body="$(curl -fsS --max-time 20 "$REGISTRY/api/moshpit/tlds/$tld/names" 2>/dev/null)" || {
    # A registry that is briefly unreachable must not take the box's existing
    # names down, and must not look like "no names are pointed here".
    warn ".$tld — registry unreachable, skipping this pass"
    continue
  }

  # One record per line, so the loop never has to parse nested JSON.
  #
  # Via a file rather than a pipe into `while`: a piped loop runs in a subshell,
  # where the failure count increments a copy and the exit status below would
  # always be 0 — the script would report success for a pass that fixed nothing.
  printf '%s' "$body" | tr '{' '\n' | grep '"label"' > "$RECORDS" || true
  while IFS= read -r record; do
    label="$(printf '%s' "$record" | json_field label)"
    target="$(printf '%s' "$record" | json_field target)"
    [ -n "$label" ] || continue
    points_here "$target" || continue
    reconcile_name "$label.$tld" "$label" "$tld"
  done < "$RECORDS"
done

if [ "$FAILURES" -gt 0 ]; then
  say ""
  warn "$FAILURES name(s) could not be reconciled this pass"
  exit 1
fi
