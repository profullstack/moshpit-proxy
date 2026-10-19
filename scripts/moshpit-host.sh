#!/bin/sh
# Host a Moshpit name for a customer on this box: their account, their folder, the name's certificate.
#
#   sudo sh scripts/moshpit-host.sh alice shop.alice --key "ssh-ed25519 AAAA... alice@laptop"
#
# A name that does not exist yet is registered first, under an ending the box key holds.
#
# This is the one-time half of a Moshpit server ($5 a month, unlimited sites). It
# makes the Unix account if it is new (key-only, password locked), adds the SSH key,
# creates ~/apps/<name>/public, and runs setup-origin.sh for the name with that
# folder as its webroot and this box as the name's target. After that the customer
# ships with `moshcode deploy <name>` from their own machine, as often as they like,
# and nothing here needs to run again. Another name for the same customer is another
# run of this script.
#
# The registry signs with the key in $RENEW_ENV, the box's own: the name must be held
# by that key's account, because the daily renewal (moshpit-renew.sh) signs with it too.
# Re-running is safe: the account, key and folder are kept, and setup-origin.sh reuses
# the name's key so its pin does not move.
set -eu

RENEW_ENV="${MOSHPIT_RENEW_ENV:-/etc/moshpit/renew.env}"
SETUP="${MOSHPIT_SETUP_ORIGIN:-$(dirname "$0")/setup-origin.sh}"
TARGET="${MOSHPIT_HOST_TARGET:-$(hostname -f)}"
HOMES="${MOSHPIT_HOMES:-/home}"

die() { printf 'moshpit-host: %s\n' "$*" >&2; exit 1; }

usage() {
  cat >&2 <<EOF
usage: moshpit-host.sh <user> <name> [--key "<ssh public key>"] [--dry-run]

  <user>   the customer's account on this box (made if new)
  <name>   the Moshpit name to serve from /home/<user>/apps/<name>/public
  --key    an SSH public key to let in (added once; repeat the run to add more)

environment: MOSHPIT_RENEW_ENV, MOSHPIT_SETUP_ORIGIN, MOSHPIT_HOST_TARGET (default: hostname -f)
EOF
}

case "${1:-}" in -h|--help|'') usage; exit 0 ;; esac
USER_NAME="$1"; NAME="${2:-}"; shift; shift 2>/dev/null || true
KEY=""; DRY_RUN=0
while [ $# -gt 0 ]; do
  case "$1" in
    --key) KEY="${2:?--key needs a public key}"; shift ;;
    --dry-run) DRY_RUN=1 ;;
    *) usage; die "unknown option: $1" ;;
  esac
  shift
done

printf '%s' "$USER_NAME" | grep -Eq '^[a-z_][a-z0-9_-]{0,31}$' || die "not a valid account name: $USER_NAME"
# The same shape `moshcode deploy` accepts: lowercase labels, at least one dot, none empty.
printf '%s' "$NAME" | grep -Eq '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$' || die "not a Moshpit name: $NAME"
case "$NAME" in *.pit.world) die "$NAME is the relay's address; pass the name itself (${NAME%.pit.world})" ;; esac
if [ -n "$KEY" ]; then
  printf '%s' "$KEY" | grep -Eq '^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh.com) [A-Za-z0-9+/=]+( .*)?$' \
    || die "--key does not look like one SSH public key line"
fi

HOME_DIR="$HOMES/$USER_NAME"
SITE="$HOME_DIR/apps/$NAME"

if [ "$DRY_RUN" = 1 ]; then
  echo "account   $USER_NAME ($(id -u "$USER_NAME" >/dev/null 2>&1 && echo exists || echo new))"
  echo "folder    $SITE/public"
  echo "origin    sh $SETUP $NAME --webroot $SITE/public --api-key <from $RENEW_ENV> --target $TARGET"
  exit 0
fi

[ "$(id -u)" = 0 ] || die "run as root (it makes accounts and nginx blocks)"
[ -f "$SETUP" ] || die "$SETUP is missing"
[ -f "$RENEW_ENV" ] || die "no $RENEW_ENV: this box has no registry key, so it cannot sign or point $NAME"
# shellcheck disable=SC1090
. "$RENEW_ENV"
[ -n "${MOSHPIT_API_KEY:-}" ] || die "$RENEW_ENV has no MOSHPIT_API_KEY"
REGISTRY="${MOSHPIT_REGISTRY:-https://app.moshcode.sh}"

# Register the name first if it is new: the registry signs, points and pins only names that
# exist. 201 is made, 409 is taken (by this account, fine: setup-origin's retarget proves it;
# by anyone else, that call fails loudly), anything else stops here.
TLD="${NAME##*.}"; LABEL="${NAME%.*}"
status=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 30 -X POST "$REGISTRY/api/moshpit/tlds/$TLD/names" \
  -H "authorization: Bearer $MOSHPIT_API_KEY" -H 'content-type: application/json' \
  --data "{\"label\":\"$LABEL\",\"target\":\"$TARGET\"}") || die "the registry did not answer"
case "$status" in
  201) echo "registered $NAME" ;;
  409) ;;
  *) die "could not register $NAME (HTTP $status): this box's key must hold .$TLD" ;;
esac

if ! id -u "$USER_NAME" >/dev/null 2>&1; then
  useradd --create-home --home-dir "$HOME_DIR" --shell /bin/bash "$USER_NAME"
  passwd --lock "$USER_NAME" >/dev/null
  echo "made account $USER_NAME (key-only)"
fi

if [ -n "$KEY" ]; then
  install -d -m 700 -o "$USER_NAME" -g "$USER_NAME" "$HOME_DIR/.ssh"
  AUTH="$HOME_DIR/.ssh/authorized_keys"
  touch "$AUTH"
  grep -qxF "$KEY" "$AUTH" || printf '%s\n' "$KEY" >> "$AUTH"
  chown "$USER_NAME:$USER_NAME" "$AUTH"; chmod 600 "$AUTH"
fi

# nginx reads the webroot as another user: the home must be traversable, not listable.
chmod o+x "$HOME_DIR"
install -d -o "$USER_NAME" -g "$USER_NAME" "$HOME_DIR/apps" "$SITE" "$SITE/public"

sh "$SETUP" "$NAME" --webroot "$SITE/public" --api-key "$MOSHPIT_API_KEY" --target "$TARGET"

# setup-origin.sh writes a placeholder index.html as root; the folder is the customer's.
chown -R "$USER_NAME:$USER_NAME" "$SITE"

cat <<EOF

$NAME is hosted here for $USER_NAME. From their machine:

  moshcode deploy $NAME --host $TARGET --user $USER_NAME

It opens at https://$NAME/ on Moshpit DNS and https://$NAME.pit.world/ everywhere else.
EOF
