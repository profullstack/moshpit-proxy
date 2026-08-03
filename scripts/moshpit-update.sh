#!/bin/sh
# Keep /opt/moshpit at the tip of this repo, so merging ships.
#
# It did not. /opt/moshpit was a hand-copied nginx/ and scripts/, which meant a
# merged fix reached the box only when somebody remembered to copy it — and the
# symptom of forgetting is not an error, it is the fix appearing not to work.
# A whole afternoon went into that: the origin template still redirected to
# HTTPS on a box whose repo had stopped doing so, and every reconcile pass
# faithfully re-applied the old one.
#
#   sh scripts/moshpit-update.sh              # pull and apply
#   sh scripts/moshpit-update.sh --dry-run    # say what would change
#
# Config, read from /etc/moshpit/update.conf (override with MOSHPIT_UPDATE_CONF):
#
#   MOSHPIT_REPO=https://github.com/profullstack/moshpit-proxy.git
#   MOSHPIT_BRANCH=main
#   MOSHPIT_PREFIX=/opt/moshpit
#
# Converts a hand-copied prefix into a checkout on first run rather than
# demanding someone do it by hand: an upgrade path nobody has to read about is
# the only kind that gets taken. The old tree is kept next to the new one, so a
# local edit somebody forgot to upstream is recoverable rather than gone.
set -eu

CONF="${MOSHPIT_UPDATE_CONF:-/etc/moshpit/update.conf}"
[ -f "$CONF" ] && . "$CONF"

REPO="${MOSHPIT_REPO:-https://github.com/profullstack/moshpit-proxy.git}"
BRANCH="${MOSHPIT_BRANCH:-main}"
PREFIX="${MOSHPIT_PREFIX:-/opt/moshpit}"
DRY_RUN=0

BOLD=''; DIM=''; RED=''; OFF=''
if [ -t 2 ]; then BOLD=$(printf '\033[1m'); DIM=$(printf '\033[2m'); RED=$(printf '\033[31m'); OFF=$(printf '\033[0m'); fi
say()  { printf '%s\n' "$*" >&2; }
step() { printf '%s==>%s %s\n' "$BOLD" "$OFF" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$RED" "$OFF" "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    -h|--help) sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
  shift
done

command -v git >/dev/null 2>&1 || die "git is required"

# ---- first run: adopt a hand-copied prefix ---------------------------------

if [ ! -d "$PREFIX/.git" ]; then
  step "$PREFIX is not a checkout — converting"
  if [ "$DRY_RUN" = "1" ]; then
    say "  ${DIM}would clone $REPO into $PREFIX, keeping the old tree beside it${OFF}"
    exit 0
  fi

  TMP="$PREFIX.new.$$"
  rm -rf "$TMP"
  git clone --quiet --branch "$BRANCH" --depth 50 "$REPO" "$TMP" \
    || die "clone failed — $PREFIX left exactly as it was"

  if [ -e "$PREFIX" ]; then
    # Kept, not deleted. If somebody edited a script in place and never
    # upstreamed it, this is the only copy that has it.
    OLD="$PREFIX.superseded.$(date -u +%Y%m%dT%H%M%SZ)"
    mv "$PREFIX" "$OLD"
    say "  ${DIM}previous tree kept at $OLD${OFF}"
  fi
  mv "$TMP" "$PREFIX"
  say "  ${DIM}$PREFIX is now a checkout of $BRANCH${OFF}"
  CHANGED=1
else
  # ---- normal run: fast-forward ------------------------------------------

  before="$(git -C "$PREFIX" rev-parse HEAD)"
  git -C "$PREFIX" fetch --quiet origin "$BRANCH" || die "fetch failed — nothing changed"

  # Refuse to clobber local edits. Overwriting them silently is how a fix
  # somebody applied on the box at 3am disappears without trace.
  if ! git -C "$PREFIX" diff --quiet || ! git -C "$PREFIX" diff --cached --quiet; then
    die "$PREFIX has uncommitted changes — refusing to overwrite them. Commit, stash, or revert first."
  fi

  after="$(git -C "$PREFIX" rev-parse "origin/$BRANCH")"
  if [ "$before" = "$after" ]; then
    say "${DIM}already at $(git -C "$PREFIX" rev-parse --short HEAD) — nothing to do${OFF}"
    exit 0
  fi

  step "updating $(echo "$before" | cut -c1-7) -> $(echo "$after" | cut -c1-7)"
  git -C "$PREFIX" --no-pager log --oneline "$before..$after" | sed 's/^/  /' >&2 || true
  [ "$DRY_RUN" = "1" ] && exit 0

  git -C "$PREFIX" merge --ff-only --quiet "origin/$BRANCH" \
    || die "not a fast-forward — $PREFIX has diverged and needs a look"
  CHANGED=1
fi

# ---- apply ----------------------------------------------------------------

# The origin template is read fresh by every reconcile pass, so a template
# change needs no action here. Only nginx has to be told.
if [ "${CHANGED:-0}" = "1" ] && command -v nginx >/dev/null 2>&1; then
  if nginx -t >/dev/null 2>&1; then
    nginx -s reload >/dev/null 2>&1 || true
    say "${DIM}nginx reloaded${OFF}"
  else
    # Loud, and not fatal: the update landed, and nginx was already broken or
    # is broken by something unrelated. Failing here would strand the checkout.
    say "${RED}warning:${OFF} nginx -t fails — not reloading. Run \`nginx -t\` to see why."
  fi
fi
