#!/bin/sh
# Install moshpit-proxy, and set this computer up to open Moshpit sites.
#
#   curl -fsSL https://raw.githubusercontent.com/profullstack/moshpit-proxy/main/install.sh | sh
#
# Installs to your home directory and needs no root for the code itself. The
# setup step asks once before changing anything, and on macOS will ask for your
# password because the system store needs it.
#
# If piping a script from the internet into a shell makes you uneasy, good — read
# it first:
#
#   curl -fsSL .../install.sh -o install.sh && less install.sh && sh install.sh
#
set -eu

REPO="profullstack/moshpit-proxy"
REF="${MOSHPIT_REF:-main}"
PREFIX="${MOSHPIT_PREFIX:-${XDG_DATA_HOME:-$HOME/.local/share}/moshpit-proxy}"
BINDIR="${MOSHPIT_BIN:-$HOME/.local/bin}"
ACTION="install"
RUN_TRUST=1
ASSUME_YES=""

RED=''; BOLD=''; DIM=''; OFF=''
if [ -t 2 ]; then RED=$(printf '\033[31m'); BOLD=$(printf '\033[1m'); DIM=$(printf '\033[2m'); OFF=$(printf '\033[0m'); fi

say()  { printf '%s\n' "$*" >&2; }
step() { printf '%s==>%s %s\n' "$BOLD" "$OFF" "$*" >&2; }
warn() { printf '%swarning:%s %s\n' "$RED" "$OFF" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$RED" "$OFF" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --uninstall) ACTION="uninstall" ;;
    --no-trust)  RUN_TRUST=0 ;;
    --yes|-y)    ASSUME_YES="--yes" ;;
    --prefix)    PREFIX="${2:?--prefix needs a path}"; shift ;;
    --bin)       BINDIR="${2:?--bin needs a path}"; shift ;;
    --ref)       REF="${2:?--ref needs a git ref}"; shift ;;
    -h|--help)
      cat >&2 <<EOF
usage: install.sh [options]

  --uninstall             remove the install, and undo the browser setup
  --no-trust              install the code only, skip the browser setup
  --yes                   do not ask before the browser setup
  --prefix <dir>          where the code goes   (default: $PREFIX)
  --bin <dir>             where the shims go    (default: $BINDIR)
  --ref <tag|branch|sha>  what to install       (default: main)

environment: MOSHPIT_PREFIX, MOSHPIT_BIN, MOSHPIT_REF
EOF
      exit 0 ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
  shift
done

if [ "$ACTION" = "uninstall" ]; then
  if [ -x "$PREFIX/bin/moshpit-trust.ts" ] && have node; then
    step "undoing the browser setup"
    node "$PREFIX/bin/moshpit-trust.ts" --uninstall || warn "could not undo the browser setup"
  fi
  step "removing $PREFIX"
  rm -rf "$PREFIX"
  for shim in moshpit-proxy moshpit-pin moshpit-trust; do rm -f "$BINDIR/$shim"; done
  say "Removed."
  exit 0
fi

# ---------------------------------------------------------------- runtime

have node || die "node is required (v24 or newer)"

# Checked by capability rather than by version string, for the same reason
# moshpit-transport does it: a Node built without the pieces we need passes a
# version check and then fails at the first connection. Dynamic SNI and TLS 1.3
# are the two this proxy cannot work without.
node -e '
  const tls = require("node:tls");
  const [maj] = process.versions.node.split(".").map(Number);
  if (maj < 24) { console.error("node " + process.versions.node + " is too old"); process.exit(1); }
  if (typeof tls.createSecureContext !== "function") { console.error("node:tls is incomplete"); process.exit(1); }
' || die "this node cannot run the proxy — install Node 24 or newer"

have openssl || die "openssl is required (the local key is generated with it)"

# ---------------------------------------------------------------- fetch

step "installing $REPO@$REF to $PREFIX"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

url="https://codeload.github.com/$REPO/tar.gz/$REF"
if have curl; then
  curl -fsSL "$url" -o "$tmp/src.tgz" || die "download failed: $url"
elif have wget; then
  wget -qO "$tmp/src.tgz" "$url" || die "download failed: $url"
else
  die "need curl or wget"
fi

mkdir -p "$tmp/src"
tar -xzf "$tmp/src.tgz" -C "$tmp/src" --strip-components=1 || die "could not unpack the download"

rm -rf "$PREFIX"
mkdir -p "$(dirname "$PREFIX")"
mv "$tmp/src" "$PREFIX"

# ---------------------------------------------------------------- shims

mkdir -p "$BINDIR"
for shim in moshpit-proxy moshpit-pin moshpit-trust; do
  [ -f "$PREFIX/bin/$shim.ts" ] || continue
  cat > "$BINDIR/$shim" <<EOF
#!/bin/sh
exec node "$PREFIX/bin/$shim.ts" "\$@"
EOF
  chmod +x "$BINDIR/$shim"
done

case ":$PATH:" in
  *":$BINDIR:"*) ;;
  *) warn "$BINDIR is not on your PATH — add it to use \`moshpit-proxy\` by name" ;;
esac

# ---------------------------------------------------------------- setup

if [ "$RUN_TRUST" = "1" ]; then
  step "setting up your browsers"
  # Straight to the terminal, not through this script's stdin: when the whole
  # installer arrived via `curl | sh`, stdin is the script itself and a prompt
  # would read the rest of the file as the answer.
  if [ -n "$ASSUME_YES" ] || [ ! -r /dev/tty ]; then
    node "$PREFIX/bin/moshpit-trust.ts" ${ASSUME_YES:+--yes} || warn "browser setup did not finish — run \`moshpit-trust\` yourself"
  else
    node "$PREFIX/bin/moshpit-trust.ts" < /dev/tty || warn "browser setup did not finish — run \`moshpit-trust\` yourself"
  fi
fi

say ""
say "${BOLD}Installed.${OFF}"
say "  ${DIM}start the proxy:${OFF}  moshpit-proxy"
say "  ${DIM}redo the setup:${OFF}   moshpit-trust"
say "  ${DIM}undo everything:${OFF}  install.sh --uninstall"
