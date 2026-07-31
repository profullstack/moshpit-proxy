#!/bin/sh
# Moshpit pin-verifying proxy. Port comes from the environment so the same
# script serves the unprivileged run (8443) and the real one (443).
cd /home/anthony/moshpit-proxy
export MOSHPIT_PROXY_PORT=${MOSHPIT_PROXY_PORT:-8443}
export MOSHPIT_PROXY_LOG=${MOSHPIT_PROXY_LOG:-1}
exec node bin/moshpit-proxy.ts
