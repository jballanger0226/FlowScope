#!/bin/sh
# Container entrypoint, used by Docker, Podman and Proxmox VE (OCI image as an LXC container).
#
# A new volume, a bind mount, or a Proxmox mount point is usually owned by root, and inside an unprivileged Proxmox
# container "root" is a shifted, harmless uid. So the container starts as root only long enough to make /data writable
# for the unprivileged "node" user, then drops to that user before any FlowScope code runs.
#
# Started as another user (docker run --user 1000:1000, or compose "user:"), it does nothing but run FlowScope.
set -eu

DATA="${FLOWSCOPE_DATA_DIR:-/data}"
RUN="node --disable-warning=ExperimentalWarning /app/dist/src/cli.js"

if [ "$(id -u)" = "0" ]; then
  mkdir -p "$DATA"
  want="$(id -u node)"
  if [ "$(stat -c %u "$DATA")" != "$want" ]; then
    echo "flowscope: giving the data folder $DATA to the unprivileged user (one time)" >&2
    chown -R node:node "$DATA" || echo "flowscope: could not change ownership of $DATA; start with --user matching the owner of the volume" >&2
  fi
  if command -v setpriv >/dev/null 2>&1; then
    # shellcheck disable=SC2086
    exec setpriv --reuid=node --regid=node --init-groups -- $RUN "$@"
  fi
  echo "flowscope: setpriv not found, running as root" >&2
fi
# shellcheck disable=SC2086
exec $RUN "$@"
