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
    # The web console is on port 443, which an unprivileged user may not open. Keep just CAP_NET_BIND_SERVICE for "node" (part of Docker's
    # and Podman's default set), probing first so a container started without it still runs, on a port above 1023.
    caps=""
    if setpriv --reuid=node --regid=node --init-groups --inh-caps=+net_bind_service --ambient-caps=+net_bind_service -- true 2>/dev/null; then
      caps="--inh-caps=+net_bind_service --ambient-caps=+net_bind_service"
    fi
    # shellcheck disable=SC2086
    exec setpriv --reuid=node --regid=node --init-groups $caps -- $RUN "$@"
  fi
  echo "flowscope: setpriv not found, running as root" >&2
fi
# shellcheck disable=SC2086
exec $RUN "$@"
