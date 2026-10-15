# Builds the root filesystem of the FlowScope Proxmox VE container template (a "CT template").
# Not run with `docker run`: build.sh exports the result as a .tar.zst that you upload in the Proxmox web interface
# (storage -> CT Templates -> Upload) and then pick when you click Create CT. See docs/deployment.md.
#
# It is Debian 12 with systemd, the network tools Proxmox expects in a container, and FlowScope installed as a service by the same
# installer the command-line route uses (packaging/proxmox/install.sh), so both routes end up with the same layout and `flowscope-ctl`.
# Build from the repository root:   docker build -f packaging/lxc-template/Dockerfile --output type=tar,dest=rootfs.tar .
ARG DEBIAN_IMAGE=debian:bookworm-slim
ARG NODE_IMAGE=node:22-bookworm-slim

FROM ${NODE_IMAGE} AS nodesrc

FROM ${DEBIAN_IMAGE}
# declared inside the stage: an ARG before the first FROM is only visible to FROM lines
ARG CLICKHOUSE_VERSION=25.8
# clickhouse (the default) or sqlite: a template without ClickHouse, for small sites. build.sh sets it (STORAGE_BACKEND=sqlite).
ARG STORAGE_BACKEND=clickhouse
# lxc (the Proxmox container template) or vm (the root filesystem packaging/vm/build.sh turns into a bootable disk). A VM is a real machine with
# its own kernel, so the LXC-only systemd sandbox relaxations are not applied to it. packaging/vm/build.sh sets it.
ARG TEMPLATE_KIND=lxc
ENV DEBIAN_FRONTEND=noninteractive
# What a Proxmox container needs from the inside: an init system, a DHCP client and ifupdown (Proxmox writes /etc/network/interfaces),
# login tools for setting the root password, and SSH for key-based access. Also what the installer and `flowscope-ctl update` use.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      systemd systemd-sysv dbus libpam-systemd \
      ifupdown isc-dhcp-client iproute2 iputils-ping \
      openssh-server \
      ca-certificates curl tar gzip xz-utils gnupg apt-transport-https \
      locales procps nano less tzdata \
 && rm -rf /var/lib/apt/lists/*

# Node.js from the official image of the same Debian release, including npm (the installer needs it to update FlowScope later).
COPY --from=nodesrc /usr/local/bin/node /usr/local/bin/node
COPY --from=nodesrc /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
 && node --version && npm --version

# ClickHouse (skipped when STORAGE_BACKEND=sqlite), FlowScope's storage, from ClickHouse's own repository, pinned to the 25.8 LTS line (the one the project is tested against; the newest
# line, 26.8, does not run on older CPUs such as a 2010 Xeon) and held so apt upgrade keeps it there. Installed here, not by the FlowScope installer, so this layer is cached.
# It listens on 127.0.0.1 only (the installer writes that setting). The user FlowScope connects as is made at each container's first boot.
RUN if [ "$STORAGE_BACKEND" = clickhouse ]; then \
      curl -fsSL 'https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key' | gpg --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg \
   && echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg arch=$(dpkg --print-architecture)] https://packages.clickhouse.com/deb lts main" > /etc/apt/sources.list.d/clickhouse.list \
   && apt-get update \
   && apt-get install -y --no-install-recommends "clickhouse-server=${CLICKHOUSE_VERSION}.*" "clickhouse-common-static=${CLICKHOUSE_VERSION}.*" "clickhouse-client=${CLICKHOUSE_VERSION}.*" \
   && apt-mark hold clickhouse-server clickhouse-common-static clickhouse-client \
   && rm -rf /var/lib/apt/lists/*; \
    fi

# FlowScope itself. FLOWSCOPE_TEMPLATE_BUILD keeps a password out of the template; the first-boot service makes one per container.
COPY . /tmp/flowscope-src
# the commit the template is built from (build.sh passes it; the source copy has no .git folder)
ARG GIT_SHA=unknown
RUN if [ "$TEMPLATE_KIND" = lxc ]; then export FLOWSCOPE_LXC=1; fi; \
    FLOWSCOPE_REVISION=$GIT_SHA FLOWSCOPE_TEMPLATE_BUILD=1 FLOWSCOPE_STORAGE=$STORAGE_BACKEND FLOWSCOPE_NODE=system FLOWSCOPE_SKIP_APT=1 FLOWSCOPE_SKIP_SYSTEMD=1 \
    FLOWSCOPE_SRC=/tmp/flowscope-src bash /tmp/flowscope-src/packaging/proxmox/install.sh \
 && rm -rf /tmp/flowscope-src /root/.npm

# Template extras: first-boot service and its drop-in for flowscope.service.
COPY packaging/lxc-template/rootfs/ /
RUN chmod 755 /usr/local/sbin/flowscope-firstboot \
 && systemctl enable flowscope.service flowscope-firstboot.service ssh.service \
 && if [ "$STORAGE_BACKEND" = clickhouse ]; then systemctl enable clickhouse-server.service; else rm -rf /etc/systemd/system/clickhouse-server.service.d; fi

# Turn the Docker-flavoured Debian image into a normal system: no "do not start services" policy, no Docker apt tweaks.
# Nothing machine-specific may ship in a template: empty machine-id (systemd makes a new one at first boot), no SSH host keys.
RUN rm -f /usr/sbin/policy-rc.d /etc/apt/apt.conf.d/docker-* \
 && echo 'LANG=C.UTF-8' > /etc/default/locale \
 && rm -f /etc/ssh/ssh_host_* \
 && : > /etc/machine-id && rm -f /var/lib/dbus/machine-id \
 && printf 'FlowScope Proxmox template for Debian 12, built from %s\n' "$(cat /opt/flowscope/package.json | sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' | head -n1)" > /etc/flowscope-template \
 && apt-get clean && rm -rf /var/cache/apt /var/lib/apt/lists/* /tmp/* /var/tmp/*
