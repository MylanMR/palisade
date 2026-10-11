#!/bin/sh
# Runs before removal (deb: "remove"; rpm: $1 = 0). Upgrades leave the service running.
set -e
case "$1" in
  remove|purge|0)
    if [ -d /run/systemd/system ]; then
      systemctl disable --now palisade.service palisade-setup.service 2>/dev/null || true
    fi
    ;;
esac
exit 0
