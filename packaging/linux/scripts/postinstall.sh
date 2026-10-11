#!/bin/sh
# Runs after the package is installed or upgraded (deb: "configure"; rpm: $1 = 1 or 2).
set -e
MODEFILE=/opt/palisade/install-mode
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
fi
mode=$(cat "$MODEFILE" 2>/dev/null || true)
if [ "$mode" = service ] && [ -d /run/systemd/system ]; then
  # Upgrade of a service install: let setup record the new release, then restart.
  systemctl start --no-block palisade-setup.service || true
  systemctl try-restart palisade.service || true
  echo "Palisade upgraded; the service is restarting."
elif [ -z "$mode" ]; then
  cat << 'MSG'

Palisade is installed. Choose how it runs:

  sudo palisade-mode service YOUR-ADMIN-ACCOUNT
      A locked-down service account runs Palisade and writes the audit log.
      Your administrator account can review the log but not change it.

  palisade-mode desktop
      Palisade runs under your own login, with your own settings and data.

Then open http://127.0.0.1:8080/ . The first start downloads the models (about 10 GB).
MSG
fi
exit 0
