#!/bin/bash
# Stops the Palisade daemon and removes the launchd job and command wrapper.
# Audit data under /opt/palisade/data is kept deliberately: deleting audit records is
# a decision for the system owner, not a side effect of uninstalling.
#   sudo scripts/service/macos/uninstall.sh [--remove-accounts]
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
launchctl bootout system/com.palisade.server 2>/dev/null || true
rm -f /Library/LaunchDaemons/com.palisade.server.plist /usr/local/bin/palisade
if [[ "${1:-}" == "--remove-accounts" ]]; then
  dscl . -delete /Users/_palisade 2>/dev/null || true
  dscl . -delete /Groups/palisade-audit 2>/dev/null || true
  echo "service account and audit group removed"
fi
echo "Daemon removed. Code and audit data remain in /opt/palisade; remove them yourself once retention allows."
