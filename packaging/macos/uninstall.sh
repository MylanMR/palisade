#!/bin/bash
# Remove Palisade from this Mac.   sudo /opt/palisade/uninstall.sh [--remove-accounts]
# Settings and data, including the audit log, are kept in
# /Library/Application Support/Palisade and each person's ~/Library/Application Support/Palisade:
# deleting audit records should be a deliberate decision, not a side effect of uninstalling.
set -u
[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }
launchctl bootout system/com.palisade.server 2>/dev/null
launchctl bootout system/com.palisade.setup 2>/dev/null
for uid in $(ps -axo uid=,comm= | awk '/loginwindow/ {print $1}' | sort -u); do
  launchctl bootout gui/"$uid"/com.palisade.desktop 2>/dev/null
done
rm -f /Library/LaunchDaemons/com.palisade.server.plist /Library/LaunchDaemons/com.palisade.setup.plist \
      /Library/LaunchAgents/com.palisade.desktop.plist /usr/local/bin/palisade /usr/local/bin/palisade-mode
rm -rf /Applications/Palisade.app /opt/palisade
for id in com.palisade.core com.palisade.mode.service com.palisade.mode.desktop; do
  pkgutil --forget "$id" >/dev/null 2>&1
done
if [ "${1:-}" = "--remove-accounts" ]; then
  dscl . -delete /Users/_palisade 2>/dev/null
  dscl . -delete /Groups/palisade-audit 2>/dev/null
  echo "Service account and audit group removed."
fi
echo "Palisade removed. Settings and the audit log remain in /Library/Application Support/Palisade."
