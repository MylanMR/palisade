#!/bin/sh
# Runs after removal. Audit data is never deleted by the package manager: removing audit
# records should be a deliberate decision, not a side effect of uninstalling.
set -e
case "$1" in
  remove|purge|0)
    rm -f /opt/palisade/install-mode
    find /opt/palisade -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
    rmdir /opt/palisade 2>/dev/null || true
    if [ -d /run/systemd/system ]; then systemctl daemon-reload || true; fi
    echo "Palisade removed. Settings remain in /etc/palisade and data (including the audit log) in /var/lib/palisade."
    echo "Desktop-mode data remains in each person's ~/.local/share/palisade."
    ;;
esac
exit 0
