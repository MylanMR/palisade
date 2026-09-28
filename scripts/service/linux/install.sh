#!/bin/bash
# Palisade service install for Linux (systemd).
#
#   sudo scripts/service/linux/install.sh [ADMIN_ACCOUNT]
#
# Same model as the macOS installer: a system account (palisade) runs the service and
# owns the audit files; an audit group (palisade-audit) grants read-only access to
# ADMIN_ACCOUNT, who must be an administrator (member of sudo, wheel, or admin).
# Run `python -m palisade install` in the repo first; this script imports the models.
set -euo pipefail

SVC=${PALISADE_SVC:-palisade}
GRP=${PALISADE_GRP:-palisade-audit}
PREFIX=${PALISADE_PREFIX:-/opt/palisade}
DATA=$PREFIX/data
UNIT=/etc/systemd/system/palisade.service
WRAPPER=/usr/local/bin/palisade
SRC="$(cd "$(dirname "$0")/../../.." && pwd)"
PY="${PYTHON:-python3}"

say() { printf '\n==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[[ "$(uname -s)" == "Linux" ]] || die "this installer is for Linux; see scripts/service/macos/install.sh"
[[ $EUID -eq 0 ]] || die "run with sudo"
ADMIN="${1:-${SUDO_USER:-}}"
[[ -n "$ADMIN" && "$ADMIN" != "root" ]] || die "pass the administrator account name: sudo $0 <account>"
id "$ADMIN" >/dev/null 2>&1 || die "account '$ADMIN' does not exist"
id -nG "$ADMIN" | tr ' ' '\n' | grep -qxE 'sudo|wheel|admin' \
  || die "'$ADMIN' is not an administrator (not in sudo, wheel, or admin). The reviewing account must be one."
[[ -f "$SRC/palisade/__main__.py" ]] || die "run from a Palisade checkout"
[[ -f "$SRC/data/manifest.lock" ]] || die "no models installed in $SRC/data. Run 'python -m palisade install' in the repo first."

say "Audit group and service account"
getent group "$GRP" >/dev/null || groupadd --system "$GRP"
if ! id "$SVC" >/dev/null 2>&1; then
  useradd --system --gid "$GRP" --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin \
          --comment "Palisade service" "$SVC"
fi
# GPU device access for Vulkan/CUDA when those groups exist
for g in render video; do
  if getent group "$g" >/dev/null; then usermod -aG "$g" "$SVC"; fi
done
usermod -aG "$GRP" "$ADMIN"
echo "service: $SVC   audit group: $GRP   reader: $ADMIN"

say "Installing code to $PREFIX (root-owned, read-only to the service)"
mkdir -p "$PREFIX"
if command -v rsync >/dev/null; then
  rsync -a --delete --exclude '/data/' --exclude '/.venv/' --exclude '/.git/' --exclude '__pycache__/' "$SRC/" "$PREFIX/"
else
  (cd "$SRC" && tar --exclude=./data --exclude=./.venv --exclude=./.git --exclude='__pycache__' -cf - .) | (cd "$PREFIX" && tar -xf -)
fi
[[ -x "$PREFIX/.venv/bin/python" ]] || "$PY" -m venv "$PREFIX/.venv"
"$PREFIX/.venv/bin/python" -m pip install --quiet -r "$PREFIX/requirements.txt"
"$PREFIX/.venv/bin/python" -m compileall -q "$PREFIX/palisade" "$PREFIX/compliance" || true
chown -R root:root "$PREFIX"
chmod -R u+rwX,go+rX,go-w "$PREFIX"

say "Importing models, binary, lock, and audit chain"
mkdir -p "$DATA"
for d in bin models; do
  if [[ -d "$SRC/data/$d" && ! -d "$DATA/$d" ]]; then cp -a "$SRC/data/$d" "$DATA/$d"; fi
done
[[ -f "$DATA/manifest.lock" ]] || cp "$SRC/data/manifest.lock" "$DATA/manifest.lock"
if [[ -d "$SRC/data/audit" && ! -d "$DATA/audit" ]]; then cp -a "$SRC/data/audit" "$DATA/audit"; echo "audit chain imported"; fi

say "Applying ownership and permissions"
chown root:"$GRP" "$DATA"; chmod 0750 "$DATA"
chown -R root:"$GRP" "$DATA/bin" "$DATA/models" "$DATA/manifest.lock"
chmod -R u+rwX,g+rX,g-w,o-rwx "$DATA/bin" "$DATA/models"
chmod 0640 "$DATA/manifest.lock"
for d in audit logs state eval compliance; do
  mkdir -p "$DATA/$d"; chown -R "$SVC":"$GRP" "$DATA/$d"; chmod 2750 "$DATA/$d"
  find "$DATA/$d" -type f -exec chmod 0640 {} +
done

say "Command wrapper: $WRAPPER"
cat > "$WRAPPER" << WRAP
#!/bin/bash
export PALISADE_ROOT=$PREFIX PALISADE_DATA=$DATA PYTHONPATH=$PREFIX
exec $PREFIX/.venv/bin/python -m palisade "\$@"
WRAP
chmod 0755 "$WRAPPER"

say "systemd unit: $UNIT"
cat > "$UNIT" << U
[Unit]
Description=Palisade policy-enforced local LLM
After=network.target

[Service]
User=$SVC
Group=$GRP
UMask=0027
WorkingDirectory=$PREFIX
Environment=PALISADE_ROOT=$PREFIX PALISADE_DATA=$DATA PYTHONPATH=$PREFIX
ExecStart=$PREFIX/.venv/bin/python -m palisade run
Restart=on-failure
RestartSec=30
# Defense in depth: even if file permissions drift, the service can only write its state.
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=$DATA/audit $DATA/logs $DATA/state $DATA/eval $DATA/compliance
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
U
chmod 0644 "$UNIT"
if [[ -d /run/systemd/system ]]; then
  systemctl daemon-reload
  systemctl enable --now palisade.service
  echo "service enabled and started"
else
  echo "systemd is not running here; start later with: systemctl enable --now palisade.service"
fi

say "Installed. Verify:"
cat << DONE
  1. systemctl status palisade                 (expect: active (running))
  2. journalctl -u palisade -n 20              (expect: Palisade ready)
  3. Log out and back in as $ADMIN, then:
       cat $DATA/state/reviewer.token           (works without sudo)
       touch $DATA/audit/test                   (fails: Permission denied)
       palisade audit verify                    (works without sudo)
DONE
