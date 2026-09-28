#!/bin/bash
# Palisade service install for macOS.
#
#   sudo scripts/service/macos/install.sh [ADMIN_ACCOUNT]
#
# Creates a hidden standard service account (_palisade) that runs Palisade as a
# launchd daemon, and an audit group (palisade-audit) whose members can read the
# audit logs and the reviewer token but cannot change them. ADMIN_ACCOUNT (default:
# the account that ran sudo) must be an Administrator and is added to the audit group.
#
# Layout after install:
#   /opt/palisade                 code, config, venv        root:wheel        read-only to the service
#   /opt/palisade/data            models, binary, lock      root:palisade-audit  0750, service reads
#   /opt/palisade/data/{audit,logs,state,eval,compliance}
#                                 written by the service    _palisade:palisade-audit  2750, files 0640
#
# Run `python -m palisade install` in the repo first so the models are downloaded;
# this script imports them (and your existing audit chain) instead of re-downloading.
set -euo pipefail

SVC=_palisade
GRP=palisade-audit
PREFIX=/opt/palisade
DATA=$PREFIX/data
LABEL=com.palisade.server
PLIST=/Library/LaunchDaemons/$LABEL.plist
WRAPPER=/usr/local/bin/palisade
SRC="$(cd "$(dirname "$0")/../../.." && pwd)"
PY="${PYTHON:-python3}"

say()  { printf '\n==> %s\n' "$*"; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

[[ "$(uname -s)" == "Darwin" ]] || die "this installer is for macOS; see scripts/service/linux/install.sh"
[[ $EUID -eq 0 ]] || die "run with sudo"
ADMIN="${1:-${SUDO_USER:-}}"
[[ -n "$ADMIN" && "$ADMIN" != "root" ]] || die "pass the Administrator account name: sudo $0 <account>"
id "$ADMIN" >/dev/null 2>&1 || die "account '$ADMIN' does not exist"
dseditgroup -o checkmember -m "$ADMIN" admin >/dev/null 2>&1 \
  || die "'$ADMIN' is not an Administrator. The reviewing account must be an Administrator."
[[ -f "$SRC/palisade/__main__.py" ]] || die "run from a Palisade checkout (could not find $SRC/palisade)"
[[ -f "$SRC/data/manifest.lock" ]] || die "no models installed in $SRC/data. Run 'python -m palisade install' in the repo first."

free_id() {  # first free id in the hidden 400-499 range for users (1) or groups (2)
  local kind=$1 attr=$2 id
  for id in $(seq 400 499); do
    if ! dscl . -list "/$kind" "$attr" | awk '{print $2}' | grep -qx "$id"; then echo "$id"; return; fi
  done
  die "no free id in 400-499 for $kind"
}

say "Audit group: $GRP"
if dscl . -read "/Groups/$GRP" >/dev/null 2>&1; then
  GID=$(dscl . -read "/Groups/$GRP" PrimaryGroupID | awk '{print $2}'); echo "exists (gid $GID)"
else
  GID=$(free_id Groups PrimaryGroupID)
  dscl . -create "/Groups/$GRP"
  dscl . -create "/Groups/$GRP" PrimaryGroupID "$GID"
  dscl . -create "/Groups/$GRP" RealName "Palisade audit readers"
  dscl . -create "/Groups/$GRP" Password "*"
  echo "created (gid $GID)"
fi

say "Service account: $SVC"
if dscl . -read "/Users/$SVC" >/dev/null 2>&1; then
  echo "exists"
else
  UID_=$(free_id Users UniqueID)
  dscl . -create "/Users/$SVC"
  dscl . -create "/Users/$SVC" UniqueID "$UID_"
  dscl . -create "/Users/$SVC" PrimaryGroupID "$GID"
  dscl . -create "/Users/$SVC" UserShell /usr/bin/false
  dscl . -create "/Users/$SVC" NFSHomeDirectory /var/empty
  dscl . -create "/Users/$SVC" RealName "Palisade service"
  dscl . -create "/Users/$SVC" Password "*"
  dscl . -create "/Users/$SVC" IsHidden 1
  echo "created (uid $UID_), no login shell, no password, hidden"
fi

say "Granting $ADMIN read access through $GRP"
dseditgroup -o edit -a "$ADMIN" -t user "$GRP"
dscacheutil -flushcache || true

say "Installing code to $PREFIX (root-owned, read-only to the service)"
mkdir -p "$PREFIX"
rsync -a --delete --exclude '/data/' --exclude '/.venv/' --exclude '/.git/' --exclude '__pycache__/' "$SRC/" "$PREFIX/"
if [[ ! -x "$PREFIX/.venv/bin/python" ]]; then "$PY" -m venv "$PREFIX/.venv"; fi
"$PREFIX/.venv/bin/python" -m pip install --quiet --upgrade pip
"$PREFIX/.venv/bin/python" -m pip install --quiet -r "$PREFIX/requirements.txt"
"$PREFIX/.venv/bin/python" -m compileall -q "$PREFIX/palisade" "$PREFIX/compliance" || true
chown -R root:wheel "$PREFIX"
chmod -R u+rwX,go+rX,go-w "$PREFIX"

say "Importing models, binary, lock, and audit chain from $SRC/data"
mkdir -p "$DATA"
for d in bin models; do
  if [[ -d "$SRC/data/$d" && ! -d "$DATA/$d" ]]; then ditto "$SRC/data/$d" "$DATA/$d"; fi
done
[[ -f "$DATA/manifest.lock" ]] || cp "$SRC/data/manifest.lock" "$DATA/manifest.lock"
if [[ -d "$SRC/data/audit" && ! -d "$DATA/audit" ]]; then
  ditto "$SRC/data/audit" "$DATA/audit"; echo "existing audit chain imported; original left in place"
fi

say "Applying ownership and permissions"
chown root:"$GRP" "$DATA"; chmod 0750 "$DATA"
chown -R root:"$GRP" "$DATA/bin" "$DATA/models" "$DATA/manifest.lock"
chmod -R u+rwX,g+rX,g-w,o-rwx "$DATA/bin" "$DATA/models"
chmod 0640 "$DATA/manifest.lock"
for d in audit logs state eval compliance; do
  mkdir -p "$DATA/$d"
  chown -R "$SVC":"$GRP" "$DATA/$d"
  chmod 2750 "$DATA/$d"
  find "$DATA/$d" -type f -exec chmod 0640 {} +
done
touch "$DATA/logs/palisade.log"; chown "$SVC":"$GRP" "$DATA/logs/palisade.log"; chmod 0640 "$DATA/logs/palisade.log"

say "Command wrapper: $WRAPPER"
mkdir -p "$(dirname "$WRAPPER")"
cat > "$WRAPPER" << WRAP
#!/bin/bash
# Runs Palisade commands against the service install. Audit review commands work for
# members of $GRP; anything that changes the install needs sudo.
export PALISADE_ROOT=$PREFIX PALISADE_DATA=$DATA PYTHONPATH=$PREFIX
exec $PREFIX/.venv/bin/python -m palisade "\$@"
WRAP
chown root:wheel "$WRAPPER"; chmod 0755 "$WRAPPER"

say "launchd daemon: $PLIST"
cat > "$PLIST" << PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array><string>$PREFIX/.venv/bin/python</string><string>-m</string><string>palisade</string><string>run</string></array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PALISADE_ROOT</key><string>$PREFIX</string>
    <key>PALISADE_DATA</key><string>$DATA</string>
    <key>PYTHONPATH</key><string>$PREFIX</string>
  </dict>
  <key>UserName</key><string>$SVC</string>
  <key>GroupName</key><string>$GRP</string>
  <key>WorkingDirectory</key><string>$PREFIX</string>
  <key>Umask</key><integer>23</integer>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>StandardOutPath</key><string>$DATA/logs/palisade.log</string>
  <key>StandardErrorPath</key><string>$DATA/logs/palisade.log</string>
</dict>
</plist>
PL
chown root:wheel "$PLIST"; chmod 0644 "$PLIST"
plutil -lint "$PLIST" >/dev/null
launchctl bootout system/"$LABEL" 2>/dev/null || true
launchctl bootstrap system "$PLIST"

say "Installed. Verify:"
cat << DONE
  1. sudo launchctl print system/$LABEL | grep -E 'state|pid'      (expect: state = running)
  2. tail -n 20 $DATA/logs/palisade.log                            (expect: Palisade ready)
  3. grep -i metal $DATA/logs/base-server.log | head -3            (expect Metal lines; if absent, the
                                                                      daemon is running on CPU)
  4. Open http://127.0.0.1:8080/ in a browser.
  5. Log out and back in as $ADMIN so the new group membership applies, then:
       cat $DATA/state/reviewer.token     (should work without sudo)
       touch $DATA/audit/test             (should fail: Permission denied)
       palisade audit verify              (should work without sudo)
  6. Open http://127.0.0.1:8080/review and paste the reviewer token.

The copy of Palisade in $SRC is no longer the one running. Stop any desktop instance
there so two copies do not compete for ports 8080-8082.
DONE
