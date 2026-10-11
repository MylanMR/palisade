#!/bin/bash
# Build the macOS installer: a signed, notarized .pkg inside a signed, notarized .dmg.
#
#   packaging/macos/build.sh macos-arm64 [OUTPUT_DIR]
#   packaging/macos/build.sh macos-x64   [OUTPUT_DIR]
#
# Signing and notarization (required unless PALISADE_UNSIGNED=1):
#   MACOS_APP_IDENTITY        "Developer ID Application: NAME (TEAMID)"   signs code and the .dmg
#   MACOS_INSTALLER_IDENTITY  "Developer ID Installer: NAME (TEAMID)"     signs the .pkg
#   NOTARY_KEY_PATH, NOTARY_KEY_ID, NOTARY_ISSUER                         App Store Connect API key
#   MACOS_KEYCHAIN            optional keychain holding the identities (CI uses a temporary one)
#
# PALISADE_UNSIGNED=1 builds unsigned test installers, named *-UNSIGNED. Gatekeeper blocks
# them; they are for checking the installer's behavior on a test Mac, never for release.
set -euo pipefail

plat="${1:?usage: build.sh macos-arm64|macos-x64 [OUTPUT_DIR]}"
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
out="${2:-$repo/dist}"
work="$repo/build/macos-$plat"
payload="$work/root/opt/palisade"
unsigned="${PALISADE_UNSIGNED:-0}"
case "$plat" in macos-arm64) arch=arm64 ;; macos-x64) arch=x86_64 ;; *) echo "unknown platform $plat" >&2; exit 2 ;; esac
[ "$(uname -s)" = Darwin ] || { echo "macOS packages must be built on macOS" >&2; exit 2; }

if [ "$unsigned" != 1 ]; then
  for v in MACOS_APP_IDENTITY MACOS_INSTALLER_IDENTITY NOTARY_KEY_PATH NOTARY_KEY_ID NOTARY_ISSUER; do
    [ -n "${!v:-}" ] || { echo "missing $v (set PALISADE_UNSIGNED=1 for an unsigned test build)" >&2; exit 2; }
  done
fi
kc=(); [ -n "${MACOS_KEYCHAIN:-}" ] && kc=(--keychain "$MACOS_KEYCHAIN")

rm -rf "$work"; mkdir -p "$work/root/opt" "$work/root/Applications" "$work/pkgs" "$out"

echo "==> Payload"
python3 "$repo/packaging/build_payload.py" --platform "$plat" --out "$payload" --cache "$repo/build/cache"
install -d "$payload/libexec"
install -m 0755 "$here/palisade-mode" "$payload/libexec/palisade-mode"
install -m 0755 "$here/uninstall.sh" "$payload/uninstall.sh"
version=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$payload/install.json")

echo "==> Palisade.app (opens Palisade in the browser, starting it first in desktop mode)"
app="$work/root/Applications/Palisade.app"
osacompile -o "$app" -e 'do shell script "/opt/palisade/bin/palisade open > /dev/null 2>&1 &"'
plutil -replace CFBundleIdentifier -string com.palisade.launcher "$app/Contents/Info.plist"
plutil -replace CFBundleShortVersionString -string "$version" "$app/Contents/Info.plist"
plutil -replace CFBundleName -string Palisade "$app/Contents/Info.plist"

sign() { codesign --force --options runtime --timestamp "${kc[@]}" --sign "$MACOS_APP_IDENTITY" "$@"; }
if [ "$unsigned" != 1 ]; then
  echo "==> Signing every executable and library (hardened runtime, secure timestamp)"
  count=0
  while IFS= read -r -d '' f; do
    if file -b "$f" | grep -q 'Mach-O'; then sign "$f"; count=$((count + 1)); fi
  done < <(find "$payload" -type f -print0)
  echo "   signed $count Mach-O files"
  sign "$app"
  codesign --verify --strict --deep "$app"
  # Signing rewrote the binaries, so record their new hashes for the startup check.
  python3 "$repo/packaging/build_payload.py" --rehash-bin "$payload"
  echo "==> Smoke test under the hardened runtime"
  "$payload/bin/palisade" --help >/dev/null
  "$payload/llama/llama-server" --version 2>&1 | head -1
fi

echo "==> Component packages"
pkgbuild --analyze --root "$work/root" "$work/components.plist"
# Keep Palisade.app in /Applications even if a copy exists elsewhere on the disk.
python3 -c '
import plistlib, sys
p = sys.argv[1]; items = plistlib.load(open(p, "rb"))
for item in items: item["BundleIsRelocatable"] = False
plistlib.dump(items, open(p, "wb"))' "$work/components.plist"
pkgbuild --root "$work/root" --component-plist "$work/components.plist" --identifier com.palisade.core \
  --version "$version" --install-location / --scripts "$here/scripts/core" "$work/pkgs/core.pkg"
pkgbuild --nopayload --identifier com.palisade.mode.service --version "$version" \
  --scripts "$here/scripts/service" "$work/pkgs/mode-service.pkg"
pkgbuild --nopayload --identifier com.palisade.mode.desktop --version "$version" \
  --scripts "$here/scripts/desktop" "$work/pkgs/mode-desktop.pkg"

echo "==> Product package"
mkdir -p "$work/resources"
cp "$here/resources/"*.html "$work/resources/"
cp "$repo/LICENSE" "$work/resources/LICENSE.txt"
sed -e "s/@VERSION@/$version/g" -e "s/@ARCH@/$arch/g" "$here/distribution.xml.in" > "$work/distribution.xml"
suffix=""; [ "$unsigned" = 1 ] && suffix="-UNSIGNED"
pkg="$work/Palisade-$version-$plat$suffix.pkg"
productbuild --distribution "$work/distribution.xml" --package-path "$work/pkgs" \
  --resources "$work/resources" "$work/unsigned.pkg"

notarize() {   # submit, wait, fail unless Apple accepts, then staple the ticket
  local file=$1 result
  result=$(xcrun notarytool submit "$file" --key "$NOTARY_KEY_PATH" --key-id "$NOTARY_KEY_ID" \
           --issuer "$NOTARY_ISSUER" --wait --output-format json)
  echo "$result"
  if ! echo "$result" | grep -q '"status" *: *"Accepted"'; then
    id=$(echo "$result" | sed -n 's/.*"id" *: *"\([^"]*\)".*/\1/p' | head -1)
    [ -n "$id" ] && xcrun notarytool log "$id" --key "$NOTARY_KEY_PATH" --key-id "$NOTARY_KEY_ID" --issuer "$NOTARY_ISSUER"
    echo "notarization failed for $file" >&2; exit 1
  fi
  xcrun stapler staple "$file"
}

if [ "$unsigned" != 1 ]; then
  productsign "${kc[@]}" --sign "$MACOS_INSTALLER_IDENTITY" "$work/unsigned.pkg" "$pkg"
  pkgutil --check-signature "$pkg"
  echo "==> Notarizing the package"
  notarize "$pkg"
else
  mv "$work/unsigned.pkg" "$pkg"
fi

echo "==> Disk image"
dmgroot="$work/dmg"; mkdir -p "$dmgroot/For administrators"
cp "$pkg" "$dmgroot/"
cp "$here/desktop-mode.plist" "$dmgroot/For administrators/"
cat > "$dmgroot/For administrators/Silent install.txt" << TXT
Silent installs (MDM or Terminal) install service mode by default:
  sudo installer -pkg "$(basename "$pkg")" -target /

For desktop mode instead:
  sudo installer -pkg "$(basename "$pkg")" -target / -applyChoiceChangesXML desktop-mode.plist

Switch later with: sudo palisade-mode service ACCOUNT   or   sudo palisade-mode desktop
TXT
dmg="$out/Palisade-$version-$plat$suffix.dmg"
rm -f "$dmg"
hdiutil create -volname "Palisade $version" -srcfolder "$dmgroot" -ov -format UDZO "$dmg"
if [ "$unsigned" != 1 ]; then
  codesign --force --timestamp "${kc[@]}" --sign "$MACOS_APP_IDENTITY" "$dmg"
  echo "==> Notarizing the disk image"
  notarize "$dmg"
  spctl --assess --type open --context context:primary-signature -v "$dmg"
fi
cp "$pkg" "$out/"
ls -l "$out"
