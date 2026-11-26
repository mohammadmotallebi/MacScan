#!/usr/bin/env bash
# Builds build/MacScan-<version>.dmg for distribution: a universal (Apple Silicon + Intel) Release
# build with the Hardened Runtime and a /Applications shortcut.
#
# Usage:
#   scripts/release.sh                                   # ad-hoc signed, not notarized (current public builds)
#   DEVELOPER_ID="<sha1 or name>" scripts/release.sh     # sign with a Developer ID Application identity
#   DEVELOPER_ID=... NOTARY_PROFILE=<profile> scripts/release.sh   # ...and notarize + staple
#
# Notarization needs a "Developer ID Application" certificate and notary credentials saved with
#   xcrun notarytool store-credentials <profile> --apple-id <id> --team-id <team>
set -euo pipefail
cd "$(dirname "$0")/.."

IDENTITY="${DEVELOPER_ID:--}"
DERIVED=build/release
APP="$DERIVED/Build/Products/Release/MacScan.app"

die() { echo "error: $*" >&2; exit 1; }

# --- Build (unsigned), then sign ourselves -----------------------------------------------------
xcodebuild -project MacScan.xcodeproj -scheme MacScan -configuration Release \
  -derivedDataPath "$DERIVED" ARCHS="arm64 x86_64" ONLY_ACTIVE_ARCH=NO CODE_SIGNING_ALLOWED=NO \
  clean build | grep -E "error:|BUILD (SUCCEEDED|FAILED)" || true
[[ -d "$APP" ]] || die "build failed"

VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP/Contents/Info.plist")"
DMG="build/MacScan-$VERSION.dmg"

TIMESTAMP=(--timestamp)
[[ "$IDENTITY" == "-" ]] && TIMESTAMP=() # ad-hoc signatures can't carry a secure timestamp

# Nested bundles first, then the app (inside-out, no --deep).
find "$APP/Contents" -depth -name "*.bundle" -print0 | while IFS= read -r -d '' bundle; do
  codesign --force --sign "$IDENTITY" "${TIMESTAMP[@]+"${TIMESTAMP[@]}"}" "$bundle"
done
codesign --force --sign "$IDENTITY" --options runtime "${TIMESTAMP[@]+"${TIMESTAMP[@]}"}" \
  --entitlements Config/MacScan.entitlements "$APP"
codesign --verify --deep --strict --verbose=2 "$APP"
echo "Built $APP $VERSION ($(lipo -archs "$APP/Contents/MacOS/MacScan")), signed with $IDENTITY"

# --- DMG ---------------------------------------------------------------------------------------
STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT
ditto "$APP" "$STAGING/MacScan.app"
ln -s /Applications "$STAGING/Applications"
rm -f "$DMG"
hdiutil create -volname "MacScan $VERSION" -srcfolder "$STAGING" -fs HFS+ -format UDZO -ov "$DMG" >/dev/null
[[ "$IDENTITY" != "-" ]] && codesign --force --sign "$IDENTITY" --timestamp "$DMG"

# --- Notarize (only with a Developer ID and a notary profile) ----------------------------------
if [[ "$IDENTITY" != "-" && -n "${NOTARY_PROFILE:-}" ]]; then
  xcrun notarytool submit "$DMG" --keychain-profile "$NOTARY_PROFILE" --wait
  xcrun stapler staple "$DMG"
  spctl --assess --type open --context context:primary-signature --verbose=2 "$DMG"
else
  echo "Not notarized."
fi
echo "Release ready: $DMG"
