#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TAURI_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$TAURI_DIR/.." && pwd)"

APP_BUNDLE="${1:-$ROOT_DIR/target/release/bundle/macos/ZapDrop.app}"
if [[ ! -d "$APP_BUNDLE" ]]; then
  echo "Error: ZapDrop.app bundle not found at: $APP_BUNDLE" >&2
  exit 1
fi

APPEX_NAME="BeamDropShare.appex"
PLUGINS_DIR="$APP_BUNDLE/Contents/PlugIns"
APPEX_DIR="$PLUGINS_DIR/$APPEX_NAME"
APPEX_CONTENTS="$APPEX_DIR/Contents"
APPEX_MACOS="$APPEX_CONTENTS/MacOS"
APPEX_RESOURCES="$APPEX_CONTENTS/Resources"

rm -rf "$APPEX_DIR"
mkdir -p "$APPEX_MACOS" "$APPEX_RESOURCES"

resolve_macos_sdk() {
  for candidate in \
    "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk" \
    "/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk" \
    "/Library/Developer/CommandLineTools/SDKs/MacOSX15.4.sdk"
  do
    if [[ -d "$candidate" ]]; then
      echo "$candidate"
      return 0
    fi
  done
  xcrun --sdk macosx --show-sdk-path
}

MACOS_SDK="$(resolve_macos_sdk)"
MODULE_CACHE="/tmp/beamdrop-swift-modcache"
mkdir -p "$MODULE_CACHE"

echo "Compiling macOS Share Extension (arm64-apple-macos11.0, SDK: $MACOS_SDK)..."
env -u SDKROOT TMPDIR="/tmp" xcrun swiftc \
  -O \
  -sdk "$MACOS_SDK" \
  -module-cache-path "$MODULE_CACHE" \
  -parse-as-library \
  -application-extension \
  -target arm64-apple-macos11.0 \
  -module-name BeamDropShare \
  -Xlinker -e -Xlinker _NSExtensionMain \
  -framework Cocoa \
  -framework Foundation \
  -framework UniformTypeIdentifiers \
  "$SCRIPT_DIR/ShareViewController.swift" \
  -o "$APPEX_MACOS/BeamDropShare"

chmod +x "$APPEX_MACOS/BeamDropShare"

sed 's/\$(PRODUCT_MODULE_NAME)/BeamDropShare/g' \
  "$SCRIPT_DIR/Info.plist" > "$APPEX_CONTENTS/Info.plist"
plutil -lint "$APPEX_CONTENTS/Info.plist"

ICON_SRC="$APP_BUNDLE/Contents/Resources/icon.icns"
if [[ ! -f "$ICON_SRC" ]]; then
  ICON_SRC="$TAURI_DIR/icons/icon.icns"
fi
cp "$ICON_SRC" "$APPEX_RESOURCES/icon.icns"

echo "Signing BeamDropShare.appex and ZapDrop.app..."
codesign --force --sign - \
  --entitlements "$SCRIPT_DIR/BeamDropShare.entitlements" \
  "$APPEX_DIR"

# Re-sign the enclosing app without --deep so the embedded extension keeps its entitlements.
codesign --force --sign - "$APP_BUNDLE"

codesign --verify --deep --strict --verbose=2 "$APP_BUNDLE"
echo "Embedded Share Extension successfully into: $APPEX_DIR"

