#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
APP_BUNDLE="$ROOT_DIR/target/release/bundle/macos/ZapDrop.app"
DMG_DIR="$ROOT_DIR/target/release/bundle/dmg"
DMG_NAME="ZapDrop_0.1.0_aarch64.dmg"
DMG_PATH="$DMG_DIR/$DMG_NAME"
RELEASE_MAC_DIR="$ROOT_DIR/release/Mac"

cd "$ROOT_DIR"

./node_modules/.bin/tauri build --bundles app --ci

"$SCRIPT_DIR/embed_share_extension.sh" "$APP_BUNDLE"

mkdir -p "$DMG_DIR" "$RELEASE_MAC_DIR"
STAGE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/beamdrop-dmg-stage.XXXXXX")"
trap 'rm -rf "$STAGE_DIR"' EXIT

ditto "$APP_BUNDLE" "$STAGE_DIR/ZapDrop.app"
ln -s /Applications "$STAGE_DIR/Applications"

rm -f "$DMG_PATH"
hdiutil create \
  -volname "ZapDrop" \
  -srcfolder "$STAGE_DIR" \
  -ov \
  -format UDZO \
  -imagekey zlib-level=9 \
  "$DMG_PATH"

cp "$DMG_PATH" "$RELEASE_MAC_DIR/$DMG_NAME"
echo "Packaged macOS release DMG -> $RELEASE_MAC_DIR/$DMG_NAME"

