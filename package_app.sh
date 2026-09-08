#!/bin/bash
# Build and package a Universal 2 macOS application.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

APP_NAME="AgentReins"
APP_BUNDLE="$PROJECT_DIR/$APP_NAME.app"
VERSION="${AGENTREINS_VERSION:-1.1.0}"
BUILD_NUMBER="${AGENTREINS_BUILD_NUMBER:-$(date -u '+%Y%m%d.%H%M')}"
BUILD_DATE="${AGENTREINS_BUILD_DATE:-$(date -u '+%Y-%m-%dT%H:%M:%SZ')}"
SIGNING_IDENTITY="${CODE_SIGN_IDENTITY:--}"

echo "==> Building Universal 2 release binary (arm64 + x86_64)"
BIN_DIR="$(swift build -c release --arch arm64 --arch x86_64 --show-bin-path)"
swift build -c release --arch arm64 --arch x86_64

echo "==> Creating $APP_NAME.app"
rm -rf "$APP_BUNDLE"
mkdir -p "$APP_BUNDLE/Contents/MacOS" "$APP_BUNDLE/Contents/Resources"
cp "$BIN_DIR/$APP_NAME" "$APP_BUNDLE/Contents/MacOS/$APP_NAME"
chmod +x "$APP_BUNDLE/Contents/MacOS/$APP_NAME"
cp "$PROJECT_DIR/Resources/agentguard-memory-scan.py" "$APP_BUNDLE/Contents/Resources/"
cp "$PROJECT_DIR/Assets/AgentReins.icns" "$APP_BUNDLE/Contents/Resources/AgentReins.icns"

cat > "$APP_BUNDLE/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>$APP_NAME</string>
  <key>CFBundleDisplayName</key><string>$APP_NAME</string>
  <key>CFBundleIdentifier</key><string>com.agentspec.agentreins</string>
  <key>CFBundleVersion</key><string>$BUILD_NUMBER</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>AGRBuiltDate</key><string>$BUILD_DATE</string>
  <key>CFBundleExecutable</key><string>$APP_NAME</string>
  <key>CFBundleIconFile</key><string>AgentReins</string>
  <key>CFBundleIconName</key><string>AgentReins</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
EOF

echo "==> Signing with: $SIGNING_IDENTITY"
codesign --force --deep --options runtime --timestamp --sign "$SIGNING_IDENTITY" "$APP_BUNDLE"

echo "==> Verifying package"
codesign --verify --deep --strict --verbose=2 "$APP_BUNDLE"
ARCHITECTURES="$(lipo -archs "$APP_BUNDLE/Contents/MacOS/$APP_NAME")"
[[ "$ARCHITECTURES" == *arm64* && "$ARCHITECTURES" == *x86_64* ]] || {
  echo "error: expected arm64 and x86_64, found: $ARCHITECTURES" >&2
  exit 1
}

echo "==> Complete: $APP_BUNDLE"
echo "    Version: $VERSION ($BUILD_NUMBER)"
echo "    Architectures: $ARCHITECTURES"
