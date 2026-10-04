#!/bin/bash
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"
swift build -j 2 --product agentreins_v2
swift build -j 2 --product AgentReinsNativeHost
swift build -c release -j 2 --product AgentReinsHook
BIN_DIR="$(swift build --show-bin-path)"
HOOK_BIN_DIR="$(swift build -c release --show-bin-path)"
APP_BUNDLE="$PROJECT_DIR/.build/v2-preview/AgentReins v2.app"
mkdir -p "$APP_BUNDLE/Contents/MacOS" "$APP_BUNDLE/Contents/Resources"
cp "$BIN_DIR/agentreins_v2" "$APP_BUNDLE/Contents/MacOS/agentreins_v2"
cp "$BIN_DIR/AgentReinsNativeHost" "$APP_BUNDLE/Contents/MacOS/AgentReinsNativeHost"
cp "$HOOK_BIN_DIR/AgentReinsHook" "$APP_BUNDLE/Contents/MacOS/AgentReinsHook"
cp "$PROJECT_DIR/Assets/AgentReins.icns" "$APP_BUNDLE/Contents/Resources/AgentReins.icns"
cp "$PROJECT_DIR/Resources/agentguard-memory-scan.py" "$APP_BUNDLE/Contents/Resources/"
cp "$PROJECT_DIR/Sources/AgentReins/Resources/workbuddy_network_capture.py" "$APP_BUNDLE/Contents/Resources/"
cp -R "$PROJECT_DIR/BrowserExtension" "$APP_BUNDLE/Contents/Resources/"
cp -R "$BIN_DIR/AgentReins_AgentReins.bundle" "$APP_BUNDLE/Contents/Resources/"
cat > "$APP_BUNDLE/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleName</key><string>AgentReins v2</string>
<key>CFBundleDisplayName</key><string>AgentReins v2</string>
<key>CFBundleIdentifier</key><string>com.agentspec.agentreins.v2.preview</string>
<key>CFBundleExecutable</key><string>agentreins_v2</string>
<key>CFBundleIconFile</key><string>AgentReins</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>2.0.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
codesign --force --deep --sign - "$APP_BUNDLE"
codesign --verify --deep --strict "$APP_BUNDLE"
printf '%s\n' "$APP_BUNDLE"
