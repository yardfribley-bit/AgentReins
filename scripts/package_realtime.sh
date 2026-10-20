#!/bin/bash
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"
export CLANG_MODULE_CACHE_PATH="${CLANG_MODULE_CACHE_PATH:-/private/tmp/agentreins-clang-cache}"
export SWIFTPM_MODULECACHE_OVERRIDE="${SWIFTPM_MODULECACHE_OVERRIDE:-/private/tmp/agentreins-swift-cache}"
BUILD_CONFIGURATION="${AGENTREINS_BUILD_CONFIGURATION:-release}"
swift build --configuration "$BUILD_CONFIGURATION" --disable-sandbox -j 2 --product agentreins_v2
swift build --configuration "$BUILD_CONFIGURATION" --disable-sandbox -j 2 --product AgentReinsHook
swift build --configuration "$BUILD_CONFIGURATION" --disable-sandbox -j 2 --product AgentReinsNativeHost
BIN_DIR="$(swift build --configuration "$BUILD_CONFIGURATION" --disable-sandbox --show-bin-path)"
APP_BUNDLE="$PROJECT_DIR/.build/realtime-preview/AgentReins Realtime.app"
mkdir -p "$APP_BUNDLE/Contents/MacOS" "$APP_BUNDLE/Contents/Resources"
cp "$BIN_DIR/agentreins_v2" "$APP_BUNDLE/Contents/MacOS/agentreins_v2"
cp "$BIN_DIR/AgentReinsHook" "$APP_BUNDLE/Contents/MacOS/AgentReinsHook"
cp "$BIN_DIR/AgentReinsNativeHost" "$APP_BUNDLE/Contents/MacOS/AgentReinsNativeHost"
cp "$PROJECT_DIR/Assets/AgentReins.icns" "$APP_BUNDLE/Contents/Resources/AgentReins.icns"
cp "$PROJECT_DIR/Sources/AgentReins/Resources/workbuddy_network_capture.py" "$APP_BUNDLE/Contents/Resources/"
cp "$PROJECT_DIR/Sources/AgentReins/Resources/content_audit.py" "$APP_BUNDLE/Contents/Resources/"
# Direct app resources avoid SwiftPM's absolute development-path fallback.
cp -R "$PROJECT_DIR/Sources/AgentReins/Resources/RealtimeWorkspace" "$APP_BUNDLE/Contents/Resources/"
# Supervisor MCP (stdio) for Codex — copy next to the app for local discovery.
mkdir -p "$APP_BUNDLE/Contents/Resources/agentreins-mcp"
cp "$PROJECT_DIR/tools/agentreins-mcp/server.py" \
   "$PROJECT_DIR/tools/agentreins-mcp/evidence.py" \
   "$PROJECT_DIR/tools/agentreins-mcp/alerts_bridge.cjs" \
   "$PROJECT_DIR/tools/agentreins-mcp/codex-config.example.toml" \
   "$APP_BUNDLE/Contents/Resources/agentreins-mcp/"
cat > "$APP_BUNDLE/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleName</key><string>AgentReins Realtime</string>
<key>CFBundleDisplayName</key><string>AgentReins Realtime</string>
<key>CFBundleIdentifier</key><string>com.agentspec.agentreins.realtime</string>
<key>CFBundleExecutable</key><string>agentreins_v2</string>
<key>CFBundleIconFile</key><string>AgentReins</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>2.0.0</string>
<key>CFBundleVersion</key><string>realtime-20261009</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
codesign --force --deep --sign - "$APP_BUNDLE"
codesign --verify --deep --strict "$APP_BUNDLE"
printf '%s\n' "$APP_BUNDLE"
