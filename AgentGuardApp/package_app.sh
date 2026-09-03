#!/bin/bash
# 编译 + 打包 + 签名 + 清除隔离属性，产出可在本机双击打开的 AgentReins.app
# 说明：本机无 Developer ID 证书时只能 ad-hoc 签名（同机可用，跨机/分发需 Developer ID + 公证）。
set -e
cd "$(dirname "$0")"

echo "==> swift build -c release"
swift build -c release

echo "==> 组装 .app"
rm -rf AgentReins.app
mkdir -p AgentReins.app/Contents/MacOS AgentReins.app/Contents/Resources
cp .build/release/AgentReins AgentReins.app/Contents/MacOS/AgentReins
chmod +x AgentReins.app/Contents/MacOS/AgentReins
cp ../agentguard/agentguard-memory-scan.py AgentReins.app/Contents/Resources/ 2>/dev/null || \
  cp /Users/jatsmith/AgentSpec/agentguard/agentguard-memory-scan.py AgentReins.app/Contents/Resources/

# 版本与构建日期：每次打包自动写入，便于用户判断手里的 .app 是否最新
BUILD_DATE=$(date "+%Y-%m-%d %H:%M")
BUILD_NUM=$(date "+%Y%m%d.%H%M")
SHORT_VER="1.1.0"
echo "    版本 v$SHORT_VER · build $BUILD_NUM · 构建于 $BUILD_DATE"
cat > AgentReins.app/Contents/Info.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>AgentReins</string>
  <key>CFBundleDisplayName</key><string>AgentReins</string>
  <key>CFBundleIdentifier</key><string>com.agentspec.agentreins</string>
  <key>CFBundleVersion</key><string>$BUILD_NUM</string>
  <key>CFBundleShortVersionString</key><string>$SHORT_VER</string>
  <key>AGRBuiltDate</key><string>$BUILD_DATE</string>
  <key>CFBundleExecutable</key><string>AgentReins</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
EOF

echo "==> ad-hoc 签名 (本机无 Developer ID 证书)"
codesign --force --deep --sign - AgentReins.app

echo "==> 清除隔离属性 (否则 macOS 26 仍报'无法验证开发者')"
xattr -dr com.apple.quarantine AgentReins.app 2>/dev/null || true
xattr -dr com.apple.provenance AgentReins.app 2>/dev/null || true
xattr -cr AgentReins.app 2>/dev/null || true

echo "==> 完成: $(du -sh AgentReins.app | cut -f1)"
codesign -vvv AgentReins.app 2>&1 | head -2
