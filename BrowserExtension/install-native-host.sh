#!/bin/bash
set -euo pipefail

APP_PATH="${1:-/Applications/AgentReins.app}"
HOST_BINARY="$APP_PATH/Contents/MacOS/AgentReinsNativeHost"
TEMPLATE="$APP_PATH/Contents/Resources/BrowserExtension/native-host.json"

if [[ ! -x "$HOST_BINARY" ]]; then
  echo "AgentReins Native Host was not found at: $HOST_BINARY" >&2
  exit 1
fi

for DIRECTORY in \
  "$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts" \
  "$HOME/Library/Application Support/Microsoft Edge/NativeMessagingHosts"; do
  mkdir -p "$DIRECTORY"
  sed "s|__AGENTREINS_NATIVE_HOST__|$HOST_BINARY|g" "$TEMPLATE" \
    > "$DIRECTORY/com.agentspec.agentreins.web.json"
  echo "Installed Native Messaging manifest: $DIRECTORY"
done
