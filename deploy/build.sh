#!/usr/bin/env bash
# Build the ARM64 Linux binary and (optionally) upload it to your server.
# Usage:
#   ./deploy/build.sh                      # just build -> ./dist/agent-illusion
#   ./deploy/build.sh user@SERVER_IP       # build + scp to server:/opt/agent-illusion/
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p dist

echo "==> Building linux/arm64 binary..."
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "-s -w" -o dist/agent-illusion .
echo "    -> dist/agent-illusion ($(du -h dist/agent-illusion | cut -f1))"

if [ "${1:-}" != "" ]; then
  TARGET="$1"
  echo "==> Uploading to ${TARGET}:/opt/agent-illusion/ ..."
  ssh "$TARGET" 'sudo mkdir -p /opt/agent-illusion && sudo chown $(whoami) /opt/agent-illusion'
  scp dist/agent-illusion "$TARGET":/opt/agent-illusion/agent-illusion.new
  ssh "$TARGET" 'cd /opt/agent-illusion && chmod +x agent-illusion.new && mv agent-illusion.new agent-illusion && (sudo systemctl restart agent-illusion 2>/dev/null || true)'
  echo "    -> uploaded. If the service exists it was restarted."
fi

echo "Done."
