#!/usr/bin/env bash
set -euo pipefail

# Wrapper that guarantees safe parameters for the runner.
# Author: Wagner Azevedo
# Created on: 2025-10-16T00:55:00Z
# Usage:
#   ./run-multicloud-wrapper.sh acme aws 767397997901
#   or export CLIENT_NAME, CLOUD_PROVIDER, ACCOUNT_ID and execute without args.

CLIENT_NAME="${CLIENT_NAME:-${1:-undefined}}"
CLOUD_PROVIDER="${CLOUD_PROVIDER:-${2:-undefined}}"
ACCOUNT_ID="${ACCOUNT_ID:-${3:-undefined}}"

echo "[WRAPPER] 🧭 Performing runner with:"
echo "  CLIENT_NAME=$CLIENT_NAME"
echo "  CLOUD_PROVIDER=$CLOUD_PROVIDER"
echo "  ACCOUNT_ID=$ACCOUNT_ID"

if [ ! -x /usr/local/bin/run-multicloudassessment.sh ]; then
  echo "[WRAPPER] ❌ Runner not found or without execution permission."
  exit 1
fi

# Perform the runner with arguments always defined
exec /usr/local/bin/run-multicloudassessment.sh "$CLIENT_NAME" "$CLOUD_PROVIDER" "$ACCOUNT_ID"
