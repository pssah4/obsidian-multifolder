#!/bin/bash
set -euo pipefail

# Deploy the built plugin into a local Obsidian vault.
# Usage: ./deploy-local.sh [--build]
#
# Requires a .env file (git-ignored) with:
#   PLUGIN_DIR=/path/to/your/vault/.obsidian/plugins/multifolder
#
# Pass --build to run `npm run build` first. Without it the existing main.js
# is deployed, and the script refuses to run when there is none.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# An explicitly exported PLUGIN_DIR wins over .env, so a one-off deploy to a
# different vault does not require editing the file.
if [ -f "$SCRIPT_DIR/.env" ] && [ -z "${PLUGIN_DIR:-}" ]; then
  # shellcheck disable=SC1091
  source "$SCRIPT_DIR/.env"
fi

if [ -z "${PLUGIN_DIR:-}" ]; then
  echo "Error: PLUGIN_DIR not set. Copy .env.example to .env and set it:" >&2
  echo "  PLUGIN_DIR=/path/to/your/vault/.obsidian/plugins/multifolder" >&2
  exit 1
fi

if [ "${1:-}" = "--build" ]; then
  echo "Building..."
  npm run build
fi

if [ ! -f main.js ]; then
  echo "Error: main.js not found. Run 'npm run build' or pass --build." >&2
  exit 1
fi

# The manifest id must match the folder name, otherwise Obsidian ignores the
# plugin without saying why.
MANIFEST_ID=$(node -p "require('./manifest.json').id")
TARGET_NAME=$(basename "$PLUGIN_DIR")
if [ "$MANIFEST_ID" != "$TARGET_NAME" ]; then
  echo "Error: manifest id '$MANIFEST_ID' does not match target folder '$TARGET_NAME'." >&2
  echo "Obsidian would not load the plugin. Fix PLUGIN_DIR in .env." >&2
  exit 1
fi

echo "Deploying Multifolder $(node -p "require('./manifest.json').version") to: $PLUGIN_DIR"

mkdir -p "$PLUGIN_DIR"
cp manifest.json "$PLUGIN_DIR/"
cp main.js "$PLUGIN_DIR/"
cp styles.css "$PLUGIN_DIR/"

# Verify what landed, so a half-written copy does not look like a success.
for f in manifest.json main.js styles.css; do
  if ! cmp -s "$f" "$PLUGIN_DIR/$f"; then
    echo "Error: $f differs after copy." >&2
    exit 1
  fi
done

echo "Deployment complete, 3 files verified."
echo ""
echo "Next steps:"
echo "1. Settings -> Community plugins -> reload, then enable Multifolder"
echo "2. Or reload Obsidian (Cmd/Ctrl + R) if it is already enabled"
