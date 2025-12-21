#!/usr/bin/env bash
set -euo pipefail

# Sync the current project to the mounted volume. Adjust rsync excludes as needed.
SRC="$HOME/source/panag/"
DEST="/Volumes/www/panag/"

if [ ! -d "$DEST" ]; then
  echo "Destination $DEST is not available (check mount)." >&2
  exit 1
fi

rsync -avh \
  --exclude ".git/" \
  --exclude "*.DS_Store" \
  "$SRC" "$DEST"

echo "Sync complete: $SRC -> $DEST"