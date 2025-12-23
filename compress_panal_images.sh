#!/usr/bin/env bash
set -euo pipefail

# Resize all panal/panag logo images in ./img to 600px width (preserve aspect ratio).
# Requires ImageMagick (mogrify). This overwrites the originals; make a backup if needed.

dir="$(cd "$(dirname "$0")" && pwd)/img"
cd "$dir"

if ! command -v mogrify >/dev/null 2>&1; then
  echo "mogrify (ImageMagick) is required. Install it first." >&2
  exit 1
fi

shopt -s nullglob
files=(panal-logo-*.png panag-logo-*.png)
shopt -u nullglob

if [ ${#files[@]} -eq 0 ]; then
  echo "No matching images found (panal-logo-*.png or panag-logo-*.png)." >&2
  exit 0
fi

echo "Resizing ${#files[@]} file(s) to 600px width..."
# -resize 600x keeps width at 600, height auto; -strip removes metadata; -quality 90 for slight compression
mogrify -resize 600x -strip -quality 90 -- "${files[@]}"

echo "Done."
