#!/usr/bin/env bash
set -euo pipefail

# Convert all panal/panag logo PNGs in ./img to JPEG at max quality.
# Output JPEGs will be created alongside the PNGs with .jpg extension.
# Requires ImageMagick (convert).

dir="$(cd "$(dirname "$0")" && pwd)/img"
cd "$dir"

if ! command -v convert >/dev/null 2>&1; then
  echo "convert (ImageMagick) is required. Install it first." >&2
  exit 1
fi

shopt -s nullglob
pngs=(panal-logo-*.png panag-logo-*.png)
shopt -u nullglob

if [ ${#pngs[@]} -eq 0 ]; then
  echo "No matching PNGs found (panal-logo-*.png or panag-logo-*.png)." >&2
  exit 0
fi

echo "Converting ${#pngs[@]} file(s) to JPEG at max quality..."
for src in "${pngs[@]}"; do
  base="${src%.png}"
  dest="${base}.jpg"
  convert "$src" -quality 100 "$dest"
  echo "Created $dest"
done

echo "Done."
