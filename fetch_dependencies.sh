#!/usr/bin/env sh
set -euo pipefail
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
CSS_DIR="$BASE_DIR/css"
JS_DIR="$BASE_DIR/js"
mkdir -p "$CSS_DIR" "$JS_DIR"

echo "Downloading Bootstrap 5.3.3 CSS..."
curl -L "https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" -o "$CSS_DIR/bootstrap.min.css"

echo "Downloading Bootstrap 5.3.3 JS bundle..."
curl -L "https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" -o "$JS_DIR/bootstrap.bundle.min.js"

echo "Downloading kjua (QR generator)..."
curl -L "https://cdn.jsdelivr.net/npm/kjua@0.1.1/dist/kjua.min.js" -o "$JS_DIR/kjua.min.js"

echo "Done."
