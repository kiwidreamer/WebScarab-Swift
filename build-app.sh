#!/bin/sh
# Builds the release version of WebScarab (Swift) and puts the finished app in
# WebScarabSwift/Build/WebScarab.app, ready to open or drag into Applications.
set -eu

cd "$(dirname "$0")"
OUT="Build"

xcodebuild -project WebScarab.xcodeproj -scheme WebScarab -configuration Release -destination 'generic/platform=macOS' build -quiet

PRODUCTS=$(xcodebuild -project WebScarab.xcodeproj -scheme WebScarab -configuration Release -showBuildSettings 2>/dev/null \
  | awk -F' = ' '/ BUILT_PRODUCTS_DIR = / { print $2; exit }')

mkdir -p "$OUT"
rm -rf "$OUT/WebScarab.app"
ditto "$PRODUCTS/WebScarab.app" "$OUT/WebScarab.app"
echo "Built: $(pwd)/$OUT/WebScarab.app"
