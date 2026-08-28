#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output_dir=${1:-"$project_root/dist"}
app_dir="$output_dir/ByteTrawl.app"

cd "$project_root"
if [ -n "${BYTETRAWL_CARGO_FEATURES:-}" ]; then
  cargo build --release -p bytetrawl --features "$BYTETRAWL_CARGO_FEATURES"
else
  cargo build --release -p bytetrawl
fi

mkdir -p "$app_dir/Contents/MacOS" "$app_dir/Contents/Resources"
cp "$project_root/target/release/ByteTrawl" "$app_dir/Contents/MacOS/ByteTrawl"
cp "$project_root/packaging/macos/Info.plist" "$app_dir/Contents/Info.plist"
cp "$project_root/packaging/macos/ByteTrawl.icns" "$app_dir/Contents/Resources/ByteTrawl.icns"
chmod 755 "$app_dir/Contents/MacOS/ByteTrawl"

if command -v codesign >/dev/null 2>&1; then
  signing_identity=${BYTETRAWL_SIGNING_IDENTITY:--}
  if [ "$signing_identity" = "-" ]; then
    codesign --force --deep --sign - "$app_dir"
  else
    codesign \
      --force \
      --deep \
      --options runtime \
      --timestamp \
      --sign "$signing_identity" \
      "$app_dir"
  fi
fi

printf '%s\n' "$app_dir"
