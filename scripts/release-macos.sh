#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  printf 'usage: %s VERSION\n' "$0" >&2
  exit 2
fi

version=$1
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
release_dir="$project_root/dist/release-$version"
app_dir="$release_dir/ByteTrawl.app"
app_zip="$release_dir/ByteTrawl-$version-macos.zip"
cli_stage="$release_dir/bytetrawl-cli-$version-aarch64-apple-darwin"
cli_archive="$release_dir/bytetrawl-cli-$version-aarch64-apple-darwin.tar.gz"

case "$version" in
  *[!0-9.]*|'')
    printf 'VERSION must contain only digits and dots\n' >&2
    exit 2
    ;;
esac

mkdir -p "$release_dir" "$cli_stage"

BYTETRAWL_SIGNING_IDENTITY=${BYTETRAWL_SIGNING_IDENTITY:?set BYTETRAWL_SIGNING_IDENTITY}
export BYTETRAWL_SIGNING_IDENTITY
"$project_root/scripts/build-macos-app.sh" "$release_dir"

codesign --verify --deep --strict --verbose=2 "$app_dir"

cargo build --release --locked -p bytetrawl-cli --manifest-path "$project_root/Cargo.toml"
cp "$project_root/target/release/bytetrawl-cli" "$cli_stage/bytetrawl-cli"
cp "$project_root/README.md" "$cli_stage/README.md"
chmod 755 "$cli_stage/bytetrawl-cli"

ditto -c -k --keepParent "$app_dir" "$app_zip"
tar -C "$release_dir" -czf "$cli_archive" "$(basename "$cli_stage")"

shasum -a 256 "$app_zip" "$cli_archive"
printf '%s\n%s\n' "$app_zip" "$cli_archive"
