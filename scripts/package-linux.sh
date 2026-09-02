#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output_dir=${1:-"$project_root/dist"}
version=$(sed -n 's/^version = "\([0-9.]*\)"/\1/p' "$project_root/Cargo.toml" | head -1)
arch=$(dpkg --print-architecture)
package_root="$output_dir/bytetrawl_${version}_${arch}"

test -n "$version"
command -v dpkg-deb >/dev/null 2>&1

cd "$project_root"
cargo build --release --locked -p bytetrawl -p bytetrawl-cli

rm -rf "$package_root"
mkdir -p \
  "$package_root/DEBIAN" \
  "$package_root/usr/bin" \
  "$package_root/usr/share/applications" \
  "$package_root/usr/share/icons/hicolor/512x512/apps"

install -m 755 target/release/ByteTrawl "$package_root/usr/bin/bytetrawl"
install -m 755 target/release/bytetrawl-cli "$package_root/usr/bin/bytetrawl-cli"
install -m 644 packaging/linux/bytetrawl.desktop \
  "$package_root/usr/share/applications/bytetrawl.desktop"
install -m 644 packaging/macos/ByteTrawlIcon.png \
  "$package_root/usr/share/icons/hicolor/512x512/apps/bytetrawl.png"

dependencies=$(dpkg-shlibdeps \
  -O \
  -e"$package_root/usr/bin/bytetrawl" \
  -e"$package_root/usr/bin/bytetrawl-cli" \
  2>/dev/null | sed -n 's/^shlibs:Depends=//p')
test -n "$dependencies"

sed \
  -e "s/@VERSION@/$version/g" \
  -e "s/@ARCH@/$arch/g" \
  -e "s/@DEPENDS@/$dependencies/g" \
  packaging/linux/control.in > "$package_root/DEBIAN/control"

mkdir -p "$output_dir"
dpkg-deb --root-owner-group --build "$package_root" \
  "$output_dir/ByteTrawl-${version}-linux-${arch}.deb"

portable_dir="$output_dir/ByteTrawl-${version}-linux-${arch}"
rm -rf "$portable_dir"
mkdir -p "$portable_dir"
install -m 755 target/release/ByteTrawl "$portable_dir/bytetrawl"
install -m 755 target/release/bytetrawl-cli "$portable_dir/bytetrawl-cli"
cp LICENSE README.md "$portable_dir/"
tar -C "$output_dir" -czf "$portable_dir.tar.gz" "$(basename "$portable_dir")"

printf '%s\n' \
  "$output_dir/ByteTrawl-${version}-linux-${arch}.deb" \
  "$portable_dir.tar.gz"
