#!/bin/sh
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
base=$(docker image inspect xkeen-openwrt-vm-apk-lifecycle:25.12.6 --format '{{.Id}}')
[ "$base" = 'sha256:9e4b573afea248ad9a9c38d3f1d93f9909a019984e2db0856cfb892d7aceea99' ] || { echo 'unexpected frozen image' >&2; exit 1; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
cp "$repo/backend/target/x86_64-unknown-linux-musl/debug/validator-diff" "$tmp/validator-diff"
cp /tmp/xkeen-validator-diff-freeze/request.json "$tmp/request.json"
printf '%s  %s\n' 2348360f116475541cec96b56707c65f8f60f92ecb77f6098071504a50a830c6 "$tmp/validator-diff" | sha256sum -c -
printf '%s  %s\n' a35fe44a46ff95bdf796d45b241260dc2d00fd74cd70e8f112d9cb116e26d0cd "$tmp/request.json" | sha256sum -c -
cp "$script_dir/validator-diff-guest.sh" "$tmp/validator-diff-guest.sh"
cp "$script_dir/Dockerfile.validator-diff" "$tmp/Dockerfile"
docker build --network none -t xkeen-openwrt-vm-validator-diff:25.12.6 "$tmp"
