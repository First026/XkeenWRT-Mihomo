#!/bin/sh
set -eu
[ "$#" -eq 0 ] || { echo 'usage: build-runtime-image.sh' >&2; exit 2; }
[ "$(id -u)" -ne 0 ] || exit 1
: "${LAB_PROXY_CA:?Set LAB_PROXY_CA}"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
binary="$repo/backend/target/x86_64-unknown-linux-musl/debug/xkeenwrt-ui"
printf '%s  %s\n' 8deddd151c29c7ab6b764d9581f85137cb7e45b6e252af07e2cdd9686150c80b "$binary" | sha256sum -c -
image_id=$(env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH docker --host=unix:///var/run/docker.sock image inspect xkeen-openwrt-vm-validator-test:25.12.6 --format '{{.Id}}')
[ "$image_id" = 'sha256:cc274926d5c49b6671f75a1bd320d6665acf4803eff75016567a2396be924fc2' ] || { echo 'ERROR: validator test image differs from frozen baseline' >&2; exit 1; }
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
trap 'exit 1' HUP INT TERM
strip --strip-debug -o "$tmp/xkeenwrt-ui" "$binary"
chmod 755 "$tmp/xkeenwrt-ui"
sha256sum "$tmp/xkeenwrt-ui"
mkdir "$tmp/init"
source_dir=${XKEEN_LAB_RUNTIME_SNAPSHOT:-$repo}
for script in xkeenwrt-core xkeenwrt-runtime xkeenwrt-ui; do cp "$source_dir/openwrt/xkeenwrt-ui/files/etc/init.d/$script" "$tmp/init/$script"; chmod 755 "$tmp/init/$script"; done
rustc +1.99.1 --target x86_64-unknown-linux-musl -O "$script_dir/http-wire.rs" -o "$tmp/http-wire"
readelf -h "$tmp/http-wire" | grep -Eq 'Machine:.*Advanced Micro Devices X86-64'
if readelf -l "$tmp/http-wire" | grep -q INTERP || readelf -d "$tmp/http-wire" 2>/dev/null | grep -q NEEDED; then exit 1; fi
chmod 755 "$tmp/http-wire"
sha256sum "$tmp/http-wire"
cp "$script_dir/runtime-smoke.sh" "$tmp/runtime-smoke.sh"
chmod 755 "$tmp/runtime-smoke.sh"
cp "$script_dir/Dockerfile.runtime" "$tmp/Dockerfile"
env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
  docker --host=unix:///var/run/docker.sock build --secret "id=proxy_ca,src=$LAB_PROXY_CA" -t xkeen-openwrt-vm-runtime-test:25.12.6 "$tmp"
