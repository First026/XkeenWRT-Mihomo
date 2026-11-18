#!/bin/sh
set -eu
case "${1:-}" in "") [ "$#" -eq 0 ] || exit 2; peer=/workspace/.cache/xkeenwrt/awg-peer-x86.final; peer_hash=a383c86b224822a55cd628c8faa267276c564b674901583e484a7a2e69adea00 ;; --v3) [ "$#" -eq 1 ] || exit 2; peer=/workspace/.cache/xkeenwrt/awg-peer-v3-x86; peer_hash=1dac559166271eb0099d88458939f584bfb633d35aea54f5e67697a236f6dd8c ;; *) echo 'usage: build-awg-image.sh [--v3]' >&2; exit 2;; esac
[ "$(id -u)" -ne 0 ] || exit 1
: "${LAB_PROXY_CA:?Set LAB_PROXY_CA}"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
printf '%s  %s\n' "$peer_hash" "$peer" | sha256sum -c -
readelf -h "$peer" | grep -Eq 'Machine:.*Advanced Micro Devices X86-64'
if readelf -l "$peer" | grep -q INTERP || readelf -d "$peer" 2>/dev/null | grep -q NEEDED; then exit 1; fi
image_id=$(env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH docker --host=unix:///var/run/docker.sock image inspect xkeen-openwrt-vm-validator-test:25.12.6 --format '{{.Id}}')
[ "$image_id" = 'sha256:4d08c9cd021baafb209ec3238997ecc736c3cec828bce7df311c27185ddfd2b1' ] || { echo 'ERROR: неподтверждённый образ validator VM' >&2; exit 1; }
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
trap 'exit 1' HUP INT TERM
cp "$peer" "$tmp/awg-peer"
chmod 755 "$tmp/awg-peer"
cp "$script_dir/awg-smoke.sh" "$tmp/awg-smoke.sh"
chmod 755 "$tmp/awg-smoke.sh"
cp "$script_dir/Dockerfile.awg" "$tmp/Dockerfile"
env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
  docker --host=unix:///var/run/docker.sock build --secret "id=proxy_ca,src=$LAB_PROXY_CA" -t xkeen-openwrt-vm-awg-test:25.12.6 "$tmp"
