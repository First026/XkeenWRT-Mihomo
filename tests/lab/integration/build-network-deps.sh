#!/bin/sh
set -eu
[ "$#" -eq 0 ] && [ "$(id -u)" -ne 0 ] || exit 2
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
archive=/workspace/attachments/9afdeee4-bca6-4ee4-9ab7-b1ef46846052/xkeenwrt-lab-openwrt-25.12.6.tar.gz
packages=/workspace/.cache/xkeenwrt/lab-packages-25.12.6-b01b2991/xkeenwrt-lab-openwrt-25.12.6
printf '%s  %s\n' b01b299132987e4ba9a860c1abd2e64fc4b08b888c0069832acd029eca62a720 "$archive" | sha256sum -c -
(cd "$packages" && sha256sum -c SHA256SUMS >/dev/null)
id=$(env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH docker --host=unix:///var/run/docker.sock image inspect xkeen-openwrt-vm:25.12.6 --format '{{.Id}}')
[ "$id" = sha256:4c7477b7851e7d9788771d7532f70109d76292627a9017ce0f6b68e04827a052 ]
tmp=$(mktemp -d); trap 'rm -rf -- "$tmp"' EXIT
mkdir "$tmp/packages"; cp "$packages"/x86_64/*.apk "$tmp/packages/"; mkdir "$tmp/packages/indexes"; cp "$packages"/indexes/x86-*.adb* "$tmp/packages/indexes/"; cp "$script_dir/network-deps-guest.sh" "$tmp/guest"; chmod 755 "$tmp/guest"; cp "$script_dir/Dockerfile.network-deps" "$tmp/Dockerfile"
env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH docker --host=unix:///var/run/docker.sock build -t xkeen-openwrt-vm-network-deps:25.12.6 "$tmp"
