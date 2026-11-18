#!/bin/sh
# Run only in the explicitly selected local Docker daemon; never execute the core on the host.
set -eu
if [ "$#" -ne 2 ]; then
  echo "Usage: $0 /absolute/path/to/mihomo-linux-amd64-v1.19.34.gz /absolute/path/to/config.yaml" >&2
  exit 2
fi
archive=$(realpath "$1")
fixture=$(realpath "$2")
[ -f "$archive" ] && [ -f "$fixture" ] || { echo 'Inputs must be regular files' >&2; exit 2; }
expected=223fab877e5795ce780ba39902e5f0b1113c1256ae244a7160f1165e017e9ccc
umask 077
staging=$(mktemp -d /tmp/xkeenwrt-core-validation.XXXXXXXX)
trap 'rm -rf "$staging"' EXIT HUP INT TERM
# Inputs remain private on the host and enter the container only through stdin.
cp "$archive" "$staging/core.gz"
cp "$fixture" "$staging/config.yaml"
actual=$(sha256sum "$staging/core.gz" | cut -d' ' -f1)
[ "$actual" = "$expected" ] || { echo 'Core archive SHA-256 mismatch' >&2; exit 2; }
# Fixed tar entries prevent host path extraction and require no bind mounts.
tar -C "$staging" -cf - core.gz config.yaml | env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
  docker --host=unix:///var/run/docker.sock run -i --rm --pull=never --network=none \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges --pids-limit=64 --memory=256m \
  --tmpfs /work:rw,noexec,nosuid,nodev,size=96m --tmpfs /run-core:rw,exec,nosuid,nodev,size=96m \
  alpine@sha256:bc21487101ae47172509130ee1092cc273a831968d64b617776d1f69c81e42ab \
  sh -ec 'tar -xf - -C /work; gzip -dc /work/core.gz > /run-core/mihomo; chmod 700 /run-core/mihomo; /run-core/mihomo -v; HOME=/work timeout 15 /run-core/mihomo -t -d /work -f /work/config.yaml'
