#!/bin/sh
set -eu
[ "$#" -eq 0 ] && [ "$(id -u)" -ne 0 ] || exit 2
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
dir="$repo/backend/target/x86_64-unknown-linux-musl/debug/examples"
printf '%s  %s\n' aaf168cfb7f0824b308f4b053761c08f5d789c48747c76f352209e7d0fe97306 "$dir/lab_clone_parent" | sha256sum -c -
printf '%s  %s\n' 62e5fac2057a31fbc5c3e3699d7f44e4c26e717bc4ed79f6b6882f8ca7428e74 "$dir/lab_clone_exec" | sha256sum -c -
id=$(env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH docker --host=unix:///var/run/docker.sock image inspect xkeen-openwrt-vm:25.12.6 --format '{{.Id}}')
[ "$id" = sha256:4c7477b7851e7d9788771d7532f70109d76292627a9017ce0f6b68e04827a052 ]
tmp=$(mktemp -d); trap 'rm -rf -- "$tmp"' EXIT
cp "$dir/lab_clone_parent" "$tmp/parent"; cp "$dir/lab_clone_exec" "$tmp/probe"; cp "$script_dir/clone3-guest.sh" "$tmp/guest"; chmod 755 "$tmp/parent" "$tmp/probe" "$tmp/guest"
cp "$script_dir/Dockerfile.clone3" "$tmp/Dockerfile"
env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH docker --host=unix:///var/run/docker.sock build -t xkeen-openwrt-vm-clone3-test:25.12.6 "$tmp"
