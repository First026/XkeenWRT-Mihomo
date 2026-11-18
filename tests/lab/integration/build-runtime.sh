#!/bin/sh
set -eu
[ "$#" -eq 0 ] || { echo 'usage: build-runtime.sh' >&2; exit 2; }
[ "$(id -u)" -ne 0 ] || { echo 'ERROR: build as an ordinary user' >&2; exit 1; }
: "${LAB_PROXY_CA:?Set LAB_PROXY_CA}"
: "${XKEENWRT_BUILD_ID:?Set build ID from package-build-id.sh}"
[ "${#XKEENWRT_BUILD_ID}" -eq 64 ] || { echo "ERROR: invalid build ID" >&2; exit 1; }
case "$XKEENWRT_BUILD_ID" in *[!0-9a-f]*) echo "ERROR: invalid build ID" >&2; exit 1;; esac
case "${XKEENWRT_PACKAGE_VERSION:-}" in 0.1-r1|0.1-r2) ;; *) echo "ERROR: select fixed package version 0.1-r1 or 0.1-r2" >&2; exit 1;; esac
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
trap 'exit 1' HUP INT TERM
if [ -n "${XKEEN_LAB_RUNTIME_SNAPSHOT:-}" ]; then
  snapshot=$XKEEN_LAB_RUNTIME_SNAPSHOT
else
  snapshot="$tmp/source"
  mkdir "$snapshot"
  (cd "$repo" && tar --exclude=backend/target --exclude=crates/profile-policy/target --exclude=recovery/target -cf - backend crates/profile-policy recovery frontend/dist) | tar -C "$snapshot" -xf -
fi
[ -f "$snapshot/backend/Cargo.lock" ] && [ -d "$snapshot/crates/profile-policy" ] && [ -d "$snapshot/frontend/dist" ] || { echo 'ERROR: frozen runtime snapshot missing' >&2; exit 1; }
cp "$script_dir/Dockerfile.musl-build" "$tmp/Dockerfile"
env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
  docker --host=unix:///var/run/docker.sock build --secret "id=proxy_ca,src=$LAB_PROXY_CA" -t xkeenwrt-lab-musl-builder:bookworm "$tmp"
image_id=$(env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH docker --host=unix:///var/run/docker.sock image inspect xkeenwrt-lab-musl-builder:bookworm --format '{{.Id}}')
[ "$image_id" = sha256:8056f12bd38bdbba501702f690d815ae1281d9cd3b1eb178106ab0acecda3386 ] || { echo "ERROR: build image identity changed" >&2; exit 1; }
env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
  docker --host=unix:///var/run/docker.sock run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  --user "$(id -u):$(id -g)" --memory 2g --memory-swap 2g --pids-limit 256 --cpus 2 \
  --mount "type=bind,src=$snapshot,dst=/src,readonly" \
  --mount "type=bind,src=$repo/backend/target,dst=/out" \
  --mount "type=bind,src=$HOME/.cargo,dst=/cargo" --mount "type=bind,src=$HOME/.rustup,dst=/rustup,readonly" \
  -e HOME=/tmp -e CARGO_HOME=/cargo -e RUSTUP_HOME=/rustup -e RUSTUP_TOOLCHAIN=1.99.1 \
  -e PATH=/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  -e CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld -e CC_x86_64_unknown_linux_musl=musl-gcc \
  -e 'RUSTFLAGS=-C linker-flavor=ld.lld -C target-feature=+crt-static' \
  -e CARGO_INCREMENTAL=0 -e CARGO_PROFILE_DEV_DEBUG=0 -e CARGO_PROFILE_DEV_OPT_LEVEL=2 \
  -e "XKEENWRT_PACKAGE_VERSION=$XKEENWRT_PACKAGE_VERSION" -e "XKEENWRT_BUILD_ID=$XKEENWRT_BUILD_ID" -w /src/backend xkeenwrt-lab-musl-builder:bookworm \
  cargo build --target-dir /out --target x86_64-unknown-linux-musl --features lab-hooks --bin xkeenwrt-ui --locked --offline -j 1
binary="$repo/backend/target/x86_64-unknown-linux-musl/debug/xkeenwrt-ui"
readelf -h "$binary" | grep -Eq 'Machine:.*Advanced Micro Devices X86-64'
if readelf -l "$binary" | grep -q INTERP || readelf -d "$binary" 2>/dev/null | grep -q NEEDED; then echo 'ERROR: non-static ELF' >&2; exit 1; fi
sha256sum "$binary"
