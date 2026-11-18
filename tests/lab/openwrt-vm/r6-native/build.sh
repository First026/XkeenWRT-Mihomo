#!/bin/sh
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
bundle=/workspace/.cache/xkeenwrt/lab-packages-25.12.6-b01b2991/xkeenwrt-lab-openwrt-25.12.6
r10=/tmp/xkeenwrt-arm64-current-20261113/r10
tag=xkeen-openwrt-vm-r6-native:25.12.6
builder_image=xkeenwrt-lab-musl-builder:bookworm
builder_image_id=sha256:8056f12bd38bdbba501702f690d815ae1281d9cd3b1eb178106ab0acecda3386
sdk_source=/home/dockerd/.local/share/docker/vfs/dir/6054b6ee3a1dbdb3dfed68a084d7b67e76db5e58e0a7f0cdce618d816e684772
toolchain="$sdk_source/builder/staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl"
host_lib="$sdk_source/builder/staging_dir/host/lib"
cargo_home=${CARGO_HOME:-$HOME/.cargo}
rustup_home=${RUSTUP_HOME:-$HOME/.rustup}
docker_local() {
  env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
    docker --host=unix:///var/run/docker.sock "$@"
}
[ "$(docker_local image inspect xkeen-openwrt-vm-arm64:25.12.6 --format '{{.Id}}')" = \
  sha256:d969a5d44756b89076e45dbb66e3a83d585643b9554aa944389ef221211def32 ] || {
  echo 'ERROR: armsr VM image identity changed' >&2; exit 1;
}
[ "$(docker_local image inspect "$builder_image" --format '{{.Id}}')" = "$builder_image_id" ] || {
  echo 'ERROR: cached musl builder image identity changed' >&2; exit 1;
}
(
  cd "$bundle"
  sha256sum -c SHA256SUMS >/dev/null
)
printf '%s  %s\n' b14951e627892745938334ba0c7074e0b768a8af29d28ba29198ef40933f0d89 "$r10/product/apks/xkeenwrt-core-0.1-r10.apk" | sha256sum -c -
printf '%s  %s\n' 9e7e0ecfabc7061d730ef5812a31d459111812dfad643c96366af538bfcb3e42 "$r10/product/apks/xkeenwrt-ui-0.1-r10.apk" | sha256sum -c -
printf '%s  %s\n' 61e2d1e6a2f085e1102c375b2b7f877e2b5581ede8ecc659d76782d09defdcc6 "$bundle/indexes/arm64-base.adb" | sha256sum -c -
printf '%s  %s\n' e2814aa9b2ca16dece606dd4f4c88b5b5e01e3913d1127d97e54023245c3657a "$bundle/indexes/arm64-core.adb" | sha256sum -c -
printf '%s  %s\n' a9a137f0e30c823ec9a142aedafc2d34029bc6739e33ce4778d644ba32473da3 "$bundle/indexes/arm64-kmods.adb" | sha256sum -c -
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT HUP INT TERM
mkdir -p "$tmp/input/arm64"
mkdir -p /tmp/xkeenwrt-r6-native-helper
docker_local run --rm --network none --cap-drop ALL --security-opt no-new-privileges --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m --user "$(id -u):$(id -g)" \
  --mount "type=bind,src=$script_dir/http-wire.rs,dst=/http-wire.rs,readonly" \
  --mount type=bind,src=/tmp/xkeenwrt-r6-native-helper,dst=/out \
  --mount "type=bind,src=$cargo_home,dst=/cargo,readonly" \
  --mount "type=bind,src=$rustup_home,dst=/rustup,readonly" \
  --mount "type=bind,src=$toolchain,dst=/builder/staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl,readonly" \
  --mount "type=bind,src=$host_lib,dst=/builder/staging_dir/host/lib,readonly" \
  -e HOME=/tmp -e CARGO_HOME=/cargo -e RUSTUP_HOME=/rustup -e RUSTUP_TOOLCHAIN=1.99.1 \
  -e STAGING_DIR=/builder/staging_dir -e PATH=/cargo/bin:/usr/local/bin:/usr/bin:/bin \
  "$builder_image" rustc --edition=2024 --target aarch64-unknown-linux-musl \
  -C linker=/builder/staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl/bin/aarch64-openwrt-linux-musl-gcc \
  -C target-cpu=cortex-a53 -C opt-level=s -C strip=symbols /http-wire.rs -o /out/http-wire
file /tmp/xkeenwrt-r6-native-helper/http-wire | grep -q 'ARM aarch64.*statically linked'
if readelf -l /tmp/xkeenwrt-r6-native-helper/http-wire | grep -q INTERP; then
  echo 'ERROR: test HTTP helper is dynamically linked' >&2; exit 1;
fi
cp "$script_dir/Dockerfile" "$tmp/Dockerfile"
cp "$script_dir/native-init" "$tmp/input/native-init"
cp "$script_dir/native-guest.sh" "$tmp/input/native-guest.sh"
cp "$script_dir/n02.sh" "$tmp/input/n02.sh"
cp /tmp/xkeenwrt-r6-native-helper/http-wire "$tmp/input/http-wire"
cp "$r10/product/apks/xkeenwrt-core-0.1-r10.apk" "$tmp/input/xkeenwrt-core.apk"
cp "$r10/product/apks/xkeenwrt-ui-0.1-r10.apk" "$tmp/input/xkeenwrt-ui.apk"
cp "$bundle/arm64/"*.apk "$tmp/input/arm64/"
cp "$bundle/indexes/arm64-base.adb" "$tmp/input/arm64-base.adb"
cp "$bundle/indexes/arm64-core.adb" "$tmp/input/arm64-core.adb"
cp "$bundle/indexes/arm64-kmods.adb" "$tmp/input/arm64-kmods.adb"
docker_local build --network none -t "$tag" "$tmp"
docker_local image inspect "$tag" --format '{{.Id}}'
