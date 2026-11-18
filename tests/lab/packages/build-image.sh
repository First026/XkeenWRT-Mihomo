#!/bin/sh
set -eu
: "${XK_PACKAGE_DIR:?}"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
docker_local() {
  env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
    docker --host=unix:///var/run/docker.sock "$@"
}
base=$(docker_local image inspect xkeen-openwrt-vm:25.12.6 --format '{{.Id}}')
[ "$base" = 'sha256:4c7477b7851e7d9788771d7532f70109d76292627a9017ce0f6b68e04827a052' ] || { echo 'unexpected VM base' >&2; exit 1; }
context=$(mktemp -d)
trap 'rm -rf "$context"' EXIT HUP INT TERM
image_tag=xkeen-openwrt-vm-apk-lifecycle:25.12.6
case "${XK_REBOOT_HARNESS:-no}" in
  no) ;;
  yes) image_tag=xkeen-openwrt-vm-apk-lifecycle-reboot:25.12.6 ;;
  *) echo 'XK_REBOOT_HARNESS must be no or yes' >&2; exit 2 ;;
esac
mkdir "$context/packages"
core_r3="$XK_PACKAGE_DIR/xkeenwrt-core-0.1-r3.apk"
ui_r3="$XK_PACKAGE_DIR/xkeenwrt-ui-0.1-r3.apk"
[ -f "$core_r3" ] && [ -f "$ui_r3" ] || { echo 'missing r3 APK input' >&2; exit 1; }
printf '%s  %s\n' '77c75a6cfe639442b2692c71d6f17aed2757fb64a3e05742f202675df572ab06' "$core_r3" | sha256sum -c -
printf '%s  %s\n' '0b385f86d72a9214889eaeec34e8e245aa42ef659d037a7db7955b9235d7581f' "$ui_r3" | sha256sum -c -
for part in core ui; do for ver in 0.1-r1 0.1-r2 0.1-r3; do cp "$XK_PACKAGE_DIR/xkeenwrt-$part-$ver.apk" "$context/packages/"; done; done
cp "$script_dir/Dockerfile" "$context/Dockerfile"
cp "$script_dir/lifecycle-guest.sh" "$context/lifecycle-guest.sh"
cp "$script_dir/manual-guest.sh" "$context/manual-guest.sh"
cp "$script_dir/upgrade-guest.sh" "$context/upgrade-guest.sh"
cp "$script_dir/active-remove-guest.sh" "$context/active-remove-guest.sh"
cp "$script_dir/remove-payload-loss-guest.sh" "$context/remove-payload-loss-guest.sh"
cp "$script_dir/remove-reboot-preinit.sh" "$context/remove-reboot-preinit.sh"
cp "$script_dir/remove-reboot-snapshot.sh" "$context/remove-reboot-snapshot.sh"
cp "$script_dir/remove-reboot-snapshot.init" "$context/remove-reboot-snapshot.init"
cp "$script_dir/remove-reboot-after-guest.sh" "$context/remove-reboot-after-guest.sh"
cp "$script_dir/../integration/runtime-package-smoke.sh" "$context/runtime-package-smoke.sh"
rustc +1.99.1 --target x86_64-unknown-linux-musl -C linker=rust-lld -C linker-flavor=ld.lld -O "$script_dir/../integration/http-wire.rs" -o "$context/http-wire"
readelf -h "$context/http-wire" | grep -q 'Advanced Micro Devices X86-64'
if readelf -l "$context/http-wire" | grep -q INTERP || readelf -d "$context/http-wire" 2>/dev/null | grep -q NEEDED; then exit 1; fi
rustc +1.99.1 --target x86_64-unknown-linux-musl -C linker=rust-lld -C linker-flavor=ld.lld -O "$script_dir/ipc-probe.rs" -o "$context/ipc-probe"
readelf -h "$context/ipc-probe" | grep -q 'Advanced Micro Devices X86-64'
if readelf -l "$context/ipc-probe" | grep -q INTERP || readelf -d "$context/ipc-probe" 2>/dev/null | grep -q NEEDED; then exit 1; fi
rustc +1.99.1 --target x86_64-unknown-linux-musl -C linker=rust-lld -C linker-flavor=ld.lld -O "$script_dir/validator-probe.rs" -o "$context/validator-probe"
readelf -h "$context/validator-probe" | grep -q 'Advanced Micro Devices X86-64'
if readelf -l "$context/validator-probe" | grep -q INTERP || readelf -d "$context/validator-probe" 2>/dev/null | grep -q NEEDED; then exit 1; fi
chmod 755 "$context/http-wire" "$context/ipc-probe" "$context/validator-probe"
sha256sum "$context/validator-probe"
sha256sum "$context/ipc-probe"
sha256sum "$context/http-wire"
docker_local build --network none -t "$image_tag" "$context"
